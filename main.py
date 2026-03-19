import io, csv, json, zipfile, threading, logging, re
from datetime import datetime, timedelta
import sqlite3, requests
from flask import Flask, render_template_string, jsonify, send_file
from reportlab.platypus import SimpleDocTemplate, Table
from reportlab.lib.pagesizes import letter

# ---------------- CONFIG ---------------- #
app = Flask(__name__)
DB_FILE = "redshark.db"
OTX_KEY = "aa94a69a780ed789016bb72d51d9b58b823eb1e6173f6fffc34530693dacb03b"
ABUSEIPDB_KEY = "08cf00dc25d22cbd0f45ec5ebb87cb61e93c22349a6eb14544a100"

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

LOCATIONS = [
    ("Kangar",6.4414,100.1986),("Alor Setar",6.1248,100.3678),("George Town",5.4141,100.3288),
    ("Ipoh",4.5975,101.0901),("Shah Alam",3.0738,101.5183),("Kuala Lumpur",3.1390,101.6869),
    ("Seremban",2.7297,101.9381),("Melaka",2.1896,102.2501),("Johor Bahru",1.4927,103.7414),
    ("Kuantan",3.8168,103.3317),("Kuala Terengganu",5.3302,103.1408),("Kota Bharu",6.1254,102.2386),
    ("Kuching",1.5533,110.3592),("Kota Kinabalu",5.9804,116.0735),("Putrajaya",2.9264,101.6964)
]

MITRE_MAP = [
    "T1046 Network Discovery","T1059 Command Execution","T1566 Phishing",
    "T1071 C2 Communication","T1105 Data Exfiltration","T1190 Exploit Public Facing App"
]

# ---------------- DATABASE ---------------- #
def init_db():
    with sqlite3.connect(DB_FILE, check_same_thread=False) as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS indicators(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator TEXT UNIQUE,
            type TEXT,
            source TEXT,
            severity TEXT,
            mitre TEXT,
            score INTEGER,
            country TEXT,
            lat REAL,
            lon REAL,
            first_seen TEXT,
            last_seen TEXT
        )""")
init_db()

def save_iocs(iocs):
    with sqlite3.connect(DB_FILE, check_same_thread=False) as conn:
        for i in iocs:
            try:
                conn.execute("""
                INSERT OR IGNORE INTO indicators
                (indicator,type,source,severity,mitre,score,country,lat,lon,first_seen,last_seen)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)
                """, (
                    i["indicator"], i["type"], i["source"], i["severity"], i["mitre"],
                    i["score"], i["country"], i["lat"], i["lon"], i["first_seen"], i["last_seen"]
                ))
            except Exception as e:
                logging.error(f"DB insert error: {e}")
        conn.commit()

def cleanup_db(limit=5000):
    with sqlite3.connect(DB_FILE, check_same_thread=False) as conn:
        conn.execute(f"""
        DELETE FROM indicators
        WHERE id NOT IN (
            SELECT id FROM indicators ORDER BY last_seen DESC LIMIT {limit}
        )""")
        conn.commit()

# ---------------- FETCHERS ---------------- #
def detect_type(indicator):
    ip = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
    hsh = re.compile(r"^[a-fA-F0-9]{32,128}$")
    domain = re.compile(r"^(?!\d+$)([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")
    url = re.compile(r"^https?://")
    if ip.match(indicator): return "IP"
    elif hsh.match(indicator): return "Hash"
    elif url.match(indicator) or domain.match(indicator): return "Domain"
    return "Unknown"

def fetch_otx_iocs():
    iocs=[]
    try:
        r = requests.get("https://otx.alienvault.com/api/v1/pulses/subscribed",
                         headers={"X-OTX-API-KEY":OTX_KEY}, timeout=15)
        for pulse in r.json().get("results", []):
            for ind in pulse.get("indicators", []):
                typ=detect_type(ind["indicator"])
                loc=LOCATIONS[int(datetime.utcnow().timestamp()) % len(LOCATIONS)]
                sev="Critical" if typ=="IP" else "High"
                iocs.append({
                    "indicator": ind["indicator"],
                    "type": typ,
                    "source": "OTX",
                    "severity": sev,
                    "mitre": MITRE_MAP[int(datetime.utcnow().timestamp()) % len(MITRE_MAP)],
                    "score":95 if sev=="Critical" else 80,
                    "country": loc[0],"lat": loc[1],"lon": loc[2],
                    "first_seen": datetime.utcnow().isoformat(),
                    "last_seen": datetime.utcnow().isoformat()
                })
    except Exception as e: logging.error(f"OTX error: {e}")
    return iocs

def fetch_abuseipdb():
    iocs=[]
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum=70&limit=100",
            headers={"Key":ABUSEIPDB_KEY,"Accept":"application/json"}, timeout=15)
        for item in r.json().get("data", []):
            loc=LOCATIONS[int(datetime.utcnow().timestamp()) % len(LOCATIONS)]
            iocs.append({
                "indicator": item["ipAddress"],
                "type":"IP","source":"AbuseIPDB","severity":"Critical",
                "mitre": MITRE_MAP[int(datetime.utcnow().timestamp()) % len(MITRE_MAP)],
                "score":95,
                "country":loc[0],"lat":loc[1],"lon":loc[2],
                "first_seen":datetime.utcnow().isoformat(),
                "last_seen":datetime.utcnow().isoformat()
            })
    except Exception as e: logging.error(f"AbuseIPDB error: {e}")
    return iocs

def schedule_threat_fetch(interval=600):
    def task():
        try:
            iocs = fetch_otx_iocs() + fetch_abuseipdb()
            if iocs: save_iocs(iocs); cleanup_db(); logging.info(f"Saved {len(iocs)} IOCs")
        except Exception as e: logging.error(f"Fetch error: {e}")
        threading.Timer(interval, task).start()
    task()

schedule_threat_fetch()

# ---------------- API & DASHBOARD ---------------- #
@app.route("/api/data")
def api_data():
    with sqlite3.connect(DB_FILE, check_same_thread=False) as conn:
        conn.row_factory=sqlite3.Row
        c=conn.cursor()
        c.execute("SELECT indicator,type,source,severity,mitre,score,country,lat,lon,last_seen FROM indicators ORDER BY last_seen DESC LIMIT 500")
        return jsonify([dict(r) for r in c.fetchall()])

@app.route("/")
def dashboard():
    malaysia_time=(datetime.utcnow()+timedelta(hours=8)).strftime("%Y-%m-%d %H:%M:%S")
    return render_template_string("<h1>RedShark SOC Dashboard - {{time}}</h1>", time=malaysia_time)

# ---------------- EXPORT HELPER ---------------- #
def export_data(fmt="json", limit=500):
    with sqlite3.connect(DB_FILE, check_same_thread=False) as conn:
        conn.row_factory=sqlite3.Row
        c=conn.cursor()
        if fmt=="ids": c.execute("SELECT id,indicator,type FROM indicators ORDER BY last_seen DESC LIMIT ?",(limit,)); rows=c.fetchall()
        else: c.execute("SELECT * FROM indicators ORDER BY last_seen DESC LIMIT ?",(limit,)); rows=[dict(r) for r in c.fetchall()]

    buf=io.BytesIO()
    with zipfile.ZipFile(buf,'w') as zf:
        if fmt=="json":
            for r in rows: r.update({k:"" for k,v in r.items() if v is None})
            zf.writestr("redshark_cti.json", json.dumps(rows, indent=2))
        elif fmt=="csv":
            out=io.StringIO()
            hdr=rows[0].keys() if rows else []
            w=csv.writer(out)
            w.writerow(hdr)
            for r in rows: w.writerow([str(r[h]) if r[h] is not None else "" for h in hdr])
            zf.writestr("redshark_cti.csv", out.getvalue())
        elif fmt=="pdf":
            hdr=rows[0].keys() if rows else []
            table=[[str(r[h]) if r[h] is not None else "" for h in hdr] for r in rows]
            docbuf=io.BytesIO(); doc=SimpleDocTemplate(docbuf,pagesize=letter); doc.build([Table([list(hdr)]+table)]); docbuf.seek(0)
            zf.writestr("redshark_cti.pdf", docbuf.getvalue())
        elif fmt=="ids":
            rules=""
            for r in rows:
                sid,ind,typ=r
                typ=typ.lower() if typ else ""
                if typ=="ip": rules+=f'alert ip any any -> {ind} any (msg:"Malicious IP {ind}"; sid:{sid}; rev:1;)\n'
                elif typ=="domain": rules+=f'alert tcp any any -> any 80 (msg:"Malicious Domain {ind}"; content:"{ind}"; sid:{sid}; rev:1;)\n'
                elif typ=="hash": rules+=f'alert tcp any any -> any any (msg:"Malicious Hash {ind}"; content:"{ind}"; sid:{sid}; rev:1;)\n'
            zf.writestr("redshark_ids.rules", rules)
    buf.seek(0)
    files={"json":"redshark_cti_json.zip","csv":"redshark_cti_csv.zip","pdf":"redshark_cti.pdf.zip","ids":"redshark_ids.zip"}
    return send_file(buf, as_attachment=True, download_name=files.get(fmt,"redshark_cti.zip"))

# ---------------- EXPORT ROUTES ---------------- #
@app.route("/export/json"); def export_json(): return export_data("json")
@app.route("/export/csv"); def export_csv(): return export_data("csv")
@app.route("/export/pdf"); def export_pdf(): return export_data("pdf")
@app.route("/export/ids"); def export_ids(): return export_data("ids")

# ---------------- RUN ---------------- #
if __name__=="__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)