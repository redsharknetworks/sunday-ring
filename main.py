import os
import io
import csv
import json
import time
import threading
import zipfile
import logging
from datetime import datetime, timedelta

import requests
import sqlite3
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
        c = conn.cursor()
        c.execute("""
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
        conn.commit()
init_db()

def cleanup_db(limit=5000):
    with sqlite3.connect(DB_FILE, check_same_thread=False) as conn:
        c = conn.cursor()
        c.execute("""
        DELETE FROM indicators
        WHERE id NOT IN (
            SELECT id FROM indicators
            ORDER BY last_seen DESC
            LIMIT ?
        )""", (limit,))
        conn.commit()

def save_iocs(iocs):
    with sqlite3.connect(DB_FILE, check_same_thread=False) as conn:
        c = conn.cursor()
        for f in iocs:
            try:
                c.execute("""
                INSERT OR IGNORE INTO indicators
                (indicator,type,source,severity,mitre,score,country,lat,lon,first_seen,last_seen)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (f["indicator"],f["type"],f["source"],f["severity"],f["mitre"],
                 f["score"],f["country"],f["lat"],f["lon"],f["first_seen"],f["last_seen"]))
            except sqlite3.Error as e:
                logging.warning(f"DB insert error: {e}")
        conn.commit()

# ---------------- FETCH FEEDS ---------------- #
def get_random_location():
    ts = int(datetime.utcnow().timestamp())
    return LOCATIONS[ts % len(LOCATIONS)]

def get_random_mitre():
    ts = int(datetime.utcnow().timestamp())
    return MITRE_MAP[ts % len(MITRE_MAP)]

def fetch_otx_iocs():
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
    headers = {"X-OTX-API-KEY": OTX_KEY}
    iocs = []
    try:
        r = requests.get(url, headers=headers, timeout=15)
        if r.status_code == 200:
            data = r.json()
            for pulse in data.get("results", []):
                for ind in pulse.get("indicators", []):
                    typ_raw = ind.get("type", "IPv4")
                    typ = "IP" if typ_raw=="IPv4" else "Domain" if "domain" in typ_raw.lower() else "Hash"
                    loc = get_random_location()
                    severity = "Critical" if typ=="IP" else "High"
                    iocs.append({
                        "indicator": ind["indicator"],
                        "type": typ,
                        "source": "OTX",
                        "severity": severity,
                        "mitre": get_random_mitre(),
                        "score": 95 if severity=="Critical" else 80,
                        "country": loc[0],
                        "lat": loc[1],
                        "lon": loc[2],
                        "first_seen": datetime.utcnow().isoformat(),
                        "last_seen": datetime.utcnow().isoformat()
                    })
    except Exception as e:
        logging.error(f"OTX fetch error: {e}")
    return iocs

def fetch_abuseipdb():
    url = "https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum=70&limit=100"
    headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
    iocs = []
    try:
        r = requests.get(url, headers=headers, timeout=15)
        if r.status_code == 200:
            for item in r.json().get("data", []):
                loc = get_random_location()
                iocs.append({
                    "indicator": item["ipAddress"],
                    "type": "IP",
                    "source": "AbuseIPDB",
                    "severity": "Critical",
                    "mitre": get_random_mitre(),
                    "score": 95,
                    "country": loc[0],
                    "lat": loc[1],
                    "lon": loc[2],
                    "first_seen": datetime.utcnow().isoformat(),
                    "last_seen": datetime.utcnow().isoformat()
                })
    except Exception as e:
        logging.error(f"AbuseIPDB fetch error: {e}")
    return iocs

# ---------------- THREAT ENGINE ---------------- #
def threat_engine():
    while True:
        all_iocs = fetch_otx_iocs() + fetch_abuseipdb()
        save_iocs(all_iocs)
        cleanup_db()
        logging.info(f"Saved {len(all_iocs)} IOCs")
        time.sleep(60)

threading.Thread(target=threat_engine, daemon=True).start()

# ---------------- DASHBOARD HTML ---------------- #
DASHBOARD_HTML = """<html>
<!-- Use the full live dashboard HTML from previous step (AJAX + charts + map) -->
{{dynamic_dashboard_html}}
</html>
"""

# ---------------- DASHBOARD ROUTE ---------------- #
@app.route("/")
def dashboard():
    with sqlite3.connect(DB_FILE, check_same_thread=False) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT indicator,type,source,severity,mitre,score,country,lat,lon,last_seen FROM indicators ORDER BY last_seen DESC LIMIT 500")
        rows = c.fetchall()
    malaysia_time = (datetime.utcnow()+timedelta(hours=8)).strftime("%Y-%m-%d %H:%M:%S")
    return render_template_string(DASHBOARD_HTML, rows=rows, time=malaysia_time, dynamic_dashboard_html=DASHBOARD_HTML)

# ---------------- LIVE API ---------------- #
@app.route("/api/latest")
def api_latest():
    with sqlite3.connect(DB_FILE, check_same_thread=False) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT indicator,type,source,severity,mitre,score,country,lat,lon,last_seen FROM indicators ORDER BY last_seen DESC LIMIT 500")
        rows = [dict(r) for r in c.fetchall()]
    return jsonify(rows)

# ---------------- EXPORTS ---------------- #
@app.route("/export/json")
def export_json():
    with sqlite3.connect(DB_FILE, check_same_thread=False) as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM indicators")
        rows = c.fetchall()
    return jsonify(rows)

@app.route("/export/csv")
def export_csv():
    with sqlite3.connect(DB_FILE, check_same_thread=False) as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM indicators")
        rows = c.fetchall()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id","indicator","type","source","severity","mitre","score","country","lat","lon","first_seen","last_seen"])
    writer.writerows(rows)
    return send_file(io.BytesIO(output.getvalue().encode()), as_attachment=True, download_name="redshark_cti.csv")

@app.route("/export/pdf")
def export_pdf():
    with sqlite3.connect(DB_FILE, check_same_thread=False) as conn:
        c = conn.cursor()
        c.execute("SELECT indicator,type,source,severity,mitre,score,country,lat,lon,last_seen FROM indicators LIMIT 100")
        rows = c.fetchall()
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    table_data = [["Indicator","Type","Source","Severity","MITRE","Score","Country","Lat","Lon","Last Seen"]] + list(rows)
    table = Table(table_data)
    doc.build([table])
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name="redshark_report.pdf")

@app.route("/export/ids")
def export_ids():
    with sqlite3.connect(DB_FILE, check_same_thread=False) as conn:
        c = conn.cursor()
        c.execute("SELECT indicator FROM indicators WHERE type='IP'")
        rows = c.fetchall()
    sid = 100000
    mem = io.BytesIO()
    with zipfile.ZipFile(mem,'w',zipfile.ZIP_DEFLATED) as z:
        rules = "\n".join([f'alert ip {r[0]} any -> any any (msg:"RedShark IOC"; sid:{sid+i}; rev:1;)' 
                           for i,r in enumerate(rows)])
        z.writestr("redshark_ids.rules", rules)
    mem.seek(0)
    return send_file(mem, as_attachment=True, download_name="redshark_ids_rules.zip")

# ---------------- MANUAL REFRESH ---------------- #
@app.route("/refresh")
def refresh():
    all_iocs = fetch_otx_iocs() + fetch_abuseipdb()
    save_iocs(all_iocs)
    logging.info(f"Manually refreshed {len(all_iocs)} IOCs")
    return "Threat feed refreshed"

# ---------------- RUN ---------------- #
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)