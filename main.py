import os
import io
import csv
import json
import time
import sqlite3
import threading
import zipfile
import requests
from datetime import datetime, timedelta
from flask import Flask, render_template_string, jsonify, send_file

from reportlab.platypus import SimpleDocTemplate, Table
from reportlab.lib.pagesizes import letter

app = Flask(__name__)
DB_FILE = "redshark_real.db"

# ---------------- DATABASE ---------------- #
def init_db():
    conn = sqlite3.connect(DB_FILE)
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
    )
    """)
    conn.commit()
    conn.close()

init_db()

def cleanup_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
    DELETE FROM indicators
    WHERE id NOT IN (
        SELECT id FROM indicators
        ORDER BY last_seen DESC
        LIMIT 5000
    )
    """)
    conn.commit()
    conn.close()

# ---------------- GLOBAL LOCATIONS ---------------- #
# Malaysia ibu negeri only
locations = [
    ("Kangar",6.4414,100.1986),
    ("Alor Setar",6.1248,100.3678),
    ("George Town",5.4141,100.3288),
    ("Ipoh",4.5975,101.0901),
    ("Shah Alam",3.0738,101.5183),
    ("Kuala Lumpur",3.1390,101.6869),
    ("Seremban",2.7297,101.9381),
    ("Melaka",2.1896,102.2501),
    ("Johor Bahru",1.4927,103.7414),
    ("Kuantan",3.8168,103.3317),
    ("Kuala Terengganu",5.3302,103.1408),
    ("Kota Bharu",6.1254,102.2386),
    ("Kuching",1.5533,110.3592),
    ("Kota Kinabalu",5.9804,116.0735),
    ("Putrajaya",2.9264,101.6964)
]

# ---------------- MITRE ATT&CK ---------------- #
mitre_map = [
    "T1046 Network Discovery",
    "T1059 Command Execution",
    "T1566 Phishing",
    "T1071 C2 Communication",
    "T1105 Data Exfiltration",
    "T1190 Exploit Public Facing App"
]

# ---------------- THREAT SCORE ---------------- #
def threat_score(sev):
    return {"Low": 10, "Medium": 50, "High": 75, "Critical": 95}[sev]

# ---------------- REAL FEED FUNCTIONS ---------------- #
def fetch_otx():
    """Fetch recent AlienVault OTX pulses (public)"""
    url = "https://otx.alienvault.com/api/v1/indicators/pulses/subscribed"
    try:
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        data = r.json().get("results", [])[:20]
        iocs = []
        for pulse in data:
            for ind in pulse.get("indicators", []):
                if ind["type"] not in ["IPv4", "domain", "hash"]:
                    continue
                typ = "IP" if ind["type"]=="IPv4" else ("Domain" if ind["type"]=="domain" else "Hash")
                loc = locations[0]  # assign Malaysia ibu negeri randomly later
                sev = "High" if typ=="IP" else "Medium"
                iocs.append({
                    "indicator": ind["indicator"],
                    "type": typ,
                    "source": "OTX",
                    "severity": sev,
                    "mitre": mitre_map[0],
                    "score": threat_score(sev),
                    "country": loc[0],
                    "lat": loc[1],
                    "lon": loc[2],
                    "first_seen": ind.get("created", datetime.utcnow().isoformat()),
                    "last_seen": ind.get("modified", datetime.utcnow().isoformat())
                })
        return iocs
    except Exception as e:
        print("OTX fetch error:", e)
        return []

def fetch_abuseipdb():
    """Fetch AbuseIPDB recent IPs (free, public)"""
    url = "https://api.abuseipdb.com/api/v2/blacklist"
    headers = {"Key": os.environ.get("ABUSEIPDB_KEY",""), "Accept": "application/json"}
    try:
        r = requests.get(url, headers=headers, timeout=10)
        r.raise_for_status()
        data = r.json().get("data", [])[:20]
        iocs=[]
        for ip in data:
            loc = locations[0]
            iocs.append({
                "indicator": ip["ipAddress"],
                "type": "IP",
                "source": "AbuseIPDB",
                "severity": "Critical",
                "mitre": mitre_map[0],
                "score": threat_score("Critical"),
                "country": loc[0],
                "lat": loc[1],
                "lon": loc[2],
                "first_seen": ip.get("lastReportedAt", datetime.utcnow().isoformat()),
                "last_seen": ip.get("lastReportedAt", datetime.utcnow().isoformat())
            })
        return iocs
    except:
        return []

def fetch_feeds():
    return fetch_otx() + fetch_abuseipdb()

def save_iocs(feed):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    for f in feed:
        try:
            c.execute("""
            INSERT OR IGNORE INTO indicators
            (indicator,type,source,severity,mitre,score,country,lat,lon,first_seen,last_seen)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
            """,(f["indicator"],f["type"],f["source"],f["severity"],f["mitre"],
                 f["score"],f["country"],f["lat"],f["lon"],f["first_seen"],f["last_seen"]))
        except:
            pass
    conn.commit()
    conn.close()

def threat_engine():
    while True:
        feed = fetch_feeds()
        save_iocs(feed)
        cleanup_db()
        time.sleep(300)  # fetch every 5 minutes

threading.Thread(target=threat_engine,daemon=True).start()

# ---------------- DASHBOARD ---------------- #
# Keep your existing DASHBOARD_HTML template (heatmap, charts, tables)
# ... (reuse DASHBOARD_HTML from your previous code) ...

@app.route("/")
def dashboard():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT indicator,type,source,severity,mitre,score,country,lat,lon,last_seen FROM indicators ORDER BY last_seen DESC LIMIT 500")
    rows=c.fetchall()
    conn.close()
    malaysia_time=(datetime.utcnow()+timedelta(hours=8)).strftime("%Y-%m-%d %H:%M:%S")
    return render_template_string(DASHBOARD_HTML, rows=rows, time=malaysia_time)

# ---------------- EXPORTS ---------------- #
@app.route("/export/json")
def export_json():
    conn=sqlite3.connect(DB_FILE); c=conn.cursor()
    c.execute("SELECT * FROM indicators"); rows=c.fetchall(); conn.close()
    return jsonify(rows)

@app.route("/export/csv")
def export_csv():
    conn=sqlite3.connect(DB_FILE); c=conn.cursor()
    c.execute("SELECT * FROM indicators"); rows=c.fetchall(); conn.close()
    output=io.StringIO(); writer=csv.writer(output)
    writer.writerow(["id","indicator","type","source","severity","mitre","score","country","lat","lon","first_seen","last_seen"])
    writer.writerows(rows)
    return send_file(io.BytesIO(output.getvalue().encode()),as_attachment=True,download_name="redshark_cti.csv")

# ... keep PDF, IDS, ZIP exports and /refresh routes as before ...

if __name__=="__main__":
    app.run(host="0.0.0.0", port=5000)