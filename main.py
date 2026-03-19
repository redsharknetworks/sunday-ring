import io
import csv
import json
import zipfile
import time
import threading
import logging
import re
from datetime import datetime, timedelta

import sqlite3
import requests
from flask import Flask, render_template_string, jsonify, send_file
from reportlab.platypus import SimpleDocTemplate, Table
from reportlab.lib.pagesizes import letter

# ---------------- CONFIG ---------------- #
app = Flask(__name__)
DB_FILE = "redshark.db"

# 🔥 Hardcoded API Keys
OTX_KEY = "aa94a69a780ed789016bb72d51d9b58b823eb1e6173f6fffc34530693dacb03b"
ABUSEIPDB_KEY = "08cf00dc25d22cbd0f45ec5ebb87cb61e289533bd33bceb9b93c22349a6eb8674d52aaf14544a100"

logging.basicConfig(level=logging.INFO)

THREAD_STARTED = False

LOCATIONS = [
    ("Kangar",6.4414,100.1986),("Alor Setar",6.1248,100.3678),
    ("George Town",5.4141,100.3288),("Ipoh",4.5975,101.0901),
    ("Shah Alam",3.0738,101.5183),("Kuala Lumpur",3.1390,101.6869),
    ("Seremban",2.7297,101.9381),("Melaka",2.1896,102.2501),
    ("Johor Bahru",1.4927,103.7414),("Kuantan",3.8168,103.3317),
    ("Kuala Terengganu",5.3302,103.1408),("Kota Bharu",6.1254,102.2386),
    ("Kuching",1.5533,110.3592),("Kota Kinabalu",5.9804,116.0735),
    ("Putrajaya",2.9264,101.6964)
]

MITRE_MAP = [
    "T1046 Network Discovery","T1059 Command Execution","T1566 Phishing",
    "T1071 C2 Communication","T1105 Data Exfiltration","T1190 Exploit App"
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
        )
        """)
        conn.commit()

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
                    i["indicator"], i["type"], i["source"], i["severity"],
                    i["mitre"], i["score"], i["country"],
                    i["lat"], i["lon"], i["first_seen"], i["last_seen"]
                ))
            except Exception as e:
                logging.error(e)
        conn.commit()

# ---------------- HELPERS ---------------- #
def detect_type(ind):
    if re.match(r"^https?://", ind): return "URL"
    if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", ind): return "IP"
    if re.match(r"^[a-fA-F0-9]{32,}$", ind): return "Hash"
    if "." in ind: return "Domain"
    return "Unknown"

def get_location(ind):
    return LOCATIONS[hash(ind) % len(LOCATIONS)]

# ---------------- FEEDS ---------------- #
def fetch_otx():
    url = "https://otx.alienvault.com/api/v1/pulses/latest"
    headers = {"X-OTX-API-KEY": OTX_KEY}
    iocs = []

    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            for pulse in r.json().get("results", []):
                for ind in pulse.get("indicators", []):
                    val = ind.get("indicator")
                    if not val:
                        continue

                    loc = get_location(val)

                    iocs.append({
                        "indicator": val,
                        "type": detect_type(val),
                        "source": "OTX",
                        "severity": "High",
                        "mitre": MITRE_MAP[hash(val) % len(MITRE_MAP)],
                        "score": 80,
                        "country": loc[0],
                        "lat": loc[1],
                        "lon": loc[2],
                        "first_seen": datetime.utcnow().isoformat(),
                        "last_seen": datetime.utcnow().isoformat()
                    })
    except Exception as e:
        logging.error(f"OTX error: {e}")

    return iocs

def fetch_abuse():
    url = "https://api.abuseipdb.com/api/v2/blacklist?limit=50"
    headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
    iocs = []

    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            for item in r.json().get("data", []):
                ip = item.get("ipAddress")
                if not ip:
                    continue

                loc = get_location(ip)

                iocs.append({
                    "indicator": ip,
                    "type": "IP",
                    "source": "AbuseIPDB",
                    "severity": "Critical",
                    "mitre": MITRE_MAP[hash(ip) % len(MITRE_MAP)],
                    "score": 95,
                    "country": loc[0],
                    "lat": loc[1],
                    "lon": loc[2],
                    "first_seen": datetime.utcnow().isoformat(),
                    "last_seen": datetime.utcnow().isoformat()
                })
    except Exception as e:
        logging.error(f"AbuseIPDB error: {e}")

    return iocs

# ---------------- ENGINE ---------------- #
def threat_engine():
    while True:
        logging.info("Fetching threat feeds...")
        data = fetch_otx() + fetch_abuse()
        if data:
            save_iocs(data)
            logging.info(f"Saved {len(data)} IOCs")
        else:
            logging.info("No data fetched")
        time.sleep(300)

def start_engine():
    global THREAD_STARTED
    if not THREAD_STARTED:
        THREAD_STARTED = True
        threading.Thread(target=threat_engine, daemon=True).start()

@app.before_request
def init():
    start_engine()

# ---------------- API ---------------- #
@app.route("/api/data")
def api_data():
    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("""
            SELECT indicator,type,source,severity,mitre,score,country,lat,lon,last_seen
            FROM indicators ORDER BY last_seen DESC LIMIT 500
        """).fetchall()
    return jsonify([dict(r) for r in rows])

# ---------------- DASHBOARD ---------------- #
DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
<title>RedShark SOC Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
body{background:#020617;color:white;font-family:Arial}
h1{text-align:center;color:#38bdf8}
.critical{color:red;animation:blink 1s infinite}
.high{color:orange;animation:blink 2s infinite}
@keyframes blink{0%{opacity:0.5;}50%{opacity:1;}100%{opacity:0.5;}}
</style>
</head>
<body>
<h1>🔥 RedShark SOC</h1>
<div id="data"></div>

<script>
fetch('/api/data')
.then(r=>r.json())
.then(d=>{
    let html="";
    d.forEach(x=>{
        html+=`<p class="${x.severity.toLowerCase()}">${x.severity} - ${x.indicator}</p>`;
    });
    document.getElementById("data").innerHTML=html;
});
</script>
</body>
</html>
"""

@app.route("/")
def dashboard():
    return render_template_string(DASHBOARD_HTML)

# ---------------- EXPORT ---------------- #
@app.route("/export/json")
def export_json():
    with sqlite3.connect(DB_FILE) as conn:
        rows = conn.execute("SELECT * FROM indicators").fetchall()

    mem = io.BytesIO()
    with zipfile.ZipFile(mem, 'w') as z:
        z.writestr("redshark.json", json.dumps([list(r) for r in rows]))
    mem.seek(0)

    return send_file(mem, as_attachment=True, download_name="redshark_json.zip")

# ---------------- RUN ---------------- #
if __name__ == "__main__":
    app.run()