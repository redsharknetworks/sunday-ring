import io
import csv
import json
import zipfile
import time
import threading
import logging
import re
import os
from datetime import datetime, timedelta

import sqlite3
import requests
from flask import Flask, render_template_string, jsonify, send_file

# ---------------- CONFIG ---------------- #
app = Flask(__name__)
DB_FILE = "/tmp/redshark.db"

# API KEYS (your provided keys)
OTX_KEY = "aa94a69a780ed789016bb72d51d9b58b823eb1e6173f6fffc34530693dacb03b"
ABUSEIPDB_KEY = "08cf00dc25d22cbd0f45ec5ebb87cb61e93c22349a6eb14544a100"

logging.basicConfig(level=logging.INFO)

# ---------------- STATIC ---------------- #
LOCATIONS = [
    ("Kangar",6.44,100.19),("Alor Setar",6.12,100.36),
    ("George Town",5.41,100.32),("Ipoh",4.59,101.09),
    ("KL",3.13,101.68),("JB",1.49,103.74)
]

MITRE_MAP = ["T1046","T1059","T1566","T1071","T1105","T1190"]

# ---------------- DATABASE ---------------- #
def init_db():
    try:
        with sqlite3.connect(DB_FILE) as conn:
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
    except Exception as e:
        logging.error(f"DB init error: {e}")

def save_iocs(data):
    try:
        with sqlite3.connect(DB_FILE) as conn:
            for i in data:
                try:
                    conn.execute("""
                    INSERT OR IGNORE INTO indicators
                    (indicator,type,source,severity,mitre,score,country,lat,lon,first_seen,last_seen)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)
                    """,(
                        i["indicator"],i["type"],i["source"],i["severity"],i["mitre"],
                        i["score"],i["country"],i["lat"],i["lon"],
                        i["first_seen"],i["last_seen"]
                    ))
                except Exception as e:
                    logging.error(f"Insert error: {e}")
    except Exception as e:
        logging.error(f"DB save error: {e}")

# ---------------- HELPERS ---------------- #
def detect_type(val):
    try:
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", val):
            return "IP"
        if val.startswith("http"):
            return "Domain"
        return "Hash"
    except:
        return "Unknown"

# ---------------- SAFE FETCH ---------------- #
def fetch_otx():
    data = []
    try:
        r = requests.get(
            "https://otx.alienvault.com/api/v1/pulses/subscribed",
            headers={"X-OTX-API-KEY": OTX_KEY},
            timeout=10
        )

        if r.status_code != 200:
            return []

        json_data = r.json()
        if "results" not in json_data:
            return []

        for pulse in json_data["results"]:
            for ind in pulse.get("indicators", []):
                if "indicator" not in ind:
                    continue

                loc = LOCATIONS[int(time.time()) % len(LOCATIONS)]

                data.append({
                    "indicator": ind["indicator"],
                    "type": detect_type(ind["indicator"]),
                    "source": "OTX",
                    "severity": "High",
                    "mitre": MITRE_MAP[int(time.time()) % len(MITRE_MAP)],
                    "score": 80,
                    "country": loc[0],
                    "lat": loc[1],
                    "lon": loc[2],
                    "first_seen": datetime.utcnow().isoformat(),
                    "last_seen": datetime.utcnow().isoformat()
                })
    except Exception as e:
        logging.error(f"OTX error: {e}")

    return data

def fetch_abuse():
    data = []
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/blacklist",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            timeout=10
        )

        if r.status_code != 200:
            return []

        json_data = r.json()
        if "data" not in json_data:
            return []

        for item in json_data["data"]:
            if "ipAddress" not in item:
                continue

            loc = LOCATIONS[int(time.time()) % len(LOCATIONS)]

            data.append({
                "indicator": item["ipAddress"],
                "type": "IP",
                "source": "AbuseIPDB",
                "severity": "Critical",
                "mitre": MITRE_MAP[int(time.time()) % len(MITRE_MAP)],
                "score": 95,
                "country": loc[0],
                "lat": loc[1],
                "lon": loc[2],
                "first_seen": datetime.utcnow().isoformat(),
                "last_seen": datetime.utcnow().isoformat()
            })
    except Exception as e:
        logging.error(f"AbuseIPDB error: {e}")

    return data

# ---------------- BACKGROUND WORKER ---------------- #
def worker():
    while True:
        try:
            logging.info("Fetching feeds...")
            data = fetch_otx() + fetch_abuse()
            if data:
                save_iocs(data)
        except Exception as e:
            logging.error(f"Worker error: {e}")

        time.sleep(600)

def start_worker():
    if not hasattr(start_worker, "started"):
        start_worker.started = True
        threading.Thread(target=worker, daemon=True).start()

# ---------------- HTML ---------------- #
DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
<title>RedShark SOC</title>
<script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
<style>
body{background:#020617;color:white;font-family:Arial}
h1{text-align:center;color:#38bdf8;}
table{width:100%;}
td,th{padding:6px;border:1px solid #333;}
.critical{color:red;font-weight:bold;}
.high{color:orange;}
</style>
</head>
<body>
<h1>RedShark SOC Dashboard</h1>
<p style="text-align:center">{{time}}</p>
<table>
<thead>
<tr><th>Indicator</th><th>Type</th><th>Source</th><th>Severity</th></tr>
</thead>
<tbody id="data"></tbody>
</table>

<script>
function load(){
 fetch('/api/data').then(r=>r.json()).then(d=>{
  let html='';
  d.forEach(x=>{
    html+=`<tr>
    <td>${x.indicator}</td>
    <td>${x.type}</td>
    <td>${x.source}</td>
    <td class="${x.severity.toLowerCase()}">${x.severity}</td>
    </tr>`;
  });
  document.getElementById('data').innerHTML=html;
 });
}
setInterval(load,5000);
load();
</script>
</body>
</html>
"""

# ---------------- ROUTES ---------------- #
@app.route("/")
def home():
    return render_template_string(
        DASHBOARD_HTML,
        time=(datetime.utcnow()+timedelta(hours=8)).strftime("%Y-%m-%d %H:%M:%S")
    )

@app.route("/api/data")
def api():
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM indicators ORDER BY id DESC LIMIT 100"
            ).fetchall()
        return jsonify([dict(r) for r in rows])
    except Exception as e:
        logging.error(f"API error: {e}")
        return jsonify([])

# ---------------- STARTUP ---------------- #
init_db()
start_worker()

# ---------------- RUN ---------------- #
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)