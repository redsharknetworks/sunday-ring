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
from reportlab.platypus import SimpleDocTemplate, Table
from reportlab.lib.pagesizes import letter

# ---------------- CONFIG ---------------- #
app = Flask(__name__)
DB_FILE = "/tmp/redshark.db"

# ⚠️ API KEYS (testing only)
OTX_KEY = "aa94a69a780ed789016bb72d51d9b58b823eb1e6173f6fffc34530693dacb03b"
ABUSEIPDB_KEY = "08cf00dc25d22cbd0f45ec5ebb87cb61e93c22349a6eb14544a100"

logging.basicConfig(level=logging.INFO)

# ---------------- STATIC ---------------- #
LOCATIONS = [
    ("Kangar",6.44,100.19),("Alor Setar",6.12,100.36),("George Town",5.41,100.32),
    ("Ipoh",4.59,101.09),("KL",3.13,101.68),("JB",1.49,103.74)
]

MITRE_MAP = ["T1046","T1059","T1566","T1071","T1105","T1190"]

# ---------------- DATABASE ---------------- #
def init_db():
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

def save_iocs(data):
    with sqlite3.connect(DB_FILE) as conn:
        for i in data:
            try:
                conn.execute("""
                INSERT OR IGNORE INTO indicators
                (indicator,type,source,severity,mitre,score,country,lat,lon,first_seen,last_seen)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)
                """,(
                    i["indicator"],i["type"],i["source"],i["severity"],i["mitre"],
                    i["score"],i["country"],i["lat"],i["lon"],i["first_seen"],i["last_seen"]
                ))
            except Exception as e:
                logging.error(e)

# ---------------- HELPERS ---------------- #
def detect_type(val):
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", val):
        return "IP"
    if val.startswith("http"):
        return "Domain"
    return "Hash"

# ---------------- FEEDS ---------------- #
def fetch_otx():
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
    headers = {"X-OTX-API-KEY": OTX_KEY}
    data = []
    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            for pulse in r.json().get("results", []):
                for ind in pulse.get("indicators", []):
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
        logging.error(e)
    return data

def fetch_abuse():
    url = "https://api.abuseipdb.com/api/v2/blacklist"
    headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
    data = []
    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            for item in r.json().get("data", []):
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
        logging.error(e)
    return data

# ---------------- BACKGROUND ---------------- #
def worker():
    while True:
        logging.info("Fetching feeds...")
        data = fetch_otx() + fetch_abuse()
        if data:
            save_iocs(data)
        time.sleep(600)

def start_worker():
    threading.Thread(target=worker, daemon=True).start()

@app.before_first_request
def startup():
    init_db()
    start_worker()

# ---------------- HTML DASHBOARD ---------------- #
DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
<title>RedShark SOC Dashboard</title>
<script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
body{background:#020617;color:white;font-family:Arial}
h1{text-align:center;color:#38bdf8;}
table{width:100%;border-collapse:collapse;}
th,td{border:1px solid #334155;padding:8px;}
.critical{color:red;font-weight:bold;}
.high{color:orange;}
</style>
</head>
<body>

<h1>RedShark Cyber SOC Dashboard</h1>
<p style="text-align:center;">Time: {{time}}</p>

<table>
<thead>
<tr>
<th>Indicator</th><th>Type</th><th>Source</th>
<th>Severity</th><th>Country</th><th>Last Seen</th>
</tr>
</thead>
<tbody id="data"></tbody>
</table>

<script>
function loadData(){
    $.getJSON("/api/data", function(res){
        let html="";
        res.forEach(r=>{
            html+=`<tr>
                <td>${r.indicator}</td>
                <td>${r.type}</td>
                <td>${r.source}</td>
                <td class="${r.severity.toLowerCase()}">${r.severity}</td>
                <td>${r.country}</td>
                <td>${r.last_seen}</td>
            </tr>`;
        });
        $("#data").html(html);
    });
}
setInterval(loadData,5000);
loadData();
</script>

</body>
</html>
"""

# ---------------- ROUTES ---------------- #
@app.route("/")
def dashboard():
    malaysia_time = (datetime.utcnow()+timedelta(hours=8)).strftime("%Y-%m-%d %H:%M:%S")
    return render_template_string(DASHBOARD_HTML, time=malaysia_time)

@app.route("/api/data")
def api():
    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM indicators ORDER BY id DESC LIMIT 100").fetchall()
    return jsonify([dict(r) for r in rows])

# ---------------- RUN ---------------- #
if __name__ == "__main__":
    init_db()
    start_worker()
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)