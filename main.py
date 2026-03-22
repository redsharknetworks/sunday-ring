import os
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

OTX_KEY = os.environ.get("OTX_KEY","aa94a69a780ed789016bb72d51d9b58b823eb1e6173f6fffc34530693dacb03b")
ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_KEY","08cf00dc25d22cbd0f45ec5ebb87cb61e93c22349a6eb14544a100")

logging.basicConfig(level=logging.INFO)

# ---------------- LOCATIONS ---------------- #
LOCATIONS = [
    ("Kuala Lumpur",3.1390,101.6869),("George Town",5.4141,100.3288),
    ("Johor Bahru",1.4927,103.7414),("Kota Kinabalu",5.9804,116.0735)
]

MITRE_MAP = [
    "T1046 Network Discovery","T1059 Command Execution",
    "T1566 Phishing","T1071 C2 Communication"
]

# ---------------- DATABASE ---------------- #
def get_db():
    return sqlite3.connect(DB_FILE, check_same_thread=False, timeout=10)

def init_db():
    with get_db() as conn:
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
init_db()

# ---------------- HELPERS ---------------- #
def detect_type(indicator):
    if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", indicator):
        return "IP"
    elif re.match(r"^[a-fA-F0-9]{32,128}$", indicator):
        return "Hash"
    elif indicator.startswith("http"):
        return "Domain"
    return "Unknown"

# ---------------- FETCH ---------------- #
def fetch_otx():
    url="https://otx.alienvault.com/api/v1/pulses/subscribed"
    headers={"X-OTX-API-KEY":OTX_KEY}
    out=[]
    try:
        r=requests.get(url,headers=headers,timeout=10)
        data=r.json() if r.content else {}
        for p in data.get("results",[]):
            for i in p.get("indicators",[]):
                loc=LOCATIONS[int(time.time())%len(LOCATIONS)]
                typ=detect_type(i["indicator"])
                sev="Critical" if typ=="IP" else "High"
                out.append({
                    "indicator":i["indicator"],"type":typ,"source":"OTX",
                    "severity":sev,"mitre":MITRE_MAP[0],
                    "score":95 if sev=="Critical" else 80,
                    "country":loc[0],"lat":loc[1],"lon":loc[2],
                    "first_seen":datetime.utcnow().isoformat(),
                    "last_seen":datetime.utcnow().isoformat()
                })
    except Exception as e:
        logging.error(e)
    return out

def fetch_abuse():
    url="https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum=70&limit=100"
    headers={"Key":ABUSEIPDB_KEY,"Accept":"application/json"}
    out=[]
    try:
        r=requests.get(url,headers=headers,timeout=10)
        data=r.json() if r.content else {}
        for i in data.get("data",[]):
            loc=LOCATIONS[int(time.time())%len(LOCATIONS)]
            out.append({
                "indicator":i["ipAddress"],"type":"IP","source":"AbuseIPDB",
                "severity":"Critical","mitre":MITRE_MAP[1],
                "score":95,"country":loc[0],"lat":loc[1],"lon":loc[2],
                "first_seen":datetime.utcnow().isoformat(),
                "last_seen":datetime.utcnow().isoformat()
            })
    except Exception as e:
        logging.error(e)
    return out

# ---------------- ENGINE ---------------- #
def save_iocs(data):
    with get_db() as conn:
        for i in data:
            try:
                conn.execute("""
                INSERT OR IGNORE INTO indicators
                (indicator,type,source,severity,mitre,score,country,lat,lon,first_seen,last_seen)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)
                """,tuple(i.values()))
            except Exception as e:
                logging.error(e)

def threat_engine():
    while True:
        data=fetch_otx()+fetch_abuse()
        if data:
            save_iocs(data)
            logging.info(f"Saved {len(data)} IOCs")
        time.sleep(600)

def start_bg():
    if not hasattr(start_bg,"run"):
        threading.Thread(target=threat_engine,daemon=True).start()
        start_bg.run=True

if os.environ.get("RENDER") and os.environ.get("RENDER_INSTANCE_ID"):
    start_bg()

# ---------------- HTML ---------------- #
HTML="""
<!DOCTYPE html>
<html>
<head>
<title>RedShark SOC</title>
<script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<style>
body{background:#020617;color:white;font-family:Arial}
#map{height:400px}
.critical{color:red;animation:blink 1s infinite}
@keyframes blink{50%{opacity:0.5}}
</style>
</head>
<body>
<h1>RedShark SOC Dashboard</h1>
<div id="map"></div>
<canvas id="chart"></canvas>
<table id="tbl"></table>

<script>
var map=L.map('map').setView([3,101],5);
L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png').addTo(map);

function load(){
 fetch('/api/data').then(r=>r.json()).then(d=>{
  var tbl="<tr><th>Indicator</th><th>Severity</th></tr>";
  var counts={};
  d.forEach(x=>{
    tbl+=`<tr><td>${x.indicator}</td><td class="${x.severity.toLowerCase()}">${x.severity}</td></tr>`;
    L.circleMarker([x.lat,x.lon]).addTo(map);
    counts[x.severity]=(counts[x.severity]||0)+1;
  });
  document.getElementById("tbl").innerHTML=tbl;

  new Chart(document.getElementById("chart"),{
    type:"bar",
    data:{labels:Object.keys(counts),datasets:[{data:Object.values(counts)}]}
  });
 });
}
load();
setInterval(load,60000);
</script>
</body>
</html>
"""

# ---------------- ROUTES ---------------- #
@app.route("/")
def home():
    return render_template_string(HTML)

@app.route("/api/data")
def api():
    with get_db() as conn:
        conn.row_factory=sqlite3.Row
        rows=conn.execute("SELECT * FROM indicators ORDER BY id DESC LIMIT 200")
        return jsonify([dict(r) for r in rows])

# ---------------- EXPORT ---------------- #
@app.route("/export/json")
def exp_json():
    with get_db() as conn:
        rows=conn.execute("SELECT * FROM indicators").fetchall()
    mem=io.BytesIO()
    with zipfile.ZipFile(mem,"w") as z:
        z.writestr("data.json",json.dumps([list(r) for r in rows]))
    mem.seek(0)
    return send_file(mem,as_attachment=True,download_name="data.zip")

# ---------------- RUN ---------------- #
if __name__=="__main__":
    start_bg()
    port=int(os.environ.get("PORT",5000))
    app.run(host="0.0.0.0",port=port)