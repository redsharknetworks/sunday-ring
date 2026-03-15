import sqlite3
import requests
import threading
import time
import io
import csv
import zipfile
import random
import re
from datetime import datetime
from flask import Flask, jsonify, render_template_string, send_file

app = Flask(__name__)

DB = "redshark_cti.db"

OTX_KEY = "aa94a69a780ed789016bb72d51d9b58b823eb1e6173f6fffc34530693dacb03b"
ABUSE_KEY = "08cf00dc25d22cbd0f45ec5ebb87cb61e289533bd33b93c22349a6eb8674d52aaf14544a100"

# ------------------------- Malaysia States -------------------------
STATES = [
    ("Perlis",6.44,100.19),("Kedah",6.12,100.36),("Penang",5.41,100.32),
    ("Perak",4.59,101.09),("Selangor",3.07,101.51),("Kuala Lumpur",3.13,101.68),
    ("Putrajaya",2.92,101.69),("Negeri Sembilan",2.72,101.94),("Melaka",2.18,102.25),
    ("Johor",1.49,103.74),("Pahang",3.81,103.32),("Terengganu",5.31,103.13),
    ("Kelantan",6.12,102.23),("Sarawak",1.55,110.35),("Sabah",5.98,116.07)
]

MITRE = [
    "T1566 Phishing","T1071 Command & Control","T1046 Network Discovery",
    "T1105 Data Exfiltration","T1059 Command Execution"
]

# ------------------------- IOC TYPE DETECTION -------------------------
def detect_type(value):
    if re.match(r'^https?://', value):
        return "URL"
    if re.match(r'^[a-fA-F0-9]{32}$', value):
        return "MD5"
    if re.match(r'^[a-fA-F0-9]{40}$', value):
        return "SHA1"
    if re.match(r'^[a-fA-F0-9]{64}$', value):
        return "SHA256"
    if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', value):
        return "IP"
    return "Domain"

# ------------------------- DATABASE -------------------------
def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS indicators(
        indicator TEXT PRIMARY KEY,
        type TEXT,
        source TEXT,
        severity TEXT,
        mitre TEXT,
        score INTEGER,
        country TEXT,
        lat REAL,
        lon REAL,
        last_seen TEXT
    )
    """)
    conn.commit()
    conn.close()
init_db()

def save_iocs(iocs):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    for i in iocs:
        try:
            c.execute("""
            INSERT OR IGNORE INTO indicators
            VALUES(?,?,?,?,?,?,?,?,?,?)
            """,(
                i["indicator"],i["type"],i["source"],i["severity"],i["mitre"],
                i["score"],i["country"],i["lat"],i["lon"],i["last_seen"]
            ))
        except:
            pass
    conn.commit()
    conn.close()

# ------------------------- THREAT FEEDS -------------------------
def fetch_otx():
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
    headers = {"X-OTX-API-KEY": OTX_KEY}
    iocs = []
    try:
        r = requests.get(url, headers=headers, timeout=10)
        data = r.json()
        for pulse in data.get("results", []):
            for ind in pulse.get("indicators", []):
                indicator = ind.get("indicator")
                if not indicator: continue
                typ = detect_type(indicator)
                state = random.choice(STATES)
                severity = "High" if typ != "IP" else "Critical"
                iocs.append({
                    "indicator": indicator,
                    "type": typ,
                    "source": "OTX",
                    "severity": severity,
                    "mitre": random.choice(MITRE),
                    "score": 85,
                    "country": state[0],
                    "lat": state[1],
                    "lon": state[2],
                    "last_seen": datetime.utcnow().isoformat()
                })
    except: pass
    return iocs

def fetch_abuse():
    url = "https://api.abuseipdb.com/api/v2/blacklist"
    headers = {"Key": ABUSE_KEY, "Accept": "application/json"}
    iocs = []
    try:
        r = requests.get(url, headers=headers, timeout=10)
        data = r.json()
        for item in data.get("data", [])[:100]:
            ip = item["ipAddress"]
            state = random.choice(STATES)
            iocs.append({
                "indicator": ip,
                "type": "IP",
                "source": "AbuseIPDB",
                "severity": "Critical",
                "mitre": random.choice(MITRE),
                "score": 95,
                "country": state[0],
                "lat": state[1],
                "lon": state[2],
                "last_seen": datetime.utcnow().isoformat()
            })
    except: pass
    return iocs

def fetch_urlhaus():
    url = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
    iocs = []
    try:
        r = requests.get(url, timeout=10)
        data = r.json()
        for item in data.get("urls", [])[:50]:
            indicator = item["url"]
            state = random.choice(STATES)
            iocs.append({
                "indicator": indicator,
                "type": "URL",
                "source": "URLHaus",
                "severity": "High",
                "mitre": random.choice(MITRE),
                "score": 80,
                "country": state[0],
                "lat": state[1],
                "lon": state[2],
                "last_seen": datetime.utcnow().isoformat()
            })
    except: pass
    return iocs

def fetch_threatfox():
    url = "https://threatfox-api.abuse.ch/api/v1/"
    payload = {"query":"get_iocs","limit":50}
    iocs = []
    try:
        r = requests.post(url, json=payload, timeout=10)
        data = r.json()
        for item in data.get("data", []):
            indicator = item["ioc"]
            state = random.choice(STATES)
            iocs.append({
                "indicator": indicator,
                "type": detect_type(indicator),
                "source": "ThreatFox",
                "severity": "High",
                "mitre": random.choice(MITRE),
                "score": 88,
                "country": state[0],
                "lat": state[1],
                "lon": state[2],
                "last_seen": datetime.utcnow().isoformat()
            })
    except: pass
    return iocs

def feed_loop():
    while True:
        iocs = fetch_otx() + fetch_abuse() + fetch_urlhaus() + fetch_threatfox()
        if iocs: save_iocs(iocs)
        time.sleep(600)
threading.Thread(target=feed_loop, daemon=True).start()

# ------------------------- API -------------------------
@app.route("/api/data")
def api_data():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM indicators ORDER BY last_seen DESC LIMIT 500")
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return jsonify(rows)

# ------------------------- DASHBOARD -------------------------
@app.route("/")
def dashboard():
    return render_template_string(DASHBOARD_HTML)

DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
<title>RedShark SOC Command Center</title>
<link rel="stylesheet" href="https://cdn.datatables.net/1.13.6/css/jquery.dataTables.min.css">
<script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
<script src="https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js"></script>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
body{background:#020617;color:white;font-family:Arial}
h1{text-align:center;color:#00eaff}
#map{height:420px;margin-bottom:20px}
canvas{width:95% !important;height:300px;margin:10px auto;display:block;}
.pulse{animation:pulse 1.5s infinite}
@keyframes pulse{0%{transform:scale(1)}50%{transform:scale(1.7)}100%{transform:scale(1)}}
.high{background:crimson}
.critical{background:red;font-weight:bold}
</style>
</head>
<body>
<h1>RedShark SOC Command Center</h1>

<div id="map"></div>
<canvas id="mitre"></canvas>
<canvas id="severity"></canvas>
<canvas id="timeline"></canvas>

<table id="cti" class="display">
<thead><tr>
<th>Indicator</th><th>Type</th><th>Source</th><th>Severity</th>
<th>MITRE</th><th>Score</th><th>Country</th><th>Last Seen</th>
</tr></thead>
<tbody></tbody>
</table>

<script>
var map=L.map('map',{zoomControl:false}).setView([4.5,102],6)
L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png').addTo(map)

function fetchData(){
$.getJSON("/api/data",function(data){
var table=$("#cti").DataTable()
table.clear()

var mitre_counts={}, sev_counts={"Low":0,"Medium":0,"High":0,"Critical":0}, timeline_counts={}

data.forEach(p=>{
table.row.add([
p.indicator,p.type,p.source,
`<span class="${p.severity.toLowerCase()}">${p.severity}</span>`,
p.mitre,p.score,p.country,p.last_seen
])
var color="crimson"
if(p.severity=="Critical"){color="red"}
var marker=L.circleMarker([p.lat,p.lon],{radius:10,color:color}).addTo(map)
if(p.severity=="High"){marker._path.classList.add("pulse")}

// Charts
mitre_counts[p.mitre]=(mitre_counts[p.mitre]||0)+1
sev_counts[p.severity]++
var t=p.last_seen.substring(0,13)
timeline_counts[t]=(timeline_counts[t]||0)+1
})

table.draw()

function drawChart(id,labels,data,label,background){
var ctx=document.getElementById(id)
new Chart(ctx,{
type:'bar',
data:{labels:labels,datasets:[{label:label,data:data,backgroundColor:background}]},
options:{plugins:{legend:{display:false}},responsive:true,maintainAspectRatio:false}
})
}

// MITRE
drawChart("mitre",Object.keys(mitre_counts),Object.values(mitre_counts),"MITRE ATT&CK","rgba(56,189,248,0.7)")
// Severity
drawChart("severity",Object.keys(sev_counts),Object.values(sev_counts),"Severity",["green","orange","crimson","red"])
// Timeline
drawChart("timeline",Object.keys(timeline_counts),Object.values(timeline_counts),"Threat Timeline","rgba(255,255,255,0.7)")
})
}

$(document).ready(function(){
$('#cti').DataTable()
fetchData()
setInterval(fetchData,60000)
})
</script>
</body>
</html>
"""

if __name__=="__main__":
    app.run(host="0.0.0.0", port=5000)