import os
import io
import csv
import json
import sqlite3
import threading
import time
import requests
import random
from datetime import datetime
from flask import Flask, render_template_string, send_file, jsonify
from zipfile import ZipFile
from collections import deque

app = Flask(__name__)
DB_FILE = "soc_v3_cti.db"
db_lock = threading.Lock()
latest_threats = deque(maxlen=100)  # Keep last 100 threats for map/table

# ========================
# DATABASE SETUP
# ========================
def init_db():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS threats(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT UNIQUE,
        country TEXT,
        asn TEXT,
        category TEXT,
        severity TEXT,
        mitre TEXT,
        source TEXT,
        cluster_id INTEGER,
        lat REAL,
        lon REAL,
        fetched_at TEXT
    )
    """)
    conn.commit()
    conn.close()

init_db()

# ========================
# MITRE MAPPING
# ========================
def mitre_map(category):
    mapping = {
        "C2": "Command and Control",
        "Recon": "Reconnaissance",
        "Botnet": "Persistence",
        "Phishing": "Initial Access",
        "Malware": "Execution"
    }
    return mapping.get(category,"Unknown")

# ========================
# STORE THREAT
# ========================
def store_threat(ip, source, country=None, asn=None, lat=None, lon=None, category=None, severity=None, mitre=None):
    categories = ["C2","Recon","Botnet","Malware","Phishing"]
    if severity is None: severity=random.choice(["Low","Medium","High","Critical"])
    if category is None: category=random.choice(categories)
    if mitre is None: mitre = mitre_map(category)
    if country is None or asn is None or lat is None or lon is None:
        country, asn, lat, lon = "Unknown","Unknown",0,0
    cluster_id = random.randint(1,5)
    with db_lock:
        conn = sqlite3.connect(DB_FILE, check_same_thread=False)
        c = conn.cursor()
        try:
            c.execute("""
                INSERT INTO threats(ip,country,asn,category,severity,mitre,source,cluster_id,lat,lon,fetched_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
            """,(ip,country,asn,category,severity,mitre,source,cluster_id,lat,lon,datetime.utcnow().isoformat()))
            conn.commit()
            latest_threats.appendleft({
                "ip":ip,"country":country,"asn":asn,"category":category,
                "severity":severity,"mitre":mitre,"source":source,"cluster":cluster_id,
                "lat":lat,"lon":lon,"time":datetime.utcnow().isoformat()
            })
        except sqlite3.IntegrityError:
            pass
        conn.close()

# ========================
# PRELOAD DEMO BAD IPs
# ========================
def preload_demo_bad_ips():
    demo_ips = [
        {"ip":"192.9.135.73","country":"France","asn":"ASXXXX","category":"C2","severity":"Critical","mitre":"Command and Control","source":"Feodo Tracker","lat":48.85,"lon":2.35},
        {"ip":"51.161.81.190","country":"UK","asn":"ASYYYY","category":"Botnet","severity":"High","mitre":"Persistence","source":"Feodo Tracker","lat":51.51,"lon":-0.13},
        {"ip":"37.252.6.219","country":"Russia","asn":"ASZZZZ","category":"Malware","severity":"High","mitre":"Execution","source":"Feodo Tracker","lat":55.75,"lon":37.62},
        {"ip":"172.232.185.9","country":"USA","asn":"ASAAAA","category":"Recon","severity":"Medium","mitre":"Reconnaissance","source":"Feodo Tracker","lat":40.71,"lon":-74.01},
        {"ip":"172.232.188.170","country":"USA","asn":"ASBBBB","category":"Botnet","severity":"High","mitre":"Persistence","source":"Feodo Tracker","lat":34.05,"lon":-118.24},
        {"ip":"180.76.76.76","country":"China","asn":"AS58577","category":"Malware","severity":"Critical","mitre":"Execution","source":"Feodo Tracker","lat":39.9075,"lon":116.39723},
        {"ip":"203.0.113.5","country":"Malaysia","asn":"AS4788","category":"Botnet","severity":"Medium","mitre":"Persistence","source":"Feodo Tracker","lat":3.139,"lon":101.686},
        {"ip":"159.203.69.20","country":"Netherlands","asn":"AS14061","category":"Phishing","severity":"High","mitre":"Initial Access","source":"Feodo Tracker","lat":52.3676,"lon":4.9041}
    ]
    for d in demo_ips:
        store_threat(d["ip"],d["source"],d["country"],d["asn"],d["lat"],d["lon"],d["category"],d["severity"],d["mitre"])

preload_demo_bad_ips()

# ========================
# THREAT INDEX
# ========================
def threat_index():
    conn=sqlite3.connect(DB_FILE,check_same_thread=False)
    c=conn.cursor()
    c.execute("SELECT severity,count(*) FROM threats GROUP BY severity")
    rows=c.fetchall(); conn.close()
    score=0; total=0
    for sev,count in rows:
        if sev=="Critical": score+=count*3
        elif sev=="High": score+=count*2
        elif sev=="Medium": score+=count
        total+=count
    return round(score/total,2) if total>0 else 0

# ========================
# BACKGROUND FEED INGESTION (every 5 minutes)
# ========================
FEED_URLS = [
    "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
    # You can add more public feeds here
]

def fetch_feeds():
    while True:
        for url in FEED_URLS:
            try:
                r = requests.get(url, timeout=10)
                if r.status_code == 200:
                    lines = r.text.splitlines()
                    for line in lines:
                        if line.startswith("#") or not line.strip(): continue
                        ip = line.strip()
                        store_threat(ip, source=url)
            except Exception as e:
                print(f"[Feed Error] {url}: {e}")
        time.sleep(300)  # 5 minutes

threading.Thread(target=fetch_feeds,daemon=True).start()

# ========================
# API
# ========================
@app.route("/api/threats")
def api_threats():
    return jsonify(list(latest_threats))

# ========================
# DOWNLOAD CSV / JSON / IDS RULES
# ========================
@app.route("/download/csv")
def download_csv():
    conn=sqlite3.connect(DB_FILE,check_same_thread=False)
    c=conn.cursor(); c.execute("SELECT * FROM threats"); rows=c.fetchall(); conn.close()
    output=io.StringIO(); writer=csv.writer(output)
    writer.writerow(["ID","IP","Country","ASN","Category","Severity","MITRE","Source","Cluster","Lat","Lon","FetchedAt"])
    for r in rows: writer.writerow(r)
    mem=io.BytesIO(); mem.write(output.getvalue().encode()); mem.seek(0)
    return send_file(mem,download_name="soc_demo.csv",as_attachment=True)

@app.route("/download/json")
def download_json():
    conn=sqlite3.connect(DB_FILE,check_same_thread=False)
    c=conn.cursor(); c.execute("SELECT * FROM threats"); rows=c.fetchall(); conn.close()
    mem=io.BytesIO(); mem.write(json.dumps(rows,indent=2).encode()); mem.seek(0)
    return send_file(mem,download_name="soc_demo.json",as_attachment=True)

@app.route("/download/rules")
def download_rules():
    conn=sqlite3.connect(DB_FILE,check_same_thread=False)
    c=conn.cursor(); c.execute("SELECT ip FROM threats"); ips=c.fetchall(); conn.close()
    rules=""
    for ip in ips:
        rules+=f"alert ip {ip[0]} any -> any any (msg:\"SOC Block {ip[0]}\"; sid:{random.randint(100000,999999)};)\n"
    mem=io.BytesIO()
    with ZipFile(mem,"w") as z: z.writestr("soc_rules.rules",rules)
    mem.seek(0)
    return send_file(mem,download_name="soc_rules.zip",as_attachment=True)

# ========================
# DASHBOARD
# ========================
@app.route("/")
def dashboard():
    title=f"CTI HIGHLIGHT AT {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}"
    html=f"""
<html>
<head>
<title>{title}</title>
<style>
body {{ background:#0e1a2b; color:#cfd8dc; font-family:Arial,sans-serif; }}
h1{{color:#a1c4fd}} h3{{color:#89a7c2}}
table{{width:100%;border-collapse:collapse}}
th,td{{border:1px solid #334155;padding:6px}}
.critical{{color:#ff4c4c;animation:blink 1s infinite}}
@keyframes blink {{50%{{opacity:0}}}}
canvas{{background:#0e1a2b; display:block;margin:20px auto;border:1px solid #334155}}
button{{background:#1f2937;color:#cfd8dc;padding:5px 12px;margin:3px;border:none;border-radius:4px;cursor:pointer}}
button:hover{{background:#334155}}
</style>
</head>
<body>
<h1>{title}</h1>
<h3>Threat Index: {threat_index()}</h3>
<canvas id="map" width="1000" height="500"></canvas>
<table id="tbl">
<tr><th>IP</th><th>Country</th><th>ASN</th><th>Category</th><th>Severity</th><th>MITRE</th><th>Source</th><th>Cluster</th><th>Lat</th><th>Lon</th><th>Time</th></tr>
</table>
<button onclick="window.location='/download/csv'">CSV</button>
<button onclick="window.location='/download/json'">JSON</button>
<button onclick="window.location='/download/rules'">IDS Rules</button>
<small>Developed by darkgrid@redshark.my using publicly available sources</small>
<script>
let threats=[]
const MALAYSIA={{latMin:1.0,latMax:7.5,lonMin:99.5,lonMax:119.0}}
async function loadData(){{
let r=await fetch("/api/threats"); threats=await r.json()
let tbl=document.getElementById("tbl"); tbl.innerHTML="<tr><th>IP</th><th>Country</th><th>ASN</th><th>Category</th><th>Severity</th><th>MITRE</th><th>Source</th><th>Cluster</th><th>Lat</th><th>Lon</th><th>Time</th></tr>"
threats.forEach(t=>{{
let sev=t.severity
if(sev=="Critical")sev='<span class="critical">Critical</span>'
let tr=document.createElement("tr")
tr.innerHTML=`<td>${{t.ip}}</td><td>${{t.country}}</td><td>${{t.asn}}</td><td>${{t.category}}</td><td>${{sev}}</td><td>${{t.mitre}}</td><td>${{t.source}}</td><td>${{t.cluster}}</td><td>${{t.lat}}</td><td>${{t.lon}}</td><td>${{t.time}}</td>`
tbl.appendChild(tr)
}})}
loadData(); setInterval(loadData,15000)  // table refresh every 15s

function drawMap(){{
const canvas=document.getElementById("map")
const ctx=canvas.getContext("2d")
ctx.clearRect(0,0,canvas.width,canvas.height)
ctx.fillStyle="#0e1a2b"; ctx.fillRect(0,0,canvas.width,canvas.height)
ctx.strokeStyle="#a1c4fd"; ctx.lineWidth=1.2
let latRange=MALAYSIA.latMax-MALAYSIA.latMin
let lonRange=MALAYSIA.lonMax-MALAYSIA.lonMin
let latScale=canvas.height/latRange
let lonScale=canvas.width/lonRange
threats.forEach(t=>{{
let x=(t.lon-MALAYSIA.lonMin)*lonScale
let y=canvas.height-(t.lat-MALAYSIA.latMin)*latScale
ctx.beginPath()
ctx.arc(x,y,4,0,2*Math.PI)
ctx.fillStyle=(t.severity=="Critical")?"#ff4c4c":"#00ffae"
ctx.fill()
}})
}}
drawMap(); setInterval(drawMap,10000)  // map redraw every 10s
</script>
</body>
</html>
"""
    return html

if __name__=="__main__":
    app.run(host="0.0.0.0",port=5000)