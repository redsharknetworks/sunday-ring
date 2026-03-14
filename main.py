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
import ipaddress

# ================================
# Flask App
# ================================
app = Flask(__name__)
DB_FILE = "soc_v3_malaysia.db"

# ================================
# Initialize Database
# ================================
def init_db():
    """
    Create SQLite database and threats table
    """
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

# ================================
# Preload Demo IPs
# ================================
def populate_demo_data():
    """
    Populate demo IPs so the dashboard has immediate data
    """
    demo_ips = [
        {"ip":"8.8.8.8","country":"United States","asn":"AS15169","category":"Recon","severity":"High","mitre":"Reconnaissance","source":"Demo","lat":37.386,"lon":-122.084},
        {"ip":"1.1.1.1","country":"Australia","asn":"AS13335","category":"C2","severity":"Critical","mitre":"Command and Control","source":"Demo","lat":-33.494,"lon":143.210},
        {"ip":"203.0.113.5","country":"Malaysia","asn":"AS4788","category":"Malware","severity":"Medium","mitre":"Execution","source":"Demo","lat":3.139,"lon":101.686},
        {"ip":"198.51.100.23","country":"Netherlands","asn":"AS1239","category":"Botnet","severity":"Critical","mitre":"Persistence","source":"Demo","lat":52.3676,"lon":4.9041}
    ]
    for d in demo_ips:
        store_threat(d["ip"], d["source"])

populate_demo_data()

# ================================
# MITRE Mapping
# ================================
def mitre_map(category):
    """
    Map threat category to MITRE tactic
    """
    mapping = {
        "C2": "Command and Control",
        "Recon": "Reconnaissance",
        "Botnet": "Persistence",
        "Phishing": "Initial Access",
        "Malware": "Execution"
    }
    return mapping.get(category, "Unknown")

# ================================
# Threat Feeds
# ================================
FEEDS = {
    "Feodo Tracker": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    "EmergingThreats Block": "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
    "EmergingThreats Compromised": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
    "Blocklist.de": "https://lists.blocklist.de/lists/all.txt"
}

# ================================
# In-memory cache
# ================================
latest_threats = deque(maxlen=200)

# ================================
# Geo-IP Enrichment
# ================================
def geo_ip(ip):
    """
    Query ip-api.com to get country, ASN, latitude, longitude
    """
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=5).json()
        return r.get("country", "Unknown"), r.get("as", "Unknown"), r.get("lat", 0), r.get("lon", 0)
    except:
        return "Unknown", "Unknown", 0, 0

# ================================
# Feed Parsing
# ================================
def parse_feed(feed_text):
    """
    Extract IP addresses (including CIDR) from feed text
    """
    ips = set()
    for line in feed_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        token = line.split()[0]
        try:
            if "/" in token:
                net = ipaddress.ip_network(token, strict=False)
                for ip in net.hosts():
                    ips.add(str(ip))
            else:
                ipaddress.ip_address(token)
                ips.add(token)
        except:
            continue
    return list(ips)

# ================================
# Store Threat Function
# ================================
def store_threat(ip, source):
    """
    Store threat in SQLite and in-memory cache
    """
    categories = ["C2", "Recon", "Botnet", "Malware", "Phishing"]
    severity = random.choice(["Low","Medium","High","Critical"])
    category = random.choice(categories)
    mitre = mitre_map(category)
    country, asn, lat, lon = geo_ip(ip)
    cluster_id = random.randint(1,5)

    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    c = conn.cursor()
    try:
        c.execute("""
            INSERT INTO threats(ip, country, asn, category, severity, mitre, source, cluster_id, lat, lon, fetched_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (ip, country, asn, category, severity, mitre, source, cluster_id, lat, lon, datetime.utcnow().isoformat()))
        conn.commit()
        conn.close()
        latest_threats.appendleft({
            "ip": ip,
            "country": country,
            "asn": asn,
            "category": category,
            "severity": severity,
            "mitre": mitre,
            "source": source,
            "cluster": cluster_id,
            "lat": lat,
            "lon": lon,
            "time": datetime.utcnow().isoformat()
        })
        return True
    except sqlite3.IntegrityError:
        conn.close()
        return False

# ================================
# Threat Ingestion
# ================================
def ingest_once():
    """
    Run ingestion once for all feeds
    """
    inserted = 0
    for name, url in FEEDS.items():
        try:
            r = requests.get(url, timeout=15)
            ips = parse_feed(r.text)
            for ip in ips:
                if store_threat(ip, name):
                    inserted += 1
        except Exception as e:
            print(f"[Feed Error] {name} -> {e}")
    print(f"[Ingestion] Inserted {inserted} new IPs at {datetime.utcnow().isoformat()}")
    return inserted

def ingest_loop():
    """
    Run ingestion in background thread every hour
    """
    ingest_once()
    while True:
        time.sleep(3600)
        ingest_once()

threading.Thread(target=ingest_loop, daemon=True).start()

# ================================
# Threat Index Calculation
# ================================
def threat_index():
    """
    Compute threat index based on severity
    """
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    c = conn.cursor()
    c.execute("SELECT severity, count(*) FROM threats GROUP BY severity")
    rows = c.fetchall()
    conn.close()
    score = 0
    total = 0
    for sev, count in rows:
        if sev=="Critical": score += count*3
        elif sev=="High": score += count*2
        elif sev=="Medium": score += count*1
        total += count
    return round(score/total,2) if total>0 else 0

# ================================
# API Endpoint
# ================================
@app.route("/api/threats")
def api_threats():
    return jsonify(list(latest_threats))

# ================================
# CSV Download
# ================================
@app.route("/download/csv")
def download_csv():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    c = conn.cursor()
    c.execute("SELECT * FROM threats")
    rows = c.fetchall()
    conn.close()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID","IP","Country","ASN","Category","Severity","MITRE","Source","Cluster","Lat","Lon","FetchedAt"])
    for r in rows:
        writer.writerow(r)
    mem = io.BytesIO()
    mem.write(output.getvalue().encode())
    mem.seek(0)
    return send_file(mem, download_name="soc_v3_malaysia.csv", as_attachment=True)

# ================================
# JSON Download
# ================================
@app.route("/download/json")
def download_json():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    c = conn.cursor()
    c.execute("SELECT * FROM threats")
    rows = c.fetchall()
    conn.close()
    mem = io.BytesIO()
    mem.write(json.dumps(rows, indent=2).encode())
    mem.seek(0)
    return send_file(mem, download_name="soc_v3_malaysia.json", as_attachment=True)

# ================================
# IDS Rules Download
# ================================
@app.route("/download/rules")
def download_rules():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    c = conn.cursor()
    c.execute("SELECT ip FROM threats")
    ips = c.fetchall()
    conn.close()
    rules = ""
    for ip in ips:
        rules += f"alert ip {ip[0]} any -> any any (msg:\"SOC Block {ip[0]}\"; sid:{random.randint(100000,999999)};)\n"
    mem = io.BytesIO()
    with ZipFile(mem, "w") as z:
        z.writestr("soc_v3_rules.rules", rules)
    mem.seek(0)
    return send_file(mem, download_name="soc_v3_rules.zip", as_attachment=True)

# ================================
# Dashboard HTML
# ================================
@app.route("/")
def dashboard():
    title = f"CTI HIGHLIGHT AT {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}"
    html = f"""
<html>
<head>
<title>{title}</title>
<style>
body {{
    background:#0e1a2b;
    color:#cfd8dc;
    font-family:Arial, sans-serif;
}}
h1 {{ color:#a1c4fd; }}
h3 {{ color:#89a7c2; }}
table {{ width:100%; border-collapse:collapse; }}
td, th {{ border:1px solid #334155; padding:6px; }}
.critical {{ color:#ff4c4c; animation:blink 1s infinite; }}
@keyframes blink {{ 50% {{ opacity:0; }} }}
canvas {{ background:#0e1a2b; display:block; margin:20px auto; border:1px solid #334155; }}
button {{
    background:#1f2937;
    color:#cfd8dc;
    padding:5px 12px;
    margin:3px;
    border:none;
    border-radius:4px;
    cursor:pointer;
}}
button:hover {{ background:#334155; }}
</style>
</head>
<body>
<h1>{title}</h1>
<h3>Threat Index: {threat_index()}</h3>
<canvas id="map" width="1000" height="500"></canvas>
<table id="tbl">
<tr>
<th>IP</th><th>Country</th><th>ASN</th><th>Category</th><th>Severity</th>
<th>MITRE</th><th>Source</th><th>Cluster</th><th>Lat</th><th>Lon</th><th>Time</th>
</tr>
</table>
<br>
<button onclick="window.location='/download/csv'">CSV</button>
<button onclick="window.location='/download/json'">JSON</button>
<button onclick="window.location='/download/rules'">IDS Rules</button>
<br>
<small>Developed and analysed by darkgrid@redshark.my using publicly available sources</small>

<script>
let threats = []
const MALAYSIA = {{latMin:1.0, latMax:7.5, lonMin:99.5, lonMax:119.0}}

async function loadData() {{
    let r = await fetch("/api/threats")
    threats = await r.json()
    let tbl = document.getElementById("tbl")
    tbl.innerHTML = "<tr><th>IP</th><th>Country</th><th>ASN</th><th>Category</th><th>Severity</th><th>MITRE</th><th>Source</th><th>Cluster</th><th>Lat</th><th>Lon</th><th>Time</th></tr>"
    threats.forEach(t => {{
        let sev = t.severity
        if(sev=="Critical") sev='<span class="critical">Critical</span>'
        let tr = document.createElement("tr")
        tr.innerHTML = `<td>${{t.ip}}</td><td>${{t.country}}</td><td>${{t.asn}}</td><td>${{t.category}}</td><td>${{sev}}</td><td>${{t.mitre}}</td><td>${{t.source}}</td><td>${{t.cluster}}</td><td>${{t.lat}}</td><td>${{t.lon}}</td><td>${{t.time}}</td>`
        tbl.appendChild(tr)
    }})
}}

function drawMap() {{
    const canvas = document.getElementById("map")
    const ctx = canvas.getContext("2d")
    ctx.clearRect(0,0,canvas.width,canvas.height)
    ctx.fillStyle="#0e1a2b"; ctx.fillRect(0,0,canvas.width,canvas.height)
    ctx.strokeStyle="#a1c4fd"; ctx.lineWidth=1.2

    let latRange = MALAYSIA.latMax-MALAYSIA.latMin
    let lonRange = MALAYSIA.lonMax-MALAYSIA.lonMin
    let latScale = canvas.height/latRange
    let lonScale = canvas.width/lonRange

    threats.forEach(t => {{
        let x = (t.lon-MALAYSIA.lonMin)*lonScale
        let y = canvas.height-(t.lat-MALAYSIA.latMin)*latScale
        ctx.beginPath()
        ctx.arc(x,y,4,0,2*Math.PI)
        ctx.fillStyle = (t.severity=="Critical")?"#ff4c4c":"#00ffae"
        ctx.fill()
    }})
    setTimeout(drawMap,5000)
}}

loadData()
setInterval(loadData,30000)
drawMap()
</script>
</body>
</html>
"""
    return html

if __name__=="__main__":
    app.run(host="0.0.0.0", port=5000)