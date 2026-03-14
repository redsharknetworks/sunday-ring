import os, io, csv, json, sqlite3, threading, time, requests, random
from datetime import datetime
from flask import Flask, render_template_string, send_file, jsonify
from zipfile import ZipFile
from collections import deque

app = Flask(__name__)
DB = "soc_v3_real.db"

# -----------------------------
# DATABASE INIT
# -----------------------------
def init_db():
    conn = sqlite3.connect(DB, check_same_thread=False)
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS threats(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT,
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
    conn.commit(); conn.close()

init_db()

# -----------------------------
# MITRE MAPPING
# -----------------------------
def mitre_map(cat):
    mapping = {"C2":"Command and Control",
               "Recon":"Reconnaissance",
               "Botnet":"Persistence",
               "Phishing":"Initial Access",
               "Malware":"Execution"}
    return mapping.get(cat,"Unknown")

# -----------------------------
# Threat ingestion feeds
# -----------------------------
FEEDS = {
    "Feodo Tracker": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    "EmergingThreats Block": "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
    "EmergingThreats Compromised": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
    "Blocklist.de": "https://lists.blocklist.de/lists/all.txt"
}

# In-memory latest threats cache
latest_threats = deque(maxlen=100)

# -----------------------------
# GEO enrichment
# -----------------------------
def geo_ip(ip):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=5).json()
        return r.get("country","Unknown"), r.get("as","Unknown"), r.get("lat",0), r.get("lon",0)
    except:
        return "Unknown","Unknown",0,0

# -----------------------------
# Store threat
# -----------------------------
def store_threat(ip, source):
    categories=["C2","Recon","Botnet","Malware","Phishing"]
    sev=random.choice(["Low","Medium","High","Critical"])
    cat=random.choice(categories)
    mitre = mitre_map(cat)
    country, asn, lat, lon = geo_ip(ip)
    cluster = random.randint(1,5)

    # store to DB
    conn = sqlite3.connect(DB, check_same_thread=False)
    c = conn.cursor()
    c.execute("""
        INSERT INTO threats(ip,country,asn,category,severity,mitre,source,cluster_id,lat,lon,fetched_at)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
    """,(ip,country,asn,cat,sev,mitre,source,cluster,lat,lon,datetime.utcnow().isoformat()))
    conn.commit(); conn.close()

    # store to cache for live map
    latest_threats.appendleft({
        "ip": ip,
        "country": country,
        "asn": asn,
        "category": cat,
        "severity": sev,
        "mitre": mitre,
        "source": source,
        "cluster": cluster,
        "lat": lat,
        "lon": lon,
        "time": datetime.utcnow().isoformat()
    })

# -----------------------------
# Fetch feed
# -----------------------------
def fetch_feed(name, url):
    try:
        r = requests.get(url, timeout=15)
        lines = r.text.splitlines()
        ips = []
        for l in lines:
            l = l.strip()
            if not l or l.startswith("#") or l.startswith(";"):
                continue
            parts = l.split()
            ip = parts[0]
            if ip.count(".") == 3:
                ips.append(ip)
        return ips
    except Exception as e:
        print(f"Error fetching feed {name}: {e}")
        return []

# -----------------------------
# Ingestion loop (real feeds)
# -----------------------------
def ingest_loop():
    while True:
        for name,url in FEEDS.items():
            ips = fetch_feed(name,url)
            for ip in ips:
                store_threat(ip,name)
        time.sleep(3600)  # every 1 hour

threading.Thread(target=ingest_loop, daemon=True).start()

# -----------------------------
# Threat index
# -----------------------------
def threat_index():
    conn = sqlite3.connect(DB, check_same_thread=False)
    c = conn.cursor()
    c.execute("SELECT severity,count(*) FROM threats GROUP BY severity")
    rows = c.fetchall(); conn.close()
    score = 0; total = 0
    for sev,count in rows:
        if sev=="Critical": score += count*3
        elif sev=="High": score += count*2
        elif sev=="Medium": score += count*1
        total += count
    return round(score/total,2) if total>0 else 0

# -----------------------------
# API
# -----------------------------
@app.route("/api/threats")
def api_threats():
    return jsonify(list(latest_threats))

# -----------------------------
# Downloads
# -----------------------------
@app.route("/download/csv")
def download_csv():
    conn = sqlite3.connect(DB, check_same_thread=False)
    c = conn.cursor(); c.execute("SELECT * FROM threats"); rows = c.fetchall(); conn.close()
    output = io.StringIO(); writer = csv.writer(output)
    writer.writerow(["ID","IP","Country","ASN","Category","Severity","MITRE","Source","Cluster","Lat","Lon","FetchedAt"])
    for r in rows: writer.writerow(r)
    mem = io.BytesIO(); mem.write(output.getvalue().encode()); mem.seek(0)
    return send_file(mem, download_name="soc_real.csv", as_attachment=True)

@app.route("/download/json")
def download_json():
    conn = sqlite3.connect(DB, check_same_thread=False)
    c = conn.cursor(); c.execute("SELECT * FROM threats"); rows = c.fetchall(); conn.close()
    mem = io.BytesIO(); mem.write(json.dumps(rows, indent=2).encode()); mem.seek(0)
    return send_file(mem, download_name="soc_real.json", as_attachment=True)

@app.route("/download/rules")
def download_rules():
    conn = sqlite3.connect(DB, check_same_thread=False)
    c = conn.cursor(); c.execute("SELECT ip FROM threats"); ips = c.fetchall(); conn.close()
    rules = ""
    for ip in ips:
        rules += f"alert ip {ip[0]} any -> any any (msg:\"SOC Real Block {ip[0]}\"; sid:{random.randint(100000,999999)};)\n"
    mem = io.BytesIO()
    with ZipFile(mem,'w') as z: z.writestr("soc_real_rules.rules", rules)
    mem.seek(0)
    return send_file(mem, download_name="soc_real_rules.zip", as_attachment=True)

# -----------------------------
# Dashboard
# -----------------------------
@app.route("/")
def dashboard():
    title = f"CTI HIGHLIGHT AT {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}"
    html=f"""
<html>
<head>
<title>{title}</title>
<style>
body{{background:#0e1a2b;color:#cfd8dc;font-family:Arial}}
h1{{color:#a1c4fd}}
table{{width:100%;border-collapse:collapse}}
td,th{{border:1px solid #334155;padding:6px}}
.critical{{color:#ff4c4c;animation:blink 1s infinite}}
@keyframes blink{{50%{{opacity:0}}}}
canvas{{background:#0e1a2b;display:block;margin:20px auto;border:1px solid #334155}}
</style>
</head>
<body>
<h1>{title}</h1>
<h3>Threat Index: {threat_index()}</h3>
<canvas id="map" width="1000" height="500"></canvas>
<table id="tbl">
<tr><th>IP</th><th>Country</th><th>ASN</th><th>Category</th><th>Severity</th><th>MITRE</th><th>Source</th><th>Cluster</th><th>Lat</th><th>Lon</th><th>Time</th></tr>
</table>
<br>
<button onclick="window.location='/download/csv'">CSV</button>
<button onclick="window.location='/download/json'">JSON</button>
<button onclick="window.location='/download/rules'">IDS Rules</button>
<br><small>Developed and analysed by darkgrid@redshark.my using publicly available sources</small>

<script>
let threats=[]
async function loadData(){{
    let r = await fetch("/api/threats"); threats = await r.json()
    let tbl = document.getElementById("tbl")
    tbl.innerHTML = "<tr><th>IP</th><th>Country</th><th>ASN</th><th>Category</th><th>Severity</th><th>MITRE</th><th>Source</th><th>Cluster</th><th>Lat</th><th>Lon</th><th>Time</th></tr>"
    threats.forEach(t=>{{
        let sev=t.severity; if(sev=="Critical") sev='<span class="critical">Critical</span>'
        let tr=document.createElement("tr")
        tr.innerHTML=`<td>${{t.ip}}</td><td>${{t.country}}</td><td>${{t.asn}}</td><td>${{t.category}}</td><td>${{sev}}</td><td>${{t.mitre}}</td><td>${{t.source}}</td><td>${{t.cluster}}</td><td>${{t.lat}}</td><td>${{t.lon}}</td><td>${{t.time}}</td>`
        tbl.appendChild(tr)
    }})
}}
function drawMap(){{
    const canvas=document.getElementById("map")
    const ctx=canvas.getContext("2d")
    ctx.clearRect(0,0,canvas.width,canvas.height)
    ctx.fillStyle="#0e1a2b"; ctx.fillRect(0,0,canvas.width,canvas.height)
    ctx.strokeStyle="#a1c4fd"; ctx.lineWidth=1.2
    threats.forEach(t=>{{
        let x = canvas.width*(180+t.lon)/360
        let y = canvas.height*(90-t.lat)/180
        ctx.beginPath(); ctx.arc(x,y,4,0,2*Math.PI)
        ctx.fillStyle = (t.severity=="Critical") ? "#ff4c4c" : "#00ffae"; ctx.fill()
        ctx.beginPath(); ctx.moveTo(canvas.width*(180+101.7)/360, canvas.height*(90-4.2)/180)
        ctx.lineTo(x,y); ctx.stroke()
    }})
    setTimeout(drawMap,5000)
}}
loadData(); setInterval(loadData,30000); drawMap()
</script>
</body>
</html>
"""
    return html

if __name__=="__main__":
    app.run(host="0.0.0.0", port=5000)