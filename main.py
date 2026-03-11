import os
import sqlite3
import threading
import time
import random
import requests
import io
import csv
import json
from datetime import datetime
from flask import Flask, jsonify, render_template_string, send_file
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table
from reportlab.lib.pagesizes import landscape, A4
from reportlab.lib.styles import getSampleStyleSheet

# ---------------- CONFIG ----------------
app = Flask(__name__)
PORT = int(os.getenv("PORT",5000))
DB = os.getenv("DB_PATH","/tmp/sundayring.db")
OTX_KEY = os.getenv("OTX_KEY")
ABUSE_KEY = os.getenv("ABUSE_KEY")

# ---------------- MALAYSIA STATES ----------------
STATES = [
    [1.4927,103.7414],  # Johor
    [6.1164,100.3678],  # Kedah
    [6.1254,102.2381],  # Kelantan
    [2.1896,102.2501],  # Melaka
    [2.7290,101.9383],  # Negeri Sembilan
    [3.8167,103.3333],  # Pahang
    [4.5929,101.0900],  # Perak
    [6.4400,100.2000],  # Perlis
    [5.4164,100.3327],  # Penang
    [5.3300,103.1400],  # Terengganu
    [3.1390,101.6869],  # Selangor
    [3.1390,101.6869],  # Kuala Lumpur
    [2.9264,101.6981],  # Putrajaya
    [5.2833,115.2333],  # Labuan
    [5.9804,116.0735],  # Sabah
    [1.5533,110.3592],  # Sarawak
]

# ---------------- DATABASE ----------------
def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS threats(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source TEXT,
        indicator TEXT UNIQUE,
        type TEXT,
        risk INTEGER,
        apt TEXT,
        sector TEXT,
        created_at TEXT
    )
    """)
    conn.commit()
    conn.close()

# ---------------- DUMMY DATA ----------------
def insert_dummy_data():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    for i in range(20):
        ind = f"malicious{i+1}.com"
        c.execute("""
        INSERT OR IGNORE INTO threats(source,indicator,type,risk,apt,sector,created_at)
        VALUES(?,?,?,?,?,?,?)
        """,(
            "Dummy",
            ind,
            "domain",
            random.randint(40,90),
            random.choice(["APT28","APT41","Lazarus","Unknown"]),
            random.choice(["Finance","Government","Telecom","Energy","Public"]),
            datetime.utcnow().isoformat()
        ))
    conn.commit()
    conn.close()

# ---------------- APT DETECTION ----------------
def detect_apt(indicator):
    ind = indicator.lower()
    if ".ru" in ind: return "APT28"
    if ".cn" in ind: return "APT41"
    if ".kp" in ind: return "Lazarus"
    return "Unknown"

# ---------------- INSERT IOC ----------------
def insert_ioc(source, indicator, typ, risk):
    apt = detect_apt(indicator)
    sector = random.choice(["Finance","Government","Telecom","Energy","Public"])
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    try:
        c.execute("""
        INSERT OR IGNORE INTO threats(source,indicator,type,risk,apt,sector,created_at)
        VALUES (?,?,?,?,?,?,?)
        """,(source, indicator, typ, risk, apt, sector, datetime.utcnow().isoformat()))
        conn.commit()
    except:
        pass
    conn.close()

# ---------------- THREAT FEEDS ----------------
def fetch_otx():
    if not OTX_KEY: return
    url = "https://otx.alienvault.com/api/v1/indicators/export?types=IPv4,domain,url&limit=200"
    headers = {"X-OTX-API-KEY":OTX_KEY}
    try:
        r = requests.get(url, headers=headers, timeout=30)
        r.raise_for_status()
        for line in r.text.splitlines():
            parts = line.split(",")
            if len(parts)<2: continue
            insert_ioc("OTX", parts[0], parts[1], random.randint(40,90))
    except:
        pass

def fetch_threatfox():
    url = "https://threatfox-api.abuse.ch/api/v1/"
    payload = {"query":"get_iocs","limit":100}
    try:
        r = requests.post(url,json=payload,timeout=30)
        data = r.json()
        if data.get("query_status")!="ok": return
        for i in data["data"]:
            insert_ioc("ThreatFox", i["ioc"], i["ioc_type"], 85)
    except:
        pass

def fetch_urlhaus():
    url = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
    try:
        r = requests.get(url, timeout=30)
        data = r.json()
        for u in data.get("urls",[]):
            insert_ioc("URLHaus", u["url"], "url", 75)
    except:
        pass

# ---------------- COLLECTOR ----------------
def collector():
    try:
        fetch_otx()
        fetch_threatfox()
        fetch_urlhaus()
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM threats")
        if c.fetchone()[0]==0: insert_dummy_data()
        conn.close()
    except:
        insert_dummy_data()
    while True:
        try:
            fetch_otx()
            fetch_threatfox()
            fetch_urlhaus()
        except:
            insert_dummy_data()
        time.sleep(3600)

# ---------------- SECURENATION INDEX ----------------
def securenation():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    rows = c.execute("SELECT risk FROM threats").fetchall()
    conn.close()
    if not rows: return 100
    avg = sum([r[0] for r in rows])/len(rows)
    return round(100-avg/2,2)

# ---------------- TREND ----------------
def trend():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    rows = c.execute("""
    SELECT substr(created_at,1,10),count(*) FROM threats
    GROUP BY substr(created_at,1,10) ORDER BY substr(created_at,1,10)
    """).fetchall()
    conn.close()
    labels = [r[0] for r in rows]
    values = [r[1] for r in rows]
    return labels, values

# ---------------- TOP10 ----------------
def top10():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    rows = c.execute("""
    SELECT indicator,count(*) FROM threats
    GROUP BY indicator ORDER BY count(*) DESC LIMIT 10
    """).fetchall()
    conn.close()
    return rows

# ---------------- HEATMAP ----------------
def heatmap():
    return [[s[0],s[1],random.randint(1,10)] for s in STATES]

# ---------------- EXPORTS ----------------
def export_csv():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    rows = c.execute("SELECT * FROM threats").fetchall()
    conn.close()
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["id","source","indicator","type","risk","apt","sector","created"])
    for r in rows: writer.writerow(r)
    mem = io.BytesIO()
    mem.write(out.getvalue().encode())
    mem.seek(0)
    return mem

def export_json():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    rows = c.execute("SELECT * FROM threats").fetchall()
    conn.close()
    mem = io.BytesIO()
    mem.write(json.dumps(rows).encode())
    mem.seek(0)
    return mem

# ---------------- DASHBOARD TEMPLATE ----------------
TEMPLATE = """
<html>
<head>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script src="https://unpkg.com/leaflet.heat/dist/leaflet-heat.js"></script>
<style>
body{background:#0b0f17;color:#00fff0;font-family:Consolas,monospace;}
.card{background:#101728;padding:20px;margin:15px;border-radius:10px;box-shadow:0 0 15px #00fff0;}
h1,h2,h3{color:#00fff0;}
footer{color:#0aa; font-size:12px; margin-top:30px; text-align:center;}
</style>
</head>
<body>
<h1>Sunday-Ring Threat Intelligence Dashboard</h1>

<div class="card"><h2>SecureNation Index: {{index}}</h2></div>
<div class="card"><canvas id="trend"></canvas></div>
<div class="card"><div id="map" style="height:450px;"></div></div>
<div class="card">
<h3>Top 10 Indicators</h3>
<ul>
{% for t in top %}<li>{{t[0]}}</li>{% endfor %}
</ul>
</div>

<footer>Disclaimer: Developed and analysed by <b>darkgrid@redshark.my</b>. Data aggregated from publicly available sources.</footer>

<script>
const labels={{labels|safe}}
const values={{values|safe}}
new Chart(document.getElementById("trend"),{
    type:"line",
    data:{labels:labels,datasets:[{label:"Threat Trend",data:values,borderColor:"#00ff90",backgroundColor:"rgba(0,255,144,0.3)"}]},
    options:{plugins:{legend:{labels:{color:"#00fff0"}}},scales:{x:{ticks:{color:"#00fff0"}},y:{ticks:{color:"#00fff0"}}}}
})
var map=L.map("map").setView([4.2105,101.9758],6)
L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png").addTo(map)
var heat=L.heatLayer({{heat|safe}}, {radius:30, blur:20, gradient:{0.4:'cyan',0.65:'lime',1:'red'}}).addTo(map)
</script>
</body>
</html>
"""

# ---------------- ROUTES ----------------
@app.route("/")
def dashboard():
    labels, values = trend()
    return render_template_string(TEMPLATE,
                                  index=securenation(),
                                  labels=labels,
                                  values=values,
                                  heat=heatmap(),
                                  top=top10())

@app.route("/api/threats")
def api():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    rows = c.execute("SELECT * FROM threats").fetchall()
    conn.close()
    return jsonify(rows)

@app.route("/export/csv")
def csv_report(): return send_file(export_csv(), download_name="sundayring_threats.csv")

@app.route("/export/json")
def json_report(): return send_file(export_json(), download_name="sundayring_threats.json")

# ---------------- STARTUP ----------------
init_db()
threading.Thread(target=collector,daemon=True).start()

if __name__=="__main__":
    app.run(host="0.0.0.0", port=PORT)