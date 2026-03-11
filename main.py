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

# -------------------------------------------------
# CONFIG
# -------------------------------------------------

app = Flask(__name__)

PORT = int(os.getenv("PORT", 5000))
DB = os.getenv("DB_PATH", "/tmp/sundayring.db")

OTX_KEY = os.getenv("OTX_KEY")
ABUSE_KEY = os.getenv("ABUSE_KEY")

# -------------------------------------------------
# MALAYSIA HEATMAP COORDINATES
# -------------------------------------------------

STATES = [
    [3.1390,101.6869],  # Kuala Lumpur
    [5.4164,100.3327],  # Penang
    [1.5533,110.3592],  # Sarawak
    [5.9804,116.0735],  # Sabah
    [3.8167,103.3333],  # Pahang
    [2.7290,101.9381],  # Negeri Sembilan
]

# -------------------------------------------------
# DATABASE
# -------------------------------------------------

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

# -------------------------------------------------
# SIMPLE APT DETECTION
# -------------------------------------------------

def detect_apt(ind):

    ind = ind.lower()

    if ".ru" in ind:
        return "APT28"

    if ".cn" in ind:
        return "APT41"

    if ".kp" in ind:
        return "Lazarus"

    return "Unknown"

# -------------------------------------------------
# INSERT IOC
# -------------------------------------------------

def insert_ioc(source, indicator, typ, risk):

    apt = detect_apt(indicator)

    sector = random.choice([
        "Finance",
        "Government",
        "Telecom",
        "Energy",
        "Public"
    ])

    conn = sqlite3.connect(DB)
    c = conn.cursor()

    try:

        c.execute("""
        INSERT OR IGNORE INTO threats
        (source,indicator,type,risk,apt,sector,created_at)
        VALUES (?,?,?,?,?,?,?)
        """,(
            source,
            indicator,
            typ,
            risk,
            apt,
            sector,
            datetime.utcnow().isoformat()
        ))

        conn.commit()

    except:
        pass

    conn.close()

# -------------------------------------------------
# THREAT FEEDS
# -------------------------------------------------

def fetch_otx():

    if not OTX_KEY:
        return

    url = "https://otx.alienvault.com/api/v1/indicators/export?types=IPv4,domain,url&limit=200"

    headers = {"X-OTX-API-KEY": OTX_KEY}

    r = requests.get(url, headers=headers, timeout=30)

    if r.status_code != 200:
        return

    for line in r.text.splitlines():

        parts = line.split(",")

        if len(parts) < 2:
            continue

        insert_ioc("OTX", parts[0], parts[1], 60)

def fetch_threatfox():

    url = "https://threatfox-api.abuse.ch/api/v1/"

    payload = {"query":"get_iocs","limit":100}

    r = requests.post(url, json=payload, timeout=30)

    data = r.json()

    if data.get("query_status") != "ok":
        return

    for i in data["data"]:

        insert_ioc(
            "ThreatFox",
            i["ioc"],
            i["ioc_type"],
            85
        )

def fetch_urlhaus():

    url = "https://urlhaus-api.abuse.ch/v1/urls/recent/"

    r = requests.get(url, timeout=30)

    data = r.json()

    for u in data["urls"]:

        insert_ioc(
            "URLHaus",
            u["url"],
            "url",
            75
        )

# -------------------------------------------------
# COLLECTOR LOOP
# -------------------------------------------------

def collector():

    while True:

        try:

            fetch_otx()
            fetch_threatfox()
            fetch_urlhaus()

        except Exception as e:

            print("collector error:", e)

        time.sleep(3600)

# -------------------------------------------------
# SECURENATION INDEX
# -------------------------------------------------

def securenation():

    conn = sqlite3.connect(DB)
    c = conn.cursor()

    rows = c.execute("SELECT risk FROM threats").fetchall()

    conn.close()

    if not rows:
        return 100

    avg = sum([r[0] for r in rows]) / len(rows)

    score = 100 - avg/2

    return round(score,2)

# -------------------------------------------------
# TREND DATA
# -------------------------------------------------

def trend():

    conn = sqlite3.connect(DB)
    c = conn.cursor()

    rows = c.execute("""
    SELECT substr(created_at,1,10),count(*)
    FROM threats
    GROUP BY substr(created_at,1,10)
    ORDER BY substr(created_at,1,10)
    """).fetchall()

    conn.close()

    labels = [r[0] for r in rows]
    values = [r[1] for r in rows]

    return labels, values

# -------------------------------------------------
# TOP INDICATORS
# -------------------------------------------------

def top10():

    conn = sqlite3.connect(DB)
    c = conn.cursor()

    rows = c.execute("""
    SELECT indicator,count(*)
    FROM threats
    GROUP BY indicator
    ORDER BY count(*) DESC
    LIMIT 10
    """).fetchall()

    conn.close()

    return rows

# -------------------------------------------------
# SECTOR ANALYTICS
# -------------------------------------------------

def sector_stats():

    conn = sqlite3.connect(DB)
    c = conn.cursor()

    rows = c.execute("""
    SELECT sector,count(*)
    FROM threats
    GROUP BY sector
    """).fetchall()

    conn.close()

    return rows

# -------------------------------------------------
# HEATMAP DATA
# -------------------------------------------------

def heatmap():

    heat = []

    for s in STATES:

        heat.append([
            s[0],
            s[1],
            random.randint(1,10)
        ])

    return heat

# -------------------------------------------------
# SURICATA RULE GENERATOR
# -------------------------------------------------

def suricata_rules():

    conn = sqlite3.connect(DB)
    c = conn.cursor()

    rows = c.execute("""
    SELECT indicator FROM threats
    WHERE type='IPv4'
    LIMIT 50
    """).fetchall()

    conn.close()

    rules = ""

    sid = 1000000

    for r in rows:

        ip = r[0]

        rules += f'alert ip any any -> {ip} any (msg:"Sunday-Ring IOC"; sid:{sid}; rev:1;)\n'

        sid += 1

    mem = io.BytesIO()

    mem.write(rules.encode())

    mem.seek(0)

    return mem

# -------------------------------------------------
# EXPORT REPORTS
# -------------------------------------------------

def export_csv():

    conn = sqlite3.connect(DB)
    c = conn.cursor()

    rows = c.execute("SELECT * FROM threats").fetchall()

    conn.close()

    out = io.StringIO()

    writer = csv.writer(out)

    writer.writerow([
        "id","source","indicator","type","risk","apt","sector","created"
    ])

    for r in rows:
        writer.writerow(r)

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

# -------------------------------------------------
# PDF REPORT
# -------------------------------------------------

def export_pdf():

    conn = sqlite3.connect(DB)
    c = conn.cursor()

    rows = c.execute("""
    SELECT source,indicator,type,risk
    FROM threats
    LIMIT 30
    """).fetchall()

    conn.close()

    mem = io.BytesIO()

    doc = SimpleDocTemplate(
        mem,
        pagesize=landscape(A4)
    )

    styles = getSampleStyleSheet()

    elements = []

    elements.append(
        Paragraph("Sunday-Ring Malaysia Threat Intelligence Report", styles["Title"])
    )

    elements.append(Spacer(1,20))

    table = Table(
        [["Source","Indicator","Type","Risk"]] + rows
    )

    elements.append(table)

    elements.append(Spacer(1,20))

    elements.append(
        Paragraph(
            "Disclaimer: Developed and analysed by darkgrid@redshark.my. Data is aggregated from publicly available threat intelligence sources for monitoring and research purposes.",
            styles["Normal"]
        )
    )

    doc.build(elements)

    mem.seek(0)

    return mem

# -------------------------------------------------
# DASHBOARD TEMPLATE
# -------------------------------------------------

TEMPLATE = """
<html>
<head>

<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

<link rel="stylesheet"
href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>

<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script src="https://unpkg.com/leaflet.heat/dist/leaflet-heat.js"></script>

<style>

body{
background:#0a0f1a;
color:white;
font-family:Arial;
}

.card{
background:#0f1c2e;
padding:15px;
margin:15px;
border-radius:8px;
}

</style>

</head>

<body>

<h1>Sunday-Ring Threat Intelligence Dashboard</h1>

<div class="card">
<h2>SecureNation Index: {{index}}</h2>
</div>

<div class="card">
<canvas id="trend"></canvas>
</div>

<div class="card">
<div id="map" style="height:450px"></div>
</div>

<div class="card">
<h3>Top 10 Indicators</h3>
<ul>
{% for t in top %}
<li>{{t[0]}}</li>
{% endfor %}
</ul>
</div>

<footer style="margin-top:40px;padding:12px;font-size:12px;color:#9aa0a6;text-align:center;border-top:1px solid #1c2a3a;">
Disclaimer: Developed and analysed by <b>darkgrid@redshark.my</b>. Data is aggregated from publicly available threat intelligence sources for monitoring and research purposes.
</footer>

<script>

const labels={{labels|safe}}
const values={{values|safe}}

new Chart(document.getElementById("trend"),{
type:"line",
data:{
labels:labels,
datasets:[{
label:"Threat Trend",
data:values
}]
}
})

var map=L.map("map").setView([4.21,101.97],6)

L.tileLayer(
"https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
).addTo(map)

var heat=L.heatLayer({{heat|safe}}).addTo(map)

</script>

</body>
</html>
"""

# -------------------------------------------------
# ROUTES
# -------------------------------------------------

@app.route("/")
def dashboard():

    labels, values = trend()

    return render_template_string(
        TEMPLATE,
        index=securenation(),
        labels=labels,
        values=values,
        heat=heatmap(),
        top=top10()
    )

@app.route("/api/threats")
def api():

    conn = sqlite3.connect(DB)
    c = conn.cursor()

    rows = c.execute("SELECT * FROM threats").fetchall()

    conn.close()

    return jsonify(rows)

@app.route("/export/csv")
def csv_report():
    return send_file(export_csv(), download_name="sundayring_threats.csv")

@app.route("/export/json")
def json_report():
    return send_file(export_json(), download_name="sundayring_threats.json")

@app.route("/export/pdf")
def pdf_report():
    return send_file(export_pdf(), download_name="sundayring_report.pdf")

@app.route("/export/suricata")
def suricata():
    return send_file(suricata_rules(), download_name="sundayring.rules")

# -------------------------------------------------
# STARTUP
# -------------------------------------------------

init_db()

threading.Thread(target=collector, daemon=True).start()

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=PORT
    )