import os
import sqlite3
import requests
import json
import csv
import io
import random
import threading
from datetime import datetime

from flask import Flask, render_template_string, send_file
import plotly.graph_objs as go
import plotly

from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table
from reportlab.lib.pagesizes import landscape, A4
from reportlab.lib.styles import getSampleStyleSheet

app = Flask(__name__)

DB = "/tmp/threats.db"
RULE_FILE = "/tmp/redshark.rules"

# ---------------- DATABASE ----------------

def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = db()
    conn.execute("""
    CREATE TABLE IF NOT EXISTS threats(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        indicator TEXT UNIQUE,
        type TEXT,
        mitre TEXT,
        sector TEXT,
        severity INTEGER,
        lat REAL,
        lon REAL,
        created TEXT
    )
    """)
    conn.commit()

init_db()

# ---------------- STATES ----------------

states = {
    "Johor":[1.49,103.74],"Kedah":[6.11,100.36],"Kelantan":[6.12,102.23],
    "Melaka":[2.18,102.25],"Negeri Sembilan":[2.72,101.94],"Pahang":[3.81,103.32],
    "Perak":[4.59,101.09],"Perlis":[6.44,100.20],"Pulau Pinang":[5.41,100.33],
    "Sabah":[5.98,116.07],"Sarawak":[1.55,110.35],"Selangor":[3.07,101.51],
    "Terengganu":[5.33,103.14],"Kuala Lumpur":[3.13,101.68]
}

sectors = ["Government","Banking","Telecommunications","Energy",
           "Healthcare","Education","Manufacturing",
           "Transportation","Retail","Technology"]

mitre = ["Reconnaissance","Initial Access","Execution",
         "Persistence","Privilege Escalation","Defense Evasion",
         "Credential Access","Discovery","Lateral Movement",
         "Collection","Command and Control","Exfiltration","Impact"]

def rand_loc():
    return random.choice(list(states.values()))
def rand_sector():
    return random.choice(sectors)
def rand_mitre():
    return random.choice(mitre)

# ---------------- INSERT THREAT ----------------

def insert_threat(indicator,typ,severity):
    conn = db()
    # prevent duplicates
    exists = conn.execute("SELECT 1 FROM threats WHERE indicator=?", (indicator,)).fetchone()
    if exists: return

    lat, lon = rand_loc()
    conn.execute("""
    INSERT INTO threats(indicator,type,mitre,sector,severity,lat,lon,created)
    VALUES(?,?,?,?,?,?,?,?)
    """, (
        indicator, typ, rand_mitre(), rand_sector(), severity, lat, lon, datetime.utcnow()
    ))
    conn.commit()

# ---------------- THREAT FEEDS ----------------

def fetch_threatfox():
    try:
        url="https://threatfox.abuse.ch/export/json/recent/"
        r = requests.get(url, timeout=10).json()
        for i in r.get("data", [])[:40]:
            insert_threat(i.get("ioc","unknown"), i.get("ioc_type","unknown"), 85)
    except: pass

def fetch_feodo():
    try:
        url="https://feodotracker.abuse.ch/downloads/ipblocklist.json"
        data = requests.get(url, timeout=10).json()
        for i in data[:40]:
            insert_threat(i.get("ip_address","0.0.0.0"), "ip", 90)
    except: pass

def fetch_hashes():
    try:
        url="https://mb-api.abuse.ch/api/v1/"
        r = requests.post(url, data={"query":"get_recent"}, timeout=10).json()
        for item in r.get("data", [])[:40]:
            insert_threat(item.get("sha256_hash",""), "hash", 75)
    except: pass

def fetch_feeds():
    fetch_threatfox()
    fetch_feodo()
    fetch_hashes()

# ---------------- SCHEDULER ----------------

def scheduler():
    fetch_feeds()
    threading.Timer(900, scheduler).start()  # every 15 min

fetch_feeds()
scheduler()

# ---------------- SECURENATION INDEX ----------------

def securenation():
    rows = db().execute("SELECT severity FROM threats ORDER BY id DESC LIMIT 100").fetchall()
    if not rows: return 0
    score = sum([r["severity"] for r in rows]) / len(rows)
    return round(score,1)

# ---------------- MALAYSIA HEATMAP ----------------

def malaysia_map():
    rows = db().execute("SELECT lat,lon,severity FROM threats").fetchall()
    lat, lon, sev = [r["lat"] for r in rows], [r["lon"] for r in rows], [r["severity"] for r in rows]

    colors = []
    for s in sev:
        if s>=85: colors.append("red")
        elif s>=70: colors.append("orange")
        else: colors.append("yellow")

    fig = go.Figure(go.Scattermapbox(
        lat=lat, lon=lon, mode="markers",
        marker=dict(size=12,color=colors,opacity=0.8),
        text=[f"Severity: {s}" for s in sev]
    ))
    fig.update_layout(
        mapbox_style="carto-darkmatter",
        mapbox_center={"lat":4.5,"lon":102},
        mapbox_zoom=4,
        paper_bgcolor="#0b1b2a",
        margin=dict(l=0,r=0,t=0,b=0)
    )
    return json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

# ---------------- TIMELINE ----------------

def timeline_chart():
    rows=db().execute("""
    SELECT substr(created,1,10) d, COUNT(*) c
    FROM threats GROUP BY d ORDER BY d
    """).fetchall()
    x=[r["d"] for r in rows]
    y=[r["c"] for r in rows]
    fig=go.Figure()
    fig.add_trace(go.Scatter(x=x,y=y,mode="lines+markers",
                             line=dict(color="#00eaff",width=3)))
    fig.update_layout(plot_bgcolor="#1a1a1a", paper_bgcolor="#0b1b2a",
                      font_color="white", title="Threat Timeline")
    return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)

# ---------------- SECTOR CHART ----------------

def sector_chart():
    rows=db().execute("""
    SELECT sector, COUNT(*) c FROM threats GROUP BY sector ORDER BY c DESC
    """).fetchall()
    sectors_=[r["sector"] for r in rows]
    counts_=[r["c"] for r in rows]
    fig=go.Figure(go.Bar(
        x=counts_, y=sectors_, orientation="h",
        marker=dict(color="#3b4a5c", line=dict(color="#6f8fbf",width=2))
    ))
    fig.update_layout(plot_bgcolor="#1a1a1a", paper_bgcolor="#0b1b2a",
                      font_color="white", title="Sector Targeting")
    return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)

# ---------------- PDF ----------------

def generate_pdf():
    rows=db().execute("""
    SELECT indicator,type,sector,severity,created FROM threats
    ORDER BY id DESC LIMIT 50
    """).fetchall()
    buffer=io.BytesIO()
    doc=SimpleDocTemplate(buffer,pagesize=landscape(A4))
    styles=getSampleStyleSheet()
    elements=[]
    elements.append(Paragraph("RedShark CTI Report", styles["Title"]))
    elements.append(Spacer(1,10))
    ts=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    elements.append(Paragraph(f"Report Generated: {ts}", styles["Normal"]))
    elements.append(Spacer(1,20))
    data=[["Indicator","Type","Sector","Severity","Timestamp"]]
    for r in rows:
        data.append([r["indicator"],r["type"],r["sector"],r["severity"],r["created"]])
    elements.append(Table(data))
    doc.build(elements)
    buffer.seek(0)
    return buffer

# ---------------- DASHBOARD HTML ----------------

HTML="""
<html>
<head>
<title>RedShark CTI Dashboard v3.2</title>
<script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
<style>
body{background:#0b1b2a;color:white;font-family:Arial;}
.card{background:#13263b;padding:20px;margin:15px;border-radius:8px;}
.download a{color:#dc143c;font-weight:bold;text-decoration:none;}
.download a:hover{color:#ff4d6d;}
</style>
</head>
<body>
<h2>Sunday-Ring Threat Intelligence Dashboard v3.2</h2>
<div class="card">SecureNation Index: <b style="color:orange">{{index}}</b></div>
<div class="card"><h3>Malaysia Threat Heatmap</h3><div id="map"></div></div>
<div class="card"><h3>Threat Timeline</h3><div id="timeline"></div></div>
<div class="card"><h3>Sector Targeting</h3><div id="sector"></div></div>
<div class="card download">
<a href="/csv">Download CSV</a> |
<a href="/json">Download JSON</a> |
<a href="/pdf">Download PDF Report</a> |
<a href="/rules">Download IPS Signatures</a>
</div>
<script>
var map={{map|safe}}
var timeline={{timeline|safe}}
var sector={{sector|safe}}
Plotly.newPlot("map",map.data,map.layout)
Plotly.newPlot("timeline",timeline.data,timeline.layout)
Plotly.newPlot("sector",sector.data,sector.layout)
</script>
</body>
</html>
"""

# ---------------- ROUTES ----------------

@app.route("/")
def dashboard():
    rows=db().execute("SELECT * FROM threats ORDER BY id DESC LIMIT 50").fetchall()
    if not rows: fetch_feeds(); rows=db().execute("SELECT * FROM threats ORDER BY id DESC LIMIT 50").fetchall()
    return render_template_string(
        HTML,
        rows=rows,
        index=securenation(),
        map=malaysia_map(),
        timeline=timeline_chart(),
        sector=sector_chart()
    )

@app.route("/pdf")
def pdf():
    pdf=generate_pdf()
    return send_file(pdf,download_name="redshark-cti-report.pdf",as_attachment=True)

@app.route("/csv")
def csv_export():
    rows=db().execute("SELECT * FROM threats").fetchall()
    out=io.StringIO()
    writer=csv.writer(out)
    if rows: writer.writerow(rows[0].keys())
    for r in rows: writer.writerow(list(r))
    mem=io.BytesIO()
    mem.write(out.getvalue().encode()); mem.seek(0)
    return send_file(mem,download_name="redshark-cti.csv",as_attachment=True)

@app.route("/json")
def json_export():
    rows=db().execute("SELECT * FROM threats").fetchall()
    data=[dict(r) for r in rows]
    mem=io.BytesIO()
    mem.write(json.dumps(data,indent=2).encode()); mem.seek(0)
    return send_file(mem,download_name="redshark-cti.json",as_attachment=True)

@app.route("/rules")
def rules():
    if not os.path.exists(RULE_FILE):
        with open(RULE_FILE,"w") as f: f.write("# RedShark IPS Signatures\n")
    return send_file(RULE_FILE,download_name="redshark-ips-signatures.rules",as_attachment=True,mimetype="text/plain")

# ---------------- RUN ----------------

if __name__=="__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT",5000)))