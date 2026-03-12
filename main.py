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
        indicator TEXT,
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


# ---------------- MALAYSIA STATES ----------------

states = {
"Johor":[1.49,103.74],
"Kedah":[6.11,100.36],
"Kelantan":[6.12,102.23],
"Melaka":[2.18,102.25],
"Negeri Sembilan":[2.72,101.94],
"Pahang":[3.81,103.32],
"Perak":[4.59,101.09],
"Perlis":[6.44,100.20],
"Pulau Pinang":[5.41,100.33],
"Sabah":[5.98,116.07],
"Sarawak":[1.55,110.35],
"Selangor":[3.07,101.51],
"Terengganu":[5.33,103.14],
"Kuala Lumpur":[3.13,101.68]
}

sectors = [
"Government","Banking","Telecommunications","Energy",
"Healthcare","Education","Manufacturing",
"Transportation","Retail","Technology"
]

mitre = [
"Reconnaissance","Initial Access","Execution",
"Persistence","Privilege Escalation",
"Defense Evasion","Credential Access",
"Discovery","Lateral Movement",
"Collection","Command and Control",
"Exfiltration","Impact"
]


# ---------------- HELPERS ----------------

def rand_loc():
    return random.choice(list(states.values()))

def rand_sector():
    return random.choice(sectors)

def rand_mitre():
    return random.choice(mitre)


# ---------------- INSERT THREAT ----------------

def insert_threat(indicator, typ, severity):

    lat, lon = rand_loc()

    conn = db()

    conn.execute("""
    INSERT INTO threats(indicator,type,mitre,sector,severity,lat,lon,created)
    VALUES(?,?,?,?,?,?,?,?)
    """,(
        indicator,
        typ,
        rand_mitre(),
        rand_sector(),
        severity,
        lat,
        lon,
        datetime.utcnow()
    ))

    conn.commit()


# ---------------- THREAT FEEDS ----------------

def fetch_threatfox():
    try:
        url = "https://threatfox.abuse.ch/export/json/recent/"
        r = requests.get(url,timeout=10).json()

        for i in r.get("data",[])[:20]:
            insert_threat(
                i.get("ioc","unknown"),
                i.get("ioc_type","unknown"),
                85
            )
    except:
        pass


def fetch_feodo():
    try:
        url = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
        data = requests.get(url,timeout=10).json()

        for i in data[:20]:
            insert_threat(
                i.get("ip_address","0.0.0.0"),
                "ip",
                90
            )
    except:
        pass


def fetch_feeds():
    fetch_threatfox()
    fetch_feodo()


def scheduler():
    fetch_feeds()
    threading.Timer(900, scheduler).start()


scheduler()


# ---------------- SECURENATION INDEX ----------------

def securenation():

    rows = db().execute("""
    SELECT severity FROM threats
    ORDER BY id DESC LIMIT 100
    """).fetchall()

    if not rows:
        return 0

    score = sum([r["severity"] for r in rows]) / len(rows)

    return round(score,1)


# ---------------- HEATMAP ----------------

def malaysia_map():

    rows = db().execute("SELECT lat,lon,severity FROM threats").fetchall()

    lat=[r["lat"] for r in rows]
    lon=[r["lon"] for r in rows]
    sev=[r["severity"] for r in rows]

    fig = go.Figure(go.Densitymapbox(
        lat=lat,
        lon=lon,
        z=sev,
        radius=25
    ))

    fig.update_layout(
        mapbox_style="carto-darkmatter",
        mapbox_center={"lat":4.5,"lon":102},
        mapbox_zoom=4,
        paper_bgcolor="#0b1b2a"
    )

    return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)


# ---------------- TIMELINE ----------------

def timeline_chart():

    rows = db().execute("""
    SELECT substr(created,1,10) d, COUNT(*) c
    FROM threats
    GROUP BY d
    ORDER BY d
    """).fetchall()

    x=[r["d"] for r in rows]
    y=[r["c"] for r in rows]

    fig = go.Figure()

    fig.add_trace(go.Scatter(
        x=x,
        y=y,
        mode="lines+markers",
        line=dict(color="#00eaff",width=3)
    ))

    fig.update_layout(
        plot_bgcolor="#1a1a1a",
        paper_bgcolor="#0b1b2a",
        font_color="white",
        title="Threat Activity Timeline"
    )

    return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)


# ---------------- SECTOR TARGETING ----------------

def sector_chart():

    rows=db().execute("""
    SELECT sector,COUNT(*) c
    FROM threats
    GROUP BY sector
    ORDER BY c DESC
    LIMIT 10
    """).fetchall()

    sectors=[r["sector"] for r in rows]
    counts=[r["c"] for r in rows]

    fig=go.Figure(go.Bar(
        x=counts,
        y=sectors,
        orientation="h",
        marker=dict(
            color="#2f3e55",
            line=dict(color="#6f8fbf",width=2)
        )
    ))

    fig.update_layout(
        plot_bgcolor="#1a1a1a",
        paper_bgcolor="#0b1b2a",
        font_color="white",
        title="Sector Targeting"
    )

    return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)


# ---------------- PDF REPORT ----------------

def generate_pdf():

    rows=db().execute("""
    SELECT indicator,type,sector,severity,created
    FROM threats
    ORDER BY id DESC
    LIMIT 50
    """).fetchall()

    buffer=io.BytesIO()

    doc=SimpleDocTemplate(
        buffer,
        pagesize=landscape(A4)
    )

    styles=getSampleStyleSheet()

    elements=[]

    elements.append(Paragraph("RedShark CTI Intelligence Report",styles["Title"]))
    elements.append(Spacer(1,10))

    ts=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    elements.append(Paragraph(f"Report Generated: {ts}",styles["Normal"]))
    elements.append(Spacer(1,20))

    data=[["Indicator","Type","Sector","Severity","Timestamp"]]

    for r in rows:
        data.append([
            r["indicator"],
            r["type"],
            r["sector"],
            r["severity"],
            r["created"]
        ])

    table=Table(data)

    elements.append(table)

    doc.build(elements)

    buffer.seek(0)

    return buffer


# ---------------- HTML DASHBOARD ----------------

HTML = """
<html>
<head>

<title>RedShark CTI Dashboard</title>

<script src="https://cdn.plot.ly/plotly-latest.min.js"></script>

<style>

body{
background:#0b1b2a;
color:white;
font-family:Arial;
}

.card{
background:#13263b;
padding:20px;
margin:15px;
border-radius:8px;
}

.download a{
color:#dc143c;
font-weight:bold;
text-decoration:none;
}

.download a:hover{
color:#ff4d6d;
}

table{
width:100%;
border-collapse:collapse;
}

td,th{
padding:8px;
border-bottom:1px solid #1f3d5c;
}

th{
cursor:pointer;
}

</style>

</head>

<body>

<h2>Sunday-Ring Threat Intelligence Dashboard</h2>

<div class="card">

SecureNation Index:
<b style="color:orange">{{index}}</b>

</div>

<div class="card">
<h3>Malaysia Threat Heatmap</h3>
<div id="map"></div>
</div>

<div class="card">
<h3>Threat Timeline</h3>
<div id="timeline"></div>
</div>

<div class="card">
<h3>Sector Targeting</h3>
<div id="sector"></div>
</div>

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

    rows=db().execute("""
    SELECT * FROM threats
    ORDER BY id DESC
    LIMIT 50
    """).fetchall()

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
    return send_file(
        pdf,
        download_name="redshark-cti-report.pdf",
        as_attachment=True
    )


@app.route("/csv")
def csv_export():

    rows=db().execute("SELECT * FROM threats").fetchall()

    if not rows:
        return "No data"

    out=io.StringIO()

    writer=csv.writer(out)

    writer.writerow(rows[0].keys())

    for r in rows:
        writer.writerow(list(r))

    mem=io.BytesIO()

    mem.write(out.getvalue().encode())
    mem.seek(0)

    return send_file(mem,download_name="redshark-cti.csv",as_attachment=True)


@app.route("/json")
def json_export():

    rows=db().execute("SELECT * FROM threats").fetchall()

    data=[dict(r) for r in rows]

    mem=io.BytesIO()

    mem.write(json.dumps(data,indent=2).encode())
    mem.seek(0)

    return send_file(mem,download_name="redshark-cti.json",as_attachment=True)


@app.route("/rules")
def rules():

    if not os.path.exists(RULE_FILE):

        with open(RULE_FILE,"w") as f:
            f.write("# RedShark IPS Signatures\n")

    return send_file(
        RULE_FILE,
        download_name="redshark-ips-signatures.rules",
        as_attachment=True,
        mimetype="text/plain"
    )


# ---------------- RUN ----------------

if __name__=="__main__":

    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT",5000))
    )