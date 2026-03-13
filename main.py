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
from reportlab.platypus import SimpleDocTemplate, Table
from reportlab.lib.pagesizes import landscape, A4

app = Flask(__name__)

DB="/tmp/threats.db"
RULE_FILE="/tmp/redshark.rules"

# ---------------- DATABASE ----------------

def db():
    conn=sqlite3.connect(DB)
    conn.row_factory=sqlite3.Row
    return conn

def init_db():
    conn=db()
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

# ---------------- MALAYSIA LOCATIONS ----------------

states={
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

sectors=[
"Government","Banking","Telecommunications","Energy",
"Healthcare","Education","Manufacturing",
"Transportation","Retail","Technology"
]

mitre=[
"Reconnaissance","Initial Access","Execution",
"Persistence","Privilege Escalation","Defense Evasion",
"Credential Access","Discovery","Lateral Movement",
"Collection","Command and Control","Exfiltration","Impact"
]

def rand_loc():
    return random.choice(list(states.values()))

# ---------------- INSERT THREAT ----------------

def insert_threat(indicator,typ,severity):

    conn=db()

    if conn.execute(
        "SELECT 1 FROM threats WHERE indicator=?",
        (indicator,)
    ).fetchone():
        return

    lat,lon=rand_loc()
    m=random.choice(mitre)
    s=random.choice(sectors)

    created=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    conn.execute("""
    INSERT INTO threats(indicator,type,mitre,sector,severity,lat,lon,created)
    VALUES(?,?,?,?,?,?,?,?)
    """,(indicator,typ,m,s,severity,lat,lon,created))

    conn.commit()

    sid=1000000+random.randint(1,9999)

    if typ=="ip":
        rule=f'alert ip any any -> any any (msg:"RedShark IP {indicator} | MITRE:{m}"; sid:{sid}; rev:1;)'
    elif typ=="url":
        rule=f'alert http any any -> any any (msg:"RedShark URL {indicator}"; content:"{indicator}"; http_uri; sid:{sid}; rev:1;)'
    elif typ=="domain":
        rule=f'alert http any any -> any any (msg:"RedShark DOMAIN {indicator}"; content:"{indicator}"; http_host; sid:{sid}; rev:1;)'
    else:
        rule=f'# hash {indicator}'

    with open(RULE_FILE,"a") as f:
        f.write(rule+"\n")

# ---------------- THREAT FEEDS ----------------

def fetch_threatfox():
    try:
        url="https://threatfox.abuse.ch/export/json/recent/"
        r=requests.get(url,timeout=10).json()

        for i in r.get("data",[])[:40]:
            insert_threat(i.get("ioc"),i.get("ioc_type"),85)
    except:
        pass


def fetch_feodo():
    try:
        url="https://feodotracker.abuse.ch/downloads/ipblocklist.json"
        r=requests.get(url,timeout=10).json()

        for i in r[:40]:
            insert_threat(i.get("ip_address"),"ip",90)
    except:
        pass


def fetch_urlhaus():
    try:
        url="https://urlhaus.abuse.ch/downloads/csv_recent/"
        data=requests.get(url).text.splitlines()
        reader=csv.reader(data)

        for r in list(reader)[10:50]:
            insert_threat(r[2],"url",70)
    except:
        pass


def fetch_hash():
    try:
        url="https://mb-api.abuse.ch/api/v1/"
        r=requests.post(url,data={"query":"get_recent"}).json()

        for i in r.get("data",[])[:40]:
            insert_threat(i.get("sha256_hash"),"hash",75)
    except:
        pass

def fetch_all():
    fetch_threatfox()
    fetch_feodo()
    fetch_urlhaus()
    fetch_hash()

# scheduler
def scheduler():
    fetch_all()
    threading.Timer(900,scheduler).start()

fetch_all()
scheduler()

# ---------------- SECURENATION INDEX ----------------

def securenation():
    rows=db().execute(
        "SELECT severity FROM threats ORDER BY id DESC LIMIT 100"
    ).fetchall()

    if not rows:
        return 0

    return round(sum([r["severity"] for r in rows])/len(rows),1)

# ---------------- CHARTS ----------------

def timeline_chart():

    rows=db().execute("""
    SELECT substr(created,1,10) d,COUNT(*) c
    FROM threats
    GROUP BY d ORDER BY d
    """).fetchall()

    x=[r["d"] for r in rows]
    y=[r["c"] for r in rows]

    fig=go.Figure()

    fig.add_trace(go.Scatter(
        x=x,
        y=y,
        mode="lines+markers",
        line=dict(color="#00E5FF",width=4,shape="spline"),
        marker=dict(size=8),
        fill="tozeroy",
        fillcolor="rgba(0,229,255,0.1)"
    ))

    fig.update_layout(
        plot_bgcolor="#0b1b2a",
        paper_bgcolor="#0b1b2a",
        font=dict(color="#A3B8CC"),
        xaxis=dict(showgrid=False),
        yaxis=dict(showgrid=False)
    )

    return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)


def indicator_chart():

    rows=db().execute(
        "SELECT type,COUNT(*) c FROM threats GROUP BY type"
    ).fetchall()

    labels=[r["type"] for r in rows]
    values=[r["c"] for r in rows]

    fig=go.Figure(data=[go.Pie(
        labels=labels,
        values=values,
        hole=0.35,
        pull=[0.05]*len(labels)
    )])

    fig.update_layout(
        paper_bgcolor="#0b1b2a",
        font_color="#A3B8CC"
    )

    return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)

# ---------------- MAP ----------------

def malaysia_map():

    rows=db().execute(
        "SELECT lat,lon,severity FROM threats"
    ).fetchall()

    lat=[r["lat"] for r in rows]
    lon=[r["lon"] for r in rows]

    sev=[r["severity"] for r in rows]

    colors=["red" if s>85 else "orange" for s in sev]

    fig=go.Figure(go.Scattermapbox(
        lat=lat,
        lon=lon,
        mode="markers",
        marker=dict(size=12,color=colors)
    ))

    fig.update_layout(
        mapbox_style="carto-darkmatter",
        mapbox_zoom=4,
        mapbox_center={"lat":4.5,"lon":102},
        paper_bgcolor="#0b1b2a",
        margin=dict(l=0,r=0,t=0,b=0)
    )

    return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)

# ---------------- HTML ----------------

HTML="""
<html>
<head>

<title>RedShark CTI Dashboard v4.0</title>

<script src="https://cdn.plot.ly/plotly-latest.min.js"></script>

<style>

body{
background:#0b1b2a;
color:#A3B8CC;
font-family:Arial
}

.card{
background:#13263b;
padding:20px;
margin:15px;
border-radius:8px
}

.download-btn{
background:#1f2f45;
color:#A3B8CC;
font-weight:bold;
border:none;
padding:10px 20px;
margin:5px;
border-radius:6px
}

.ticker{
overflow:hidden;
white-space:nowrap
}

.ticker span{
display:inline-block;
padding-left:100%;
animation:ticker 25s linear infinite
}

@keyframes ticker{
0%{transform:translateX(0)}
100%{transform:translateX(-100%)}
}

</style>
</head>

<body>

<h2>RedShark Cyber Threat Intelligence Dashboard v4.0</h2>

<div class="card ticker">
<span>
{% for r in rows %}
⚠ {{r.indicator}} detected | 
{% endfor %}
</span>
</div>

<div class="card">
<div id="timeline"></div>
</div>

<div class="card">
<div id="indicator"></div>
</div>

<div class="card">
<div id="map" style="height:400px"></div>
</div>

<div class="card">
<h3>Download RedShark CTI Report</h3>
<button class="download-btn" onclick="location.href='/csv'">CSV</button>
<button class="download-btn" onclick="location.href='/json'">JSON</button>
<button class="download-btn" onclick="location.href='/pdf'">PDF</button>
<button class="download-btn" onclick="location.href='/download_ips'">IPS Rules</button>
</div>

<script>

var timeline={{timeline|safe}}
var indicator={{indicator|safe}}
var map={{map|safe}}

Plotly.newPlot("timeline",timeline.data,timeline.layout)
Plotly.newPlot("indicator",indicator.data,indicator.layout)
Plotly.newPlot("map",map.data,map.layout)

</script>

</body>
</html>
"""

# ---------------- DASHBOARD ----------------

@app.route("/")
def dashboard():

    rows=db().execute(
        "SELECT * FROM threats ORDER BY id DESC LIMIT 20"
    ).fetchall()

    return render_template_string(
        HTML,
        rows=rows,
        timeline=timeline_chart(),
        indicator=indicator_chart(),
        map=malaysia_map()
    )

# ---------------- EXPORT ----------------

@app.route("/csv")
def csv_export():

    rows=db().execute("SELECT * FROM threats").fetchall()

    out=io.StringIO()
    writer=csv.writer(out)

    writer.writerow(rows[0].keys())

    for r in rows:
        writer.writerow(list(r))

    mem=io.BytesIO()
    mem.write(out.getvalue().encode())
    mem.seek(0)

    return send_file(mem,download_name="threats.csv",as_attachment=True)


@app.route("/json")
def json_export():

    rows=db().execute("SELECT * FROM threats").fetchall()

    data=[dict(r) for r in rows]

    mem=io.BytesIO()
    mem.write(json.dumps(data,indent=2).encode())
    mem.seek(0)

    return send_file(mem,download_name="threats.json",as_attachment=True)


@app.route("/pdf")
def pdf_export():

    rows=db().execute(
    "SELECT indicator,type,sector,severity,created FROM threats"
    ).fetchall()

    buffer=io.BytesIO()

    data=[["Indicator","Type","Sector","Severity","Time"]]

    for r in rows:
        data.append([
            r["indicator"],
            r["type"],
            r["sector"],
            r["severity"],
            r["created"]
        ])

    pdf=SimpleDocTemplate(buffer,pagesize=landscape(A4))

    pdf.build([Table(data)])

    buffer.seek(0)

    return send_file(buffer,download_name="cti_report.pdf",as_attachment=True)


@app.route("/download_ips")
def download_ips():

    if not os.path.exists(RULE_FILE):
        open(RULE_FILE,"w").close()

    return send_file(
        RULE_FILE,
        download_name="redshark_ips.rules",
        as_attachment=True
    )

# ---------------- RUN ----------------

if __name__=="__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT",5000))
    )