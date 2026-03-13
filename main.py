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

DB = "/tmp/redshark_cti.db"
RULE_FILE = "/tmp/redshark_ips.rules"

# ------------------------------------------------
# DATABASE
# ------------------------------------------------

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

# ------------------------------------------------
# MALAYSIA LOCATIONS
# ------------------------------------------------

states = {
"Johor":[1.49,103.74],
"Kedah":[6.11,100.36],
"Kelantan":[6.12,102.23],
"Melaka":[2.18,102.25],
"Negeri Sembilan":[2.72,101.94],
"Pahang":[3.81,103.32],
"Perak":[4.59,101.09],
"Pulau Pinang":[5.41,100.33],
"Sabah":[5.98,116.07],
"Sarawak":[1.55,110.35],
"Selangor":[3.07,101.51],
"Terengganu":[5.33,103.14],
"Kuala Lumpur":[3.13,101.68]
}

sectors = [
"Government","Banking","Telecom",
"Energy","Healthcare","Education"
]

mitre = [
"Reconnaissance","Initial Access","Execution",
"Persistence","Privilege Escalation",
"Defense Evasion","Credential Access",
"Discovery","Lateral Movement",
"Command and Control","Exfiltration","Impact"
]

def random_location():
    return random.choice(list(states.values()))

# ------------------------------------------------
# INSERT THREAT
# ------------------------------------------------

def insert_threat(indicator, typ, severity):

    conn = db()

    if conn.execute(
        "SELECT 1 FROM threats WHERE indicator=?",
        (indicator,)
    ).fetchone():
        return

    lat, lon = random_location()

    mit = random.choice(mitre)
    sec = random.choice(sectors)

    created = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    conn.execute("""
    INSERT INTO threats(indicator,type,mitre,sector,severity,lat,lon,created)
    VALUES(?,?,?,?,?,?,?,?)
    """,(indicator,typ,mit,sec,severity,lat,lon,created))

    conn.commit()

    generate_rule(indicator, typ, mit)

# ------------------------------------------------
# IPS RULE GENERATION
# ------------------------------------------------

def generate_rule(indicator, typ, mitre):

    sid = 1000000 + random.randint(1,9999)

    if typ == "ip":
        rule = f'alert ip any any -> any any (msg:"RedShark IP {indicator} MITRE:{mitre}"; sid:{sid}; rev:1;)'

    elif typ == "domain":
        rule = f'alert dns any any -> any any (msg:"RedShark DOMAIN {indicator}"; content:"{indicator}"; sid:{sid}; rev:1;)'

    elif typ == "url":
        rule = f'alert http any any -> any any (msg:"RedShark URL {indicator}"; content:"{indicator}"; http_uri; sid:{sid}; rev:1;)'

    else:
        rule = f'# HASH {indicator}'

    with open(RULE_FILE,"a") as f:
        f.write(rule+"\n")

# ------------------------------------------------
# THREAT FEEDS
# ------------------------------------------------

def fetch_threatfox():
    try:
        url = "https://threatfox.abuse.ch/export/json/recent/"
        data = requests.get(url,timeout=10).json()

        for i in data.get("data",[])[:20]:
            insert_threat(
                i.get("ioc"),
                i.get("ioc_type"),
                85
            )
    except:
        pass

def fetch_urlhaus():
    try:
        url = "https://urlhaus.abuse.ch/downloads/csv_recent/"
        data = requests.get(url).text.splitlines()
        reader = csv.reader(data)

        for r in list(reader)[10:30]:
            insert_threat(r[2],"url",70)
    except:
        pass

def fetch_feodo():
    try:
        url="https://feodotracker.abuse.ch/downloads/ipblocklist.json"
        data=requests.get(url).json()

        for i in data[:20]:
            insert_threat(i.get("ip_address"),"ip",90)
    except:
        pass

def fetch_hash():
    try:
        url="https://mb-api.abuse.ch/api/v1/"
        r=requests.post(url,data={"query":"get_recent"}).json()

        for i in r.get("data",[])[:20]:
            insert_threat(i.get("sha256_hash"),"hash",75)
    except:
        pass

def fetch_all():
    fetch_threatfox()
    fetch_urlhaus()
    fetch_feodo()
    fetch_hash()

fetch_all()

# ------------------------------------------------
# SECURENATION INDEX
# ------------------------------------------------

def securenation():

    rows=db().execute(
    "SELECT severity FROM threats ORDER BY id DESC LIMIT 100"
    ).fetchall()

    if not rows:
        return 0

    score=sum([r["severity"] for r in rows])/len(rows)

    return round(score,1)

# ------------------------------------------------
# CHARTS
# ------------------------------------------------

def timeline_chart():

    rows=db().execute("""
    SELECT substr(created,1,10) d,COUNT(*) c
    FROM threats
    GROUP BY d
    """).fetchall()

    x=[r["d"] for r in rows]
    y=[r["c"] for r in rows]

    fig=go.Figure()

    fig.add_trace(go.Scatter(
        x=x,
        y=y,
        mode="lines+markers",
        line=dict(color="#00E5FF",width=4,shape="spline"),
        fill="tozeroy",
        fillcolor="rgba(0,229,255,0.1)"
    ))

    fig.update_layout(
        paper_bgcolor="#0b1b2a",
        plot_bgcolor="#0b1b2a",
        font_color="#A3B8CC",
        xaxis=dict(showgrid=False),
        yaxis=dict(showgrid=False)
    )

    return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)

def indicator_chart():

    rows=db().execute("""
    SELECT type,COUNT(*) c
    FROM threats
    GROUP BY type
    """).fetchall()

    labels=[r["type"] for r in rows]
    values=[r["c"] for r in rows]

    fig=go.Figure(go.Pie(
        labels=labels,
        values=values,
        hole=0.4
    ))

    fig.update_layout(
        paper_bgcolor="#0b1b2a",
        font_color="#A3B8CC"
    )

    return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)

# ------------------------------------------------
# MALAYSIA ATTACK MAP
# ------------------------------------------------

def malaysia_map():

    rows=db().execute(
    "SELECT lat,lon,severity FROM threats"
    ).fetchall()

    lat=[r["lat"] for r in rows]
    lon=[r["lon"] for r in rows]

    fig=go.Figure(go.Scattergeo(
        lat=lat,
        lon=lon,
        mode="markers",
        marker=dict(size=10,color="crimson")
    ))

    fig.update_layout(
        geo=dict(
            scope="asia",
            center=dict(lat=4.5,lon=102)
        ),
        paper_bgcolor="#0b1b2a"
    )

    return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)

# ------------------------------------------------
# HTML TEMPLATE
# ------------------------------------------------

HTML = """
<html>
<head>

<title>RedShark CTI Dashboard v5.1</title>

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

.download{
text-align:center
}

.btn{
background:#1f2f45;
color:#A3B8CC;
padding:10px 20px;
margin:5px;
font-weight:bold;
border:none;
border-radius:6px
}

table{
width:100%;
border-collapse:collapse
}

td,th{
padding:10px;
border-bottom:1px solid #1f3d5c
}

</style>

</head>

<body>

<h2>RedShark Cyber Threat Intelligence Dashboard v5.1</h2>

<div class="card">
SecureNation Index: <b>{{index}}</b>
</div>

<div class="card">
<div id="timeline"></div>
</div>

<div class="card">
<div id="indicator"></div>
</div>

<div class="card">
<div id="map"></div>
</div>

<div class="card">

<h3>Latest Indicators</h3>

<table>

<tr>
<th>ID</th>
<th>Indicator</th>
<th>Type</th>
<th>Sector</th>
<th>Severity</th>
<th>Time</th>
</tr>

{% for r in rows %}

<tr>
<td>{{r.id}}</td>
<td>{{r.indicator}}</td>
<td>{{r.type}}</td>
<td>{{r.sector}}</td>
<td>{{r.severity}}</td>
<td>{{r.created}}</td>
</tr>

{% endfor %}

</table>

</div>

<div class="card download">

<h3>Download RedShark CTI Report</h3>

<button class="btn" onclick="location.href='/csv'">CSV</button>
<button class="btn" onclick="location.href='/json'">JSON</button>
<button class="btn" onclick="location.href='/pdf'">PDF</button>
<button class="btn" onclick="location.href='/download_ips'">IPS Rules</button>

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

# ------------------------------------------------
# DASHBOARD
# ------------------------------------------------

@app.route("/")
def dashboard():

    rows=db().execute(
    "SELECT * FROM threats ORDER BY id DESC LIMIT 50"
    ).fetchall()

    return render_template_string(
        HTML,
        rows=rows,
        index=securenation(),
        timeline=timeline_chart(),
        indicator=indicator_chart(),
        map=malaysia_map()
    )

# ------------------------------------------------
# EXPORT
# ------------------------------------------------

@app.route("/download_ips")
def download_ips():
    return send_file(
        RULE_FILE,
        download_name="redshark_ips.rules",
        as_attachment=True
    )

# ------------------------------------------------

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT",5000))
    )