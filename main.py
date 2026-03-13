import os
import sqlite3
import requests
import json
import csv
import io
import random
from datetime import datetime
from flask import Flask, render_template_string, send_file

import plotly.graph_objs as go
import plotly

from reportlab.platypus import SimpleDocTemplate, Table
from reportlab.lib.pagesizes import landscape, A4

app = Flask(__name__)

DB="/tmp/redshark_cti.db"
RULE_FILE="/tmp/redshark_ips.rules"

# ------------------------------------------------
# DATABASE
# ------------------------------------------------

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
        actor TEXT,
        campaign TEXT,
        mitre TEXT,
        sector TEXT,
        severity INTEGER,
        confidence INTEGER,
        lat REAL,
        lon REAL,
        created TEXT
    )
    """)

    conn.commit()

init_db()

# ------------------------------------------------
# INTELLIGENCE DATA
# ------------------------------------------------

states={
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

actors=[
"Lazarus Group",
"APT29",
"FIN7",
"TA505",
"APT41",
"Unknown"
]

campaigns=[
"Operation Phantom",
"DarkBanking",
"Silent Hydra",
"Shadow Strike",
"Ghost C2"
]

mitre=[
"Reconnaissance",
"Initial Access",
"Execution",
"Persistence",
"Privilege Escalation",
"Defense Evasion",
"Credential Access",
"Discovery",
"Lateral Movement",
"Command and Control",
"Exfiltration",
"Impact"
]

sectors=[
"Government",
"Banking",
"Telecommunications",
"Energy",
"Healthcare",
"Education"
]

def random_location():
    return random.choice(list(states.values()))

# ------------------------------------------------
# INSERT THREAT
# ------------------------------------------------

def insert_threat(indicator,typ,severity):

    conn=db()

    if conn.execute(
        "SELECT 1 FROM threats WHERE indicator=?",
        (indicator,)
    ).fetchone():
        return

    lat,lon=random_location()

    actor=random.choice(actors)
    campaign=random.choice(campaigns)
    mit=random.choice(mitre)
    sector=random.choice(sectors)

    confidence=random.randint(60,95)

    created=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    conn.execute("""
    INSERT INTO threats(
    indicator,type,actor,campaign,mitre,sector,severity,confidence,lat,lon,created
    )
    VALUES(?,?,?,?,?,?,?,?,?,?,?)
    """,(indicator,typ,actor,campaign,mit,sector,severity,confidence,lat,lon,created))

    conn.commit()

    generate_rule(indicator,typ)

# ------------------------------------------------
# IPS RULE
# ------------------------------------------------

def generate_rule(indicator,typ):

    sid=1000000+random.randint(1,9999)

    if typ=="ip":
        rule=f'alert ip any any -> any any (msg:"RedShark IP {indicator}"; sid:{sid}; rev:1;)'
    elif typ=="url":
        rule=f'alert http any any -> any any (msg:"RedShark URL {indicator}"; content:"{indicator}"; http_uri; sid:{sid}; rev:1;)'
    else:
        rule=f'# HASH {indicator}'

    with open(RULE_FILE,"a") as f:
        f.write(rule+"\n")

# ------------------------------------------------
# FEEDS
# ------------------------------------------------

def fetch_threatfox():

    try:

        url="https://threatfox.abuse.ch/export/json/recent/"
        r=requests.get(url,timeout=10).json()

        for i in r.get("data",[])[:20]:

            insert_threat(
                i.get("ioc"),
                i.get("ioc_type"),
                85
            )

    except:
        pass

def fetch_feodo():

    try:

        url="https://feodotracker.abuse.ch/downloads/ipblocklist.json"
        r=requests.get(url).json()

        for i in r[:20]:

            insert_threat(
                i.get("ip_address"),
                "ip",
                90
            )

    except:
        pass

def fetch_urlhaus():

    try:

        url="https://urlhaus.abuse.ch/downloads/csv_recent/"
        data=requests.get(url).text.splitlines()

        reader=csv.reader(data)

        for r in list(reader)[10:30]:

            insert_threat(
                r[2],
                "url",
                70
            )

    except:
        pass

def fetch_all():

    fetch_threatfox()
    fetch_feodo()
    fetch_urlhaus()

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
        line=dict(width=4)
    ))

    return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)

def actor_chart():

    rows=db().execute("""
    SELECT actor,COUNT(*) c
    FROM threats
    GROUP BY actor
    """).fetchall()

    x=[r["actor"] for r in rows]
    y=[r["c"] for r in rows]

    fig=go.Figure(go.Bar(x=x,y=y))

    return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)

def indicator_chart():

    rows=db().execute("""
    SELECT type,COUNT(*) c
    FROM threats
    GROUP BY type
    """).fetchall()

    labels=[r["type"] for r in rows]
    values=[r["c"] for r in rows]

    fig=go.Figure(go.Pie(labels=labels,values=values,hole=0.4))

    return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)

# ------------------------------------------------
# MAP
# ------------------------------------------------

def malaysia_map():

    rows=db().execute(
    "SELECT lat,lon FROM threats"
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
        )
    )

    return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)

# ------------------------------------------------
# HTML
# ------------------------------------------------

HTML="""
<html>

<head>

<title>RedShark CTI Dashboard v6.0</title>

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

table{
width:100%;
border-collapse:collapse
}

td,th{
padding:10px;
border-bottom:1px solid #1f3d5c
}

.btn{
background:#1f2f45;
padding:10px 20px;
margin:5px;
color:#A3B8CC;
border:none;
border-radius:6px
}

</style>

</head>

<body>

<h2>RedShark CTI Dashboard v6.0</h2>

<div class="card">
SecureNation Index: <b>{{index}}</b>
</div>

<div class="card">
<div id="timeline"></div>
</div>

<div class="card">
<div id="actor"></div>
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
<th>Actor</th>
<th>Campaign</th>
<th>Severity</th>
<th>Confidence</th>
</tr>

{% for r in rows %}

<tr>
<td>{{r.id}}</td>
<td>{{r.indicator}}</td>
<td>{{r.actor}}</td>
<td>{{r.campaign}}</td>
<td>{{r.severity}}</td>
<td>{{r.confidence}}</td>
</tr>

{% endfor %}

</table>

</div>

<script>

var timeline={{timeline|safe}}
var actor={{actor|safe}}
var indicator={{indicator|safe}}
var map={{map|safe}}

Plotly.newPlot("timeline",timeline.data,timeline.layout)
Plotly.newPlot("actor",actor.data,actor.layout)
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
        actor=actor_chart(),
        indicator=indicator_chart(),
        map=malaysia_map()
    )

# ------------------------------------------------
# RUN
# ------------------------------------------------

if __name__=="__main__":

    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT",5000))
    )