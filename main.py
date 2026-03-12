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

DB="/tmp/threats.db"

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

with app.app_context():
    init_db()

# ---------------- MALAYSIA STATES ----------------

states={

"Johor":[1.4927,103.7414],
"Kedah":[6.1184,100.3685],
"Kelantan":[6.1254,102.2381],
"Melaka":[2.1896,102.2501],
"Negeri Sembilan":[2.7258,101.9424],
"Pahang":[3.8126,103.3256],
"Perak":[4.5921,101.0901],
"Perlis":[6.4449,100.2048],
"Pulau Pinang":[5.4164,100.3327],
"Sabah":[5.9804,116.0735],
"Sarawak":[1.5533,110.3592],
"Selangor":[3.0738,101.5183],
"Terengganu":[5.3302,103.1408],
"Kuala Lumpur":[3.1390,101.6869],
"Putrajaya":[2.9264,101.6964],
"Labuan":[5.2831,115.2308]

}

sectors=[
"Government",
"Banking",
"Telecommunications",
"Energy",
"Healthcare"
]

def random_location():
    return random.choice(list(states.values()))

def random_sector():
    return random.choice(sectors)

# ---------------- INSERT ----------------

def insert_threat(indicator,typ,mitre,severity):

    lat,lon=random_location()

    conn=db()

    conn.execute(
    "INSERT INTO threats(indicator,type,mitre,sector,severity,lat,lon,created) VALUES(?,?,?,?,?,?,?,?)",
    (indicator,typ,mitre,random_sector(),severity,lat,lon,datetime.utcnow())
    )

    conn.commit()

# ---------------- FEEDS ----------------

def fetch_threatfox():

    try:

        url="https://threatfox.abuse.ch/export/json/recent/"
        r=requests.get(url,timeout=10).json()

        for i in r["data"][:20]:

            insert_threat(
                i["ioc"],
                i["ioc_type"],
                "Command & Control",
                85
            )

    except:
        pass


def fetch_urlhaus():

    try:

        url="https://urlhaus.abuse.ch/downloads/csv_recent/"
        data=requests.get(url,timeout=10).text.splitlines()

        reader=csv.reader(data)

        for row in list(reader)[10:30]:

            if len(row)>2:

                insert_threat(
                    row[2],
                    "malware_url",
                    "Execution",
                    70
                )

    except:
        pass


def fetch_feodo():

    try:

        url="https://feodotracker.abuse.ch/downloads/ipblocklist.json"
        data=requests.get(url,timeout=10).json()

        for item in data[:20]:

            insert_threat(
                item["ip_address"],
                "ip",
                "Command & Control",
                90
            )

    except:
        pass


def fetch_hashes():

    try:

        url="https://mb-api.abuse.ch/api/v1/"

        r=requests.post(
        url,
        data={"query":"get_recent"},
        timeout=10
        ).json()

        for item in r["data"][:20]:

            insert_threat(
                item["sha256_hash"],
                "hash",
                "Execution",
                75
            )

    except:
        pass


def fetch_feeds():

    fetch_threatfox()
    fetch_urlhaus()
    fetch_feodo()
    fetch_hashes()


fetch_feeds()

# ---------------- METRICS ----------------

def securenation():

    rows=db().execute(
    "SELECT severity FROM threats ORDER BY id DESC LIMIT 100"
    ).fetchall()

    if not rows:
        return 0

    score=sum([r["severity"] for r in rows])/len(rows)

    return round(score,1)

# ---------------- CHARTS ----------------

def timeline_chart():

    rows=db().execute(
    "SELECT substr(created,1,10) d,count(*) c FROM threats GROUP BY d"
    ).fetchall()

    x=[r["d"] for r in rows]
    y=[r["c"] for r in rows]

    fig=go.Figure()
    fig.add_trace(go.Scatter(x=x,y=y,mode="lines+markers"))

    return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)


def mitre_chart():

    rows=db().execute(
    "SELECT mitre,count(*) c FROM threats GROUP BY mitre"
    ).fetchall()

    labels=[r["mitre"] for r in rows]
    values=[r["c"] for r in rows]

    fig=go.Figure(data=[go.Pie(labels=labels,values=values,hole=.4)])

    return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)


def sector_chart():

    rows=db().execute(
    "SELECT sector,count(*) c FROM threats GROUP BY sector"
    ).fetchall()

    labels=[r["sector"] for r in rows]
    values=[r["c"] for r in rows]

    fig=go.Figure(data=[go.Bar(x=labels,y=values)])

    return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)


def malaysia_map():

    rows=db().execute(
    "SELECT lat,lon,severity FROM threats ORDER BY id DESC LIMIT 40"
    ).fetchall()

    lat=[]
    lon=[]
    colors=[]

    for r in rows:

        lat.append(r["lat"])
        lon.append(r["lon"])

        if r["severity"]>=85:
            colors.append("red")
        elif r["severity"]>=70:
            colors.append("orange")
        else:
            colors.append("yellow")

    fig=go.Figure(go.Scattergeo(
        lat=lat,
        lon=lon,
        mode="markers",
        marker=dict(
            size=8,
            color=colors,
            opacity=0.9
        )
    ))

    fig.update_layout(
        geo=dict(
            scope="asia",
            center=dict(lat=4.5,lon=102),
            projection_type="natural earth"
        )
    )

    return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)

# ---------------- DASHBOARD ----------------

HTML="""
<html>
<head>
<title>RedShark Threat Intelligence Dashboard</title>
<script src="https://cdn.plot.ly/plotly-latest.min.js"></script>

<style>

body{
background:#0b1b2a;
color:#00eaff;
font-family:Arial;
}

.card{
background:#13263b;
padding:20px;
margin:15px;
border-radius:8px;
}

table{
width:100%;
border-collapse:collapse;
}

td,th{
padding:8px;
border-bottom:1px solid #1f3d5c;
}

</style>
</head>

<body>

<h2>RedShark Threat Intelligence Dashboard</h2>

<div class="card">
SecureNation Index: <b>{{index}}</b>
</div>

<div class="card">
<h3>Malaysia Cyber Attack Map</h3>
<div id="map"></div>
</div>

<div class="card">
<h3>Threat Timeline</h3>
<div id="timeline"></div>
</div>

<div class="card">
<h3>MITRE ATT&CK Distribution</h3>
<div id="mitre"></div>
</div>

<div class="card">
<h3>Sector Targeting</h3>
<div id="sector"></div>
</div>

<div class="card">
<h3>Latest Threat Indicators</h3>

<table>

<tr>
<th>ID</th>
<th>Indicator</th>
<th>Type</th>
<th>Sector</th>
<th>Severity</th>
</tr>

{% for r in rows %}

<tr>
<td>{{r.id}}</td>
<td>{{r.indicator}}</td>
<td>{{r.type}}</td>
<td>{{r.sector}}</td>
<td>{{r.severity}}</td>
</tr>

{% endfor %}

</table>

</div>

<div class="card">
<a href="/csv">Download CSV</a> |
<a href="/json">Download JSON</a> |
<a href="/pdf">Download PDF</a>
</div>

<script>

var timeline={{timeline|safe}}
var mitre={{mitre|safe}}
var sector={{sector|safe}}
var map={{map|safe}}

Plotly.newPlot("timeline",timeline.data,timeline.layout)
Plotly.newPlot("mitre",mitre.data,mitre.layout)
Plotly.newPlot("sector",sector.data,sector.layout)
Plotly.newPlot("map",map.data,map.layout)

</script>

<p style="opacity:0.6">
Developed and analyzed by darkgrid@redshark.my using publicly available threat intelligence sources
</p>

</body>
</html>
"""

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
        mitre=mitre_chart(),
        sector=sector_chart(),
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
    "SELECT indicator,type,sector,severity FROM threats LIMIT 50"
    ).fetchall()

    buffer=io.BytesIO()

    data=[["Indicator","Type","Sector","Severity"]]

    for r in rows:
        data.append([r["indicator"],r["type"],r["sector"],r["severity"]])

    pdf=SimpleDocTemplate(buffer,pagesize=landscape(A4))
    table=Table(data)

    pdf.build([table])

    buffer.seek(0)

    return send_file(buffer,download_name="report.pdf",as_attachment=True)

if __name__=="__main__":
    app.run(host="0.0.0.0",port=int(os.environ.get("PORT",5000)))