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
from zipfile import ZipFile

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
    src_lat REAL,
    src_lon REAL,
    created TEXT
    )
    """)
    conn.commit()

init_db()

# ---------------- GEO DATA ----------------

malaysia=[4.5,102]

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

world_sources=[
[37.77,-122.41],
[55.75,37.61],
[39.90,116.40],
[52.52,13.40],
[28.61,77.20],
[35.68,139.69]
]

sectors=[
"Government","Banking","Telecommunications",
"Energy","Healthcare","Education",
"Manufacturing","Transportation","Retail","Technology"
]

mitre=[
"Reconnaissance","Initial Access","Execution",
"Persistence","Privilege Escalation","Defense Evasion",
"Credential Access","Discovery","Lateral Movement",
"Collection","Command and Control","Exfiltration","Impact"
]

def rand_loc(): return random.choice(list(states.values()))
def rand_src(): return random.choice(world_sources)
def rand_sector(): return random.choice(sectors)
def rand_mitre(): return random.choice(mitre)

# ---------------- INSERT THREAT ----------------

def insert_threat(indicator,typ,severity):

    conn=db()

    if conn.execute("SELECT 1 FROM threats WHERE indicator=?",(indicator,)).fetchone():
        return

    lat,lon=rand_loc()
    src_lat,src_lon=rand_src()

    m=rand_mitre()
    s=rand_sector()

    created=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    conn.execute("""
    INSERT INTO threats(indicator,type,mitre,sector,severity,lat,lon,src_lat,src_lon,created)
    VALUES(?,?,?,?,?,?,?,?,?,?)
    """,(indicator,typ,m,s,severity,lat,lon,src_lat,src_lon,created))

    conn.commit()

    sid=1000000+random.randint(1,9999)

    rule=f'alert ip any any -> any any (msg:"RedShark IOC {indicator}"; sid:{sid}; rev:1;)\n'

    with open(RULE_FILE,"a") as f:
        f.write(rule)

# ---------------- FEEDS ----------------

def fetch_threatfox():
    try:
        url="https://threatfox.abuse.ch/export/json/recent/"
        r=requests.get(url,timeout=10).json()

        for i in r.get("data",[])[:40]:
            insert_threat(i.get("ioc","unknown"),i.get("ioc_type","ip"),85)

    except:
        pass

def fetch_feodo():
    try:
        url="https://feodotracker.abuse.ch/downloads/ipblocklist.json"
        data=requests.get(url,timeout=10).json()

        for i in data[:40]:
            insert_threat(i.get("ip_address"),"ip",90)

    except:
        pass

def fetch_feeds():
    fetch_threatfox()
    fetch_feodo()

# ---------------- SCHEDULER ----------------

def scheduler():
    fetch_feeds()
    threading.Timer(900,scheduler).start()

fetch_feeds()
scheduler()

# ---------------- INDEX ----------------

def securenation():

    rows=db().execute(
    "SELECT severity FROM threats ORDER BY id DESC LIMIT 100"
    ).fetchall()

    if not rows:
        return 0

    avg=sum([r["severity"] for r in rows])/len(rows)

    return round(avg,1)

# ---------------- SUMMARY ----------------

def generate_summary():

    rows=db().execute(
    "SELECT indicator,type,severity FROM threats ORDER BY id DESC LIMIT 5"
    ).fetchall()

    s=[]

    for r in rows:
        s.append(
        f"{r['type']} indicator {r['indicator']} detected with severity {r['severity']}"
        )

    return s

# ---------------- CHARTS ----------------

def timeline_chart():

    rows=db().execute(
    "SELECT substr(created,1,10) d,COUNT(*) c FROM threats GROUP BY d ORDER BY d"
    ).fetchall()

    x=[r["d"] for r in rows]
    y=[r["c"] for r in rows]

    fig=go.Figure()

    fig.add_trace(go.Scatter(
    x=x,y=y,
    fill="tozeroy",
    line=dict(color="#ff3b3b",width=3),
    fillcolor="rgba(255,0,0,0.3)"
    ))

    fig.update_layout(
    plot_bgcolor="#000",
    paper_bgcolor="#000",
    font_color="#fff"
    )

    return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)

def sector_chart():

    rows=db().execute(
    "SELECT sector,COUNT(*) c FROM threats GROUP BY sector"
    ).fetchall()

    labels=[r["sector"] for r in rows]
    values=[r["c"] for r in rows]

    fig=go.Figure(go.Bar(
    x=labels,y=values,
    marker=dict(color="rgba(255,60,60,0.8)")
    ))

    fig.update_layout(
    plot_bgcolor="#000",
    paper_bgcolor="#000",
    font_color="#fff"
    )

    return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)

def indicator_chart():

    rows=db().execute(
    "SELECT type,COUNT(*) c FROM threats GROUP BY type"
    ).fetchall()

    labels=[r["type"] for r in rows]
    values=[r["c"] for r in rows]

    fig=go.Figure(go.Pie(
    labels=labels,
    values=values,
    hole=0.55
    ))

    fig.update_layout(
    plot_bgcolor="#000",
    paper_bgcolor="#000",
    font_color="#fff"
    )

    return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)

def mitre_chart():

    rows=db().execute(
    "SELECT mitre,COUNT(*) c FROM threats GROUP BY mitre"
    ).fetchall()

    labels=[r["mitre"] for r in rows]
    values=[r["c"] for r in rows]

    fig=go.Figure(go.Bar(x=labels,y=values))

    fig.update_layout(
    plot_bgcolor="#000",
    paper_bgcolor="#000",
    font_color="#fff"
    )

    return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)

def malaysia_map():

    rows=db().execute(
    "SELECT lat,lon,src_lat,src_lon,severity FROM threats"
    ).fetchall()

    fig=go.Figure()

    for r in rows:

        fig.add_trace(go.Scattermapbox(
        lat=[r["src_lat"],r["lat"]],
        lon=[r["src_lon"],r["lon"]],
        mode="lines",
        line=dict(width=1,color="red")
        ))

    fig.add_trace(go.Scattermapbox(
    lat=[r["lat"] for r in rows],
    lon=[r["lon"] for r in rows],
    mode="markers",
    marker=dict(
    size=12,
    color=[r["severity"] for r in rows],
    colorscale="Reds"
    )
    ))

    fig.update_layout(
    mapbox_style="carto-darkmatter",
    mapbox_center={"lat":4.5,"lon":102},
    mapbox_zoom=4,
    paper_bgcolor="#000"
    )

    return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)

# ---------------- HTML ----------------

HTML="""
<html>
<head>

<script src="https://cdn.plot.ly/plotly-latest.min.js"></script>

<style>

body{
background:#000;
color:#fff;
font-family:Arial;
}

.card{
background:#0a0a0a;
border:1px solid #330000;
padding:20px;
margin:15px;
box-shadow:0 0 10px #440000;
}

</style>

</head>

<body>

<h2>RedShark CTI Dashboard</h2>

<p>Threat Intelligence Highlights @ {{timestamp}}</p>

<div class="card">

<h3>⚡ Threat Intelligence Highlights</h3>

<ul>

{% for s in summary %}

<li>{{s}}</li>

{% endfor %}

</ul>

</div>

<div class="card">

<h3>SecureNation Threat Index: {{index}}</h3>

</div>

<div class="card">

<h3>Malaysia Attack Map</h3>

<div id="map" style="height:400px;"></div>

</div>

<div class="card">

<h3>Threat Timeline</h3>

<div id="timeline"></div>

</div>

<div class="card">

<h3>Sector Targeting</h3>

<div id="sector"></div>

</div>

<div class="card">

<h3>Indicator Distribution</h3>

<div id="indicator"></div>

</div>

<div class="card">

<h3>MITRE ATT&CK</h3>

<div id="mitre"></div>

</div>

<script>

var map={{map|safe}};
var timeline={{timeline|safe}};
var sector={{sector|safe}};
var indicator={{indicator|safe}};
var mitre={{mitre|safe}};

Plotly.newPlot("map",map.data,map.layout);
Plotly.newPlot("timeline",timeline.data,timeline.layout);
Plotly.newPlot("sector",sector.data,sector.layout);
Plotly.newPlot("indicator",indicator.data,indicator.layout);
Plotly.newPlot("mitre",mitre.data,mitre.layout);

</script>

</body>

</html>
"""

# ---------------- ROUTE ----------------

@app.route("/")
def dashboard():

    return render_template_string(
    HTML,
    summary=generate_summary(),
    index=securenation(),
    timestamp=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
    timeline=timeline_chart(),
    sector=sector_chart(),
    indicator=indicator_chart(),
    mitre=mitre_chart(),
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

@app.route("/download_ips")
def download_ips():

    if not os.path.exists(RULE_FILE):
        open(RULE_FILE,"w").close()

    zip_path="/tmp/redshark_ips.zip"

    with ZipFile(zip_path,"w") as zipf:
        zipf.write(RULE_FILE,"redshark.rules")

    return send_file(zip_path,download_name="redshark_ips.zip",as_attachment=True)

# ---------------- MAIN ----------------

if __name__=="__main__":
    app.run(host="0.0.0.0",port=5000)