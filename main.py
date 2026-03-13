import os
import sqlite3
import requests
import json
import csv
import io
import random
import threading
import time
from datetime import datetime
from flask import Flask, render_template_string, send_file

import plotly.graph_objs as go
import plotly

from reportlab.platypus import SimpleDocTemplate, Table
from reportlab.lib.pagesizes import landscape, A4

app = Flask(__name__)
DB="/tmp/redshark_cti_v7_2_1.db"
RULE_FILE="/tmp/redshark_ips_v7_2_1.rules"

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

# ---------------- SEED DUMMY DATA ----------------
def seed_dummy_data():
    conn = db()
    if conn.execute("SELECT 1 FROM threats LIMIT 1").fetchone():
        return
    sample_indicators = [
        ("192.168.1.100", "ip", 90),
        ("malicious.com/path", "url", 75),
        ("abcd1234ef5678", "hash", 80)
    ]
    for ind, typ, sev in sample_indicators:
        insert_threat(ind, typ, sev)

# ---------------- DATA ----------------
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

actors=["Lazarus","APT29","FIN7","TA505","APT41","Unknown"]
campaigns=["Operation Phantom","DarkBanking","Silent Hydra","Shadow Strike","Ghost C2"]
mitre=["Reconnaissance","Initial Access","Execution","Persistence","Privilege Escalation","Defense Evasion",
       "Credential Access","Discovery","Lateral Movement","Command & Control","Exfiltration","Impact"]
sectors=["Government","Banking","Telecom","Energy","Healthcare","Education"]

def random_location():
    return random.choice(list(states.values()))

# ---------------- INSERT ----------------
def insert_threat(indicator,typ,severity):
    conn=db()
    if conn.execute("SELECT 1 FROM threats WHERE indicator=?",(indicator,)).fetchone():
        return
    lat,lon=random_location()
    actor=random.choice(actors)
    campaign=random.choice(campaigns)
    mit=random.choice(mitre)
    sector=random.choice(sectors)
    confidence=random.randint(60,95)
    created=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    conn.execute("""
    INSERT INTO threats(indicator,type,actor,campaign,mitre,sector,severity,confidence,lat,lon,created)
    VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
    """,(indicator,typ,actor,campaign,mit,sector,severity,confidence,lat,lon,created))
    conn.commit()
    generate_rule(indicator,typ)

# ---------------- IPS RULE ----------------
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

# ---------------- FEEDS ----------------
def fetch_threatfox():
    try:
        url="https://threatfox.abuse.ch/export/json/recent/"
        r=requests.get(url,timeout=10).json()
        for i in r.get("data",[])[:20]:
            insert_threat(i.get("ioc"),i.get("ioc_type"),85)
    except: pass

def fetch_feodo():
    try:
        url="https://feodotracker.abuse.ch/downloads/ipblocklist.json"
        r=requests.get(url).json()
        for i in r[:20]:
            insert_threat(i.get("ip_address"),"ip",90)
    except: pass

def fetch_urlhaus():
    try:
        url="https://urlhaus.abuse.ch/downloads/csv_recent/"
        data=requests.get(url).text.splitlines()
        reader=csv.reader(data)
        for r in list(reader)[10:30]:
            insert_threat(r[2],"url",70)
    except: pass

def background_feed_loop():
    while True:
        fetch_threatfox()
        fetch_feodo()
        fetch_urlhaus()
        time.sleep(30)

threading.Thread(target=background_feed_loop,daemon=True).start()

# ---------------- SECURENATION INDEX ----------------
def securenation():
    rows=db().execute("SELECT severity FROM threats ORDER BY id DESC LIMIT 100").fetchall()
    if not rows: return 0
    return round(sum([r["severity"] for r in rows])/len(rows),1)

# ---------------- CHARTS ----------------
def timeline_chart():
    rows=db().execute("SELECT substr(created,1,10) d,COUNT(*) c FROM threats GROUP BY d").fetchall()
    x=[r["d"] for r in rows]
    y=[r["c"] for r in rows]
    fig=go.Figure()
    fig.add_trace(go.Scatter(x=x,y=y,mode="lines+markers",line=dict(width=3,color="#FFA500")))
    fig.update_layout(plot_bgcolor="#0b1b2a",paper_bgcolor="#0b1b2a",font_color="#A3B8CC",
                      xaxis=dict(showgrid=False),yaxis=dict(showgrid=False))
    return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)

def actor_chart():
    rows=db().execute("SELECT actor,COUNT(*) c FROM threats GROUP BY actor").fetchall()
    x=[r["actor"] for r in rows]
    y=[r["c"] for r in rows]
    fig=go.Figure(go.Bar(x=x,y=y,marker_color="#00eaff"))
    fig.update_layout(plot_bgcolor="#0b1b2a",paper_bgcolor="#0b1b2a",font_color="#A3B8CC")
    return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)

def indicator_chart():
    rows=db().execute("SELECT type,COUNT(*) c FROM threats GROUP BY type").fetchall()
    labels=[r["type"] for r in rows]
    values=[r["c"] for r in rows]
    fig=go.Figure(go.Pie(labels=labels,values=values,hole=0.4))
    fig.update_layout(plot_bgcolor="#0b1b2a",paper_bgcolor="#0b1b2a",font_color="#A3B8CC")
    return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)

def mitre_chart():
    rows=db().execute("SELECT mitre,COUNT(*) c FROM threats GROUP BY mitre").fetchall()
    labels=[r["mitre"] for r in rows]
    values=[r["c"] for r in rows]
    fig=go.Figure(go.Bar(x=labels,y=values,marker_color="#FFA500"))
    fig.update_layout(plot_bgcolor="#0b1b2a",paper_bgcolor="#0b1b2a",font_color="#A3B8CC",xaxis_tickangle=-45)
    return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)

def sector_chart():
    rows=db().execute("SELECT sector,COUNT(*) c FROM threats GROUP BY sector").fetchall()
    labels=[r["sector"] for r in rows]
    values=[r["c"] for r in rows]
    fig=go.Figure(go.Bar(x=labels,y=values,marker_color="#00eaff"))
    fig.update_layout(plot_bgcolor="#0b1b2a",paper_bgcolor="#0b1b2a",font_color="#A3B8CC")
    return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)

def malaysia_map():
    rows=db().execute("SELECT lat,lon,severity FROM threats").fetchall()
    lat=[]
    lon=[]
    color=[]
    size=[]
    for r in rows:
        lat.append(r["lat"])
        lon.append(r["lon"])
        if r["severity"]>=85:
            color.append("crimson")
            size.append(14)
        elif r["severity"]>=70:
            color.append("orange")
            size.append(10)
        else:
            color.append("yellow")
            size.append(6)
    fig=go.Figure(go.Scatter3d(x=lon,y=lat,z=[s for s in size],mode="markers",
                                 marker=dict(size=size,color=color,opacity=0.9)))
    fig.update_layout(scene=dict(xaxis=dict(showbackground=False),
                                 yaxis=dict(showbackground=False),
                                 zaxis=dict(showbackground=False)),
                      paper_bgcolor="#0b1b2a",font_color="#A3B8CC")
    return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)

# ---------------- SEED DATA ----------------
seed_dummy_data()

# ---------------- DASHBOARD HTML ----------------
HTML="""
<html>
<head>
<title>RedShark CTI v7.2.1</title>
<script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
<style>
body{background:#0b1b2a;color:#A3B8CC;font-family:Arial}
.card{background:#13263b;padding:20px;margin:15px;border-radius:8px}
table{width:100%;border-collapse:collapse}
td,th{padding:10px;border-bottom:1px solid #1f3d5c}
th{cursor:pointer}
.btn{background:#1f2f45;padding:10px 20px;margin:5px;color:#A3B8CC;font-weight:bold;border:none;border-radius:6px;cursor:pointer}
.progress{background:#1f2f45;border-radius:6px;overflow:hidden;height:20px;width:100%}
.progress-bar{height:20px;background:crimson;width:{{index}}%}
</style>
</head>
<body>

<h2>RedShark CTI Dashboard v7.2.1</h2>

<div class="card">
SecureNation Index
<div class="progress"><div class="progress-bar"></div></div>
</div>

<div class="card"><h3>Timeline</h3><div id="timeline"></div></div>
<div class="card"><h3>Actor Activity</h3><div id="actor"></div></div>
<div class="card"><h3>Indicator Type</h3><div id="indicator"></div></div>
<div class="card"><h3>MITRE ATT&CK Heatmap</h3><div id="mitre"></div></div>
<div class="card"><h3>Sector Targeting</h3><div id="sector"></div></div>
<div class="card"><h3>Malaysia Attack 3D Heatmap</h3><div id="map"></div></div>

<div class="card">
<h3>Latest Indicators</h3>
<table id="indicatorTable">
<tr>
<th onclick="sortTable(0)">ID</th>
<th onclick="sortTable(1)">Indicator</th>
<th onclick="sortTable(2)">Actor</th>
<th onclick="sortTable(3)">Campaign</th>
<th onclick="sortTable(4)">Severity</th>
<th onclick="sortTable(5)">Confidence</th>
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

<div class="card">
<button class="btn" onclick="window.location.href='/csv'">Download CSV</button>
<button class="btn" onclick="window.location.href='/json'">Download JSON</button>
<button class="btn" onclick="window.location.href='/pdf'">Download PDF</button>
<button class="btn" onclick="window.location.href='/ips'">Download IPS Rules</button>
</div>

<script>
function sortTable(n) {
    var table=document.getElementById("indicatorTable")
    var rows=Array.from(table.rows).slice(1)
    rows.sort((a,b)=>a.cells[n].innerText.localeCompare(b.cells[n].innerText))
    rows.forEach(r=>table.appendChild(r))
}

var timeline={{timeline|safe}}
var actor={{actor|safe}}
var indicator={{indicator|safe}}
var mitre={{mitre|safe}}
var sector={{sector|safe}}
var map={{map|safe}}

Plotly.newPlot("timeline",timeline.data,timeline.layout)
Plotly.newPlot("actor",actor.data,actor.layout)
Plotly.newPlot("indicator",indicator.data,indicator.layout)
Plotly.newPlot("mitre",mitre.data,mitre.layout)
Plotly.newPlot("sector",sector.data,sector.layout)
Plotly.newPlot("map",map.data,map.layout)
</script>
</body>
</html>
"""

# ---------------- DASHBOARD ----------------
@app.route("/")
def dashboard():
    rows=db().execute("SELECT * FROM threats ORDER BY id DESC LIMIT 50").fetchall()
    return render_template_string(HTML,
                                  rows=rows,
                                  index=securenation(),
                                  timeline=timeline_chart(),
                                  actor=actor_chart(),
                                  indicator=indicator_chart(),
                                  mitre=mitre_chart(),
                                  sector=sector_chart(),
                                  map=malaysia_map())

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
    rows=db().execute("SELECT indicator,type,actor,campaign,severity,confidence FROM threats LIMIT 50").fetchall()
    buffer=io.BytesIO()
    data=[["Indicator","Type","Actor","Campaign","Severity","Confidence"]]
    for r in rows:
        data.append([r["indicator"],r["type"],r["actor"],r["campaign"],r["severity"],r["confidence"]])
    pdf=SimpleDocTemplate(buffer,pagesize=landscape(A4))
    table=Table(data)
    pdf.build([table])
    buffer.seek(0)
    return send_file(buffer,download_name="report.pdf",as_attachment=True)

@app.route("/ips")
def ips_export():
    return send_file(RULE_FILE,download_name="redshark_ips.rules",as_attachment=True)

# ---------------- RUN ----------------
if __name__=="__main__":
    app.run(host="0.0.0.0",port=int(os.environ.get("PORT",5000)))