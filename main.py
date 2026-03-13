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

DB = "redshark_cti.db"
RULE_FILE = "redshark_ips.rules"

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

# ---------------- DUMMY DATA ----------------
def insert_threat(indicator,typ,severity):
    conn = db()
    if conn.execute("SELECT 1 FROM threats WHERE indicator=?",(indicator,)).fetchone():
        return
    lat,lon=random.choice([[1.49,103.74],[6.11,100.36],[6.12,102.23],[2.18,102.25],[2.72,101.94],[3.81,103.32],
                           [4.59,101.09],[5.41,100.33],[5.98,116.07],[1.55,110.35],[3.07,101.51],[5.33,103.14],[3.13,101.68]])
    actor=random.choice(["Lazarus","APT29","FIN7","TA505","APT41","Unknown"])
    campaign=random.choice(["Operation Phantom","DarkBanking","Silent Hydra","Shadow Strike","Ghost C2"])
    mitre=random.choice(["Reconnaissance","Initial Access","Execution","Persistence","Privilege Escalation","Defense Evasion",
                         "Credential Access","Discovery","Lateral Movement","Command & Control","Exfiltration","Impact"])
    sector=random.choice(["Government","Banking","Telecom","Energy","Healthcare","Education"])
    confidence=random.randint(60,95)
    created=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    conn.execute("""
    INSERT INTO threats(indicator,type,actor,campaign,mitre,sector,severity,confidence,lat,lon,created)
    VALUES(?,?,?,?,?,?,?,?,?,?,?)
    """,(indicator,typ,actor,campaign,mitre,sector,severity,confidence,lat,lon,created))
    conn.commit()
    generate_rule(indicator,typ)

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
seed_dummy_data()

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
            if len(r)>2:
                insert_threat(r[2],"url",70)
    except: pass

def background_feed_loop():
    while True:
        fetch_threatfox()
        fetch_feodo()
        fetch_urlhaus()
        time.sleep(30)
threading.Thread(target=background_feed_loop,daemon=True).start()

# ---------------- SECURENATION ----------------
def securenation():
    rows=db().execute("SELECT severity FROM threats ORDER BY id DESC LIMIT 100").fetchall()
    if not rows: return 0
    return round(sum([r["severity"] for r in rows])/len(rows),1)

def progress_color(index):
    if index>=85: return "crimson"
    if index>=70: return "orange"
    return "green"

# ---------------- CHARTS (Nikkei Style) ----------------
def timeline_chart():
    rows=db().execute("SELECT substr(created,1,10) d,COUNT(*) c FROM threats GROUP BY d").fetchall()
    x=[str(r["d"]) for r in rows] or ["No Data"]
    y=[int(r["c"]) for r in rows] or [0]
    fig=go.Figure()
    fig.add_trace(go.Scatter(x=x,y=y,mode="lines+markers",line=dict(width=3,color="#FFA500"),marker=dict(size=8)))
    fig.update_layout(plot_bgcolor="#0b1b2a",paper_bgcolor="#0b1b2a",font_color="#A3B8CC",
                      xaxis=dict(showgrid=False),yaxis=dict(showgrid=False))
    return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)

def actor_chart():
    rows=db().execute("SELECT actor,COUNT(*) c FROM threats GROUP BY actor").fetchall()
    x=[r["actor"] for r in rows] or ["No Data"]
    y=[r["c"] for r in rows] or [0]
    fig=go.Figure(go.Bar(x=x,y=y,marker_color="#00eaff"))
    fig.update_layout(plot_bgcolor="#0b1b2a",paper_bgcolor="#0b1b2a",font_color="#A3B8CC",xaxis=dict(showgrid=False),yaxis=dict(showgrid=False))
    return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)

def indicator_chart():
    rows=db().execute("SELECT type,COUNT(*) c FROM threats GROUP BY type").fetchall()
    labels=[r["type"] for r in rows] or ["No Data"]
    values=[r["c"] for r in rows] or [0]
    fig=go.Figure(go.Pie(labels=labels,values=values,hole=0.3))
    fig.update_traces(marker=dict(line=dict(color="#0b1b2a",width=2)))
    fig.update_layout(plot_bgcolor="#0b1b2a",paper_bgcolor="#0b1b2a",font_color="#A3B8CC")
    return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)

def mitre_chart():
    rows=db().execute("SELECT mitre,COUNT(*) c FROM threats GROUP BY mitre").fetchall()
    labels=[r["mitre"] for r in rows] or ["No Data"]
    values=[r["c"] for r in rows] or [0]
    fig=go.Figure(go.Bar(x=labels,y=values,marker_color="#FFA500"))
    fig.update_layout(plot_bgcolor="#0b1b2a",paper_bgcolor="#0b1b2a",font_color="#A3B8CC",
                      xaxis_tickangle=-45,xaxis=dict(showgrid=False),yaxis=dict(showgrid=False))
    return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)

def sector_chart():
    rows=db().execute("SELECT sector,COUNT(*) c FROM threats GROUP BY sector").fetchall()
    labels=[r["sector"] for r in rows] or ["No Data"]
    values=[r["c"] for r in rows] or [0]
    fig=go.Figure(go.Bar(x=labels,y=values,marker_color="#00eaff"))
    fig.update_layout(plot_bgcolor="#0b1b2a",paper_bgcolor="#0b1b2a",font_color="#A3B8CC",
                      xaxis=dict(showgrid=False),yaxis=dict(showgrid=False))
    return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)

def malaysia_map():
    rows=db().execute("SELECT lat,lon,severity FROM threats").fetchall()
    lat,lon,color,size=[],[],[],[]
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
    if not lat: lat,lon,size,color=[0],[0],[0],["grey"]
    fig=go.Figure(go.Scattergeo(
        lon=lon,lat=lat,
        mode="markers",
        marker=dict(size=size,color=color,opacity=0.8,line=dict(width=2,color="white")),
    ))
    fig.update_layout(
        geo=dict(scope="asia",projection_type="natural earth",showland=True,landcolor="#0b1b2a",
                 showlakes=False,showocean=True,oceancolor="#0b1b2a"),
        plot_bgcolor="#0b1b2a",paper_bgcolor="#0b1b2a",font_color="#A3B8CC")
    return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)

# ---------------- DASHBOARD HTML ----------------
HTML = """<html>
<head>
<title>RedShark CTI Dashboard v7.2.6</title>
<script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
<style>
body{background:#0b1b2a;color:#A3B8CC;font-family:Arial,sans-serif;margin:0;padding:0}
.card{background:#13263b;padding:20px;margin:15px;border-radius:8px}
table{width:100%;border-collapse:collapse}
td,th{padding:10px;border-bottom:1px solid #1f3d5c;text-align:left}
th{cursor:pointer}
.btn{background:#0b1b2a;padding:10px 20px;margin:5px;color:#A3B8CC;font-weight:bold;border:none;border-radius:6px;cursor:pointer}
.progress{background:#1f2f45;border-radius:6px;overflow:hidden;height:20px;width:100%}
.progress-bar{height:20px;background:{{progress_color}};width:{{index}}%}
</style>
</head>
<body>
<h2 style="margin-left:15px;">RedShark CTI Dashboard v7.2.6</h2>
<div class="card">SecureNation Index
<div class="progress"><div class="progress-bar"></div></div></div>

<div class="card"><h3>Timeline</h3><div id="timeline" style="height:300px;"></div></div>
<div class="card"><h3>Actor Activity</h3><div id="actor" style="height:300px;"></div></div>
<div class="card"><h3>Indicator Type</h3><div id="indicator" style="height:300px;"></div></div>
<div class="card"><h3>MITRE ATT&CK</h3><div id="mitre" style="height:300px;"></div></div>
<div class="card"><h3>Sector Targeting</h3><div id="sector" style="height:300px;"></div></div>
<div class="card"><h3>Malaysia Attack Map</h3><div id="map" style="height:400px;"></div></div>

<div class="card"><h3>Latest Indicators</h3>
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
</table></div>

<div class="card">
<button class="btn" onclick="window.location.href='/csv'">Download CSV</button>
<button class="btn" onclick="window.location.href='/json'">Download JSON</button>
<button class="btn" onclick="window.location.href='/pdf'">Download PDF</button>
<button class="btn" onclick="window.location.href='/ips'">Download IPS Rules</button>
</div>

<script>
function sortTable(n){
    var table=document.getElementById("indicatorTable")
    var rows=Array.from(table.rows).slice(1)
    rows.sort((a,b)=>a.cells[n].innerText.localeCompare(b.cells[n].innerText))
    rows.forEach(r=>table.appendChild(r))
}
Plotly.newPlot("timeline",{{timeline|safe}}.data,{{timeline|safe}}.layout,{responsive:true,displayModeBar:false})
Plotly.newPlot("actor",{{actor|safe}}.data,{{actor|safe}}.layout,{responsive:true,displayModeBar:false})
Plotly.newPlot("indicator",{{indicator|safe}}.data,{{indicator|safe}}.layout,{responsive:true,displayModeBar:false})
Plotly.newPlot("mitre",{{mitre|safe}}.data,{{mitre|safe}}.layout,{responsive:true,displayModeBar:false})
Plotly.newPlot("sector",{{sector|safe}}.data,{{sector|safe}}.layout,{responsive:true,displayModeBar:false})
Plotly.newPlot("map",{{map|safe}}.data,{{map|safe}}.layout,{responsive:true,displayModeBar:false})
</script>
</body>
</html>
"""

# ---------------- DASHBOARD ----------------
@app.route("/")
def dashboard():
    rows = db().execute("SELECT * FROM threats ORDER BY id DESC LIMIT 50").fetchall() or []
    index=securenation()
    return render_template_string(HTML,
                                  rows=rows,
                                  index=index,
                                  progress_color=progress_color(index),
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
    if not rows: return "No data available",404
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
    if not rows: return "No data available",404
    data=[dict(r) for r in rows]
    mem=io.BytesIO()
    mem.write(json.dumps(data,indent=2).encode())
    mem.seek(0)
    return send_file(mem,download_name="threats.json",as_attachment=True)

@app.route("/pdf")
def pdf_export():
    rows=db().execute("SELECT indicator,type,actor,campaign,severity,confidence FROM threats LIMIT 50").fetchall()
    if not rows: return "No data available",404
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
    if not os.path.exists(RULE_FILE):
        return "No IPS rules available",404
    return send_file(RULE_FILE,download_name="redshark_ips.rules",as_attachment=True)

if __name__=="__main__":
    app.run(host="0.0.0.0",port=int(os.environ.get("PORT",5000)))