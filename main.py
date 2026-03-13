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
from reportlab.platypus import SimpleDocTemplate, Table, Paragraph
from reportlab.lib.pagesizes import landscape, A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors

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

# ---------------- STATES & SECTORS ----------------
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

def rand_loc(): return random.choice(list(states.values()))
def rand_sector(): return random.choice(sectors)
def rand_mitre(): return random.choice(mitre)

# ---------------- INSERT THREAT ----------------
def insert_threat(indicator,typ,severity):
    conn = db()
    if conn.execute("SELECT 1 FROM threats WHERE indicator=?", (indicator,)).fetchone():
        return
    lat, lon = rand_loc()
    m = rand_mitre()
    s = rand_sector()
    created = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    conn.execute("""
    INSERT INTO threats(indicator,type,mitre,sector,severity,lat,lon,created)
    VALUES(?,?,?,?,?,?,?,?)
    """, (indicator, typ, m, s, severity, lat, lon, created))
    conn.commit()
    # ---------------- IPS RULE GENERATION ----------------
    rule_sid = 1000000 + random.randint(1,9999)
    if typ=="ip":
        rule_line = f'alert ip any any -> any any (msg:"RedShark IP {indicator} | MITRE: {m}"; sid:{rule_sid}; rev:1;)\n'
    elif typ=="url":
        rule_line = f'alert http any any -> any any (msg:"RedShark URL {indicator} | MITRE: {m}"; content:"{indicator}"; http_uri; sid:{rule_sid}; rev:1;)\n'
    elif typ=="domain":
        rule_line = f'alert http any any -> any any (msg:"RedShark DOMAIN {indicator} | MITRE: {m}"; content:"{indicator}"; http_host; sid:{rule_sid}; rev:1;)\n'
    elif typ=="hash":
        rule_line = f'# Hash {indicator} | MITRE: {m} (requires file inspection)\n'
    else:
        rule_line = f'# Unknown type {typ} {indicator} | MITRE: {m}\n'
    with open(RULE_FILE,"a") as f:
        f.write(rule_line)

# ---------------- FEEDS ----------------
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

def fetch_urlhaus():
    try:
        url="https://urlhaus.abuse.ch/downloads/csv_recent/"
        data = requests.get(url, timeout=10).text.splitlines()
        reader = csv.reader(data)
        for row in list(reader)[10:50]:
            if len(row)>2:
                insert_threat(row[2],"url",70)
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
    fetch_urlhaus()

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
    return round(sum([r["severity"] for r in rows])/len(rows),1)

# ---------------- CHARTS ----------------
def malaysia_map():
    rows = db().execute("SELECT lat,lon,severity FROM threats").fetchall()
    lat, lon, sev = [r["lat"] for r in rows], [r["lon"] for r in rows], [r["severity"] for r in rows]
    colors, sizes = [], []
    for s in sev:
        if s>=85: colors.append("red"); sizes.append(18)
        elif s>=70: colors.append("orange"); sizes.append(12)
        else: colors.append("yellow"); sizes.append(10)
    fig = go.Figure()
    fig.add_trace(go.Scattermapbox(
        lat=lat, lon=lon, mode="markers",
        marker=dict(size=sizes, color=colors, opacity=0.8),
        text=[f"Severity: {s}" for s in sev],
        hoverinfo="text"
    ))
    fig.update_layout(
        mapbox_style="carto-darkmatter",
        mapbox_center={"lat":4.5,"lon":102},
        mapbox_zoom=4,
        paper_bgcolor="#0b1b2a",
        margin=dict(l=0,r=0,t=0,b=0),
        mapbox=dict(accesstoken=None)
    )
    return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)

def timeline_chart():
    rows=db().execute("SELECT substr(created,1,10) d, COUNT(*) c FROM threats GROUP BY d ORDER BY d").fetchall()
    x=[r["d"] for r in rows]; y=[r["c"] for r in rows]
    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=x, y=y, mode="lines+markers",
        line=dict(color="#00eaff", width=4, shape='spline', smoothing=1.3),
        marker=dict(size=10, color="#00eaff", line=dict(width=2, color="#ffffff"))
    ))
    fig.update_layout(plot_bgcolor="#0b1b2a", paper_bgcolor="#0b1b2a",
                      font_color="#A3B8CC", xaxis=dict(showgrid=False),
                      yaxis=dict(showgrid=False))
    return json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

def sector_chart():
    rows=db().execute("SELECT sector, COUNT(*) c FROM threats GROUP BY sector ORDER BY c DESC").fetchall()
    labels=[r["sector"] for r in rows]; values=[r["c"] for r in rows]
    fig=go.Figure(go.Bar(x=labels, y=values,
                         marker=dict(color="#3a4a5c", line=dict(color="#6f8fbf",width=2))))
    fig.update_layout(plot_bgcolor="#0b1b2a", paper_bgcolor="#0b1b2a",
                      font_color="#A3B8CC", title="Sector Targeting")
    return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)

def indicator_type_chart():
    rows=db().execute("SELECT type, COUNT(*) c FROM threats GROUP BY type").fetchall()
    labels=[r["type"] for r in rows]; values=[r["c"] for r in rows]
    fig = go.Figure(data=[go.Pie(labels=labels, values=values, hole=0.3, pull=[0.05]*len(labels))])
    fig.update_layout(plot_bgcolor="#0b1b2a", paper_bgcolor="#0b1b2a",
                      font_color="#A3B8CC", title="Indicator Type Distribution")
    return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)

def mitre_chart():
    rows=db().execute("SELECT mitre, COUNT(*) c FROM threats GROUP BY mitre").fetchall()
    labels=[r["mitre"] for r in rows]; values=[r["c"] for r in rows]
    fig=go.Figure()
    fig.add_trace(go.Scatter(x=labels, y=values, mode='lines+markers',
                             line=dict(color="#ff9900", width=3)))
    fig.update_layout(plot_bgcolor="#0b1b2a", paper_bgcolor="#0b1b2a",
                      font_color="#A3B8CC", title="MITRE Techniques Trend",
                      xaxis=dict(showgrid=False), yaxis=dict(showgrid=False))
    return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)

# ---------------- DASHBOARD HTML ----------------
HTML = """<html>
<head>
<title>RedShark Threat Intelligence Dashboard</title>
<script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
<link rel="stylesheet" href="https://cdn.datatables.net/1.13.4/css/jquery.dataTables.min.css">
<script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
<script src="https://cdn.datatables.net/1.13.4/js/jquery.dataTables.min.js"></script>
<style>
body{background:#0b1b2a;color:#A3B8CC;font-family:Arial;}
.card{background:#13263b;padding:20px;margin:15px;border-radius:8px;}
table{width:100%;border-collapse:collapse;}
td,th{padding:8px;border-bottom:1px solid #1f3d5c;text-align:center;}
a.download-link{color:#FFA500;font-weight:bold;text-decoration:none;}
.center{text-align:center;}
.blink {animation: blink-animation 1s infinite;color:#DC143C;font-weight:bold;}
@keyframes blink-animation {0% {opacity:1;}50% {opacity:0;}100% {opacity:1;}}
</style>
</head>
<body>
<h2>RedShark Threat Intelligence Dashboard</h2>

<div class="card">
SecureNation Index: <b>{{index}}</b>
</div>

<div class="card">
<h3>Latest Cyber Bulletin</h3>
<ul>
{% for b in bulletin %}
<li>{{b.indicator}} ({{b.type}}) – Severity: {{b.severity}}</li>
{% endfor %}
</ul>
</div>

<div class="card">
<h3>Malaysia Cyber Attack Map</h3>
<div id="map" style="height:400px;"></div>
</div>

<div class="card">
<h3>Threat Timeline</h3>
<div id="timeline" style="height:300px;"></div>
</div>

<div class="card">
<h3>MITRE ATT&CK Techniques</h3>
<div id="mitre" style="height:300px;"></div>
</div>

<div class="card">
<h3>Sector Targeting</h3>
<div id="sector" style="height:300px;"></div>
</div>

<div class="card">
<h3>Indicator Type Distribution</h3>
<div id="indicator_type" style="height:300px;"></div>
</div>

<div class="card">
<h3>Latest Threat Indicators</h3>
<table id="threat_table">
<thead>
<tr><th>ID</th><th>Indicator</th><th>Type</th><th>Sector</th><th>Severity</th></tr>
</thead>
<tbody>
{% for r in rows %}
<tr class="{{'blink' if r.severity>=85 else ''}}">
<td>{{r.id}}</td>
<td>{{r.indicator}}</td>
<td>{{r.type}}</td>
<td>{{r.sector}}</td>
<td>{{r.severity}}</td>
</tr>
{% endfor %}
</tbody>
</table>
</div>

<div class="card center">
<a class="download-link" href="/csv">Download CSV</a> |
<a class="download-link" href="/json">Download JSON</a> |
<a class="download-link" href="/pdf">Download PDF</a> |
<a class="download-link" href="/download_ips">Download IPS Signatures</a>
</div>

<p class="center" style="opacity:0.6;">
Developed and analyzed by darkgrid@redshark.my using publicly available threat intelligence sources
</p>

<script>
var timeline={{timeline|safe}};
var mitre={{mitre|safe}};
var sector={{sector|safe}};
var indicator_type={{indicator_type|safe}};
var map={{map|safe}};
Plotly.newPlot("timeline",timeline.data,timeline.layout);
Plotly.newPlot("mitre",mitre.data,mitre.layout);
Plotly.newPlot("sector",sector.data,sector.layout);
Plotly.newPlot("indicator_type",indicator_type.data,indicator_type.layout);
Plotly.newPlot("map",map.data,map.layout);

// Animate pulsing for critical red markers
var mapData = map.data[0];
var sizes = mapData.marker.size;
var growing = true;
setInterval(function(){
    for(var i=0;i<sizes.length;i++){
        if(mapData.marker.color[i]=="red"){
            sizes[i] = growing ? 25 : 18;
        }
    }
    mapData.marker.size = sizes;
    Plotly.redraw("map");
    growing = !growing;
}, 800);

$(document).ready(function(){ $('#threat_table').DataTable(); });
</script>
</body>
</html>
"""

@app.route("/")
def dashboard():
    rows=db().execute("SELECT * FROM threats ORDER BY id DESC LIMIT 50").fetchall()
    bulletin = rows[:5]  # top 5 latest threats
    return render_template_string(
        HTML,
        rows=rows,
        bulletin=bulletin,
        index=securenation(),
        timeline=timeline_chart(),
        mitre=mitre_chart(),
        sector=sector_chart(),
        indicator_type=indicator_type_chart(),
        map=malaysia_map()
    )

# ---------------- EXPORT ----------------
@app.route("/csv")
def csv_export():
    rows=db().execute("SELECT * FROM threats").fetchall()
    if not rows:
        return "No data to export", 404
    out=io.StringIO()
    writer=csv.writer(out)
    writer.writerow(rows[0].keys())
    for r in rows:
        writer.writerow(list(r))
    mem=io.BytesIO(); mem.write(out.getvalue().encode()); mem.seek(0)
    return send_file(mem,download_name="threats.csv",as_attachment=True)

@app.route("/json")
def json_export():
    rows=db().execute("SELECT * FROM threats").fetchall()
    data=[dict(r) for r in rows]
    mem=io.BytesIO(); mem.write(json.dumps(data,indent=2).encode()); mem.seek(0)
    return send_file(mem,download_name="threats.json",as_attachment=True)

@app.route("/pdf")
def pdf_export():
    rows=db().execute("SELECT indicator,type,sector,severity,created FROM threats LIMIT 50").fetchall()
    buffer=io.BytesIO()
    data=[["Indicator","Type","Sector","Severity","Timestamp"]]
    styles = getSampleStyleSheet()
    for r in rows:
        data.append([
            Paragraph(r["indicator"], styles['Normal']),
            r["type"], r["sector"], str(r["severity"]), r["created"]
        ])
    table = Table(data)
    table.setStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#1f3d5c")),
        ('TEXTCOLOR',(0,0),(-1,0),colors.white),
        ('ALIGN',(0,0),(-1,-1),'CENTER'),
        ('GRID',(0,0),(-1,-1),0.5,colors.gray),
        ('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'),
        ('BOTTOMPADDING',(0,0),(-1,0),8),
    ])
    pdf=SimpleDocTemplate(buffer,pagesize=landscape(A4), leftMargin=20, rightMargin=20)
    pdf.build([table])
    buffer.seek(0)
    return send_file(buffer,download_name="redshark-cti-report.pdf",as_attachment=True)

@app.route("/download_ips")
def download_ips():
    if not os.path.exists(RULE_FILE):
        open(RULE_FILE,"w").close()
    return send_file(RULE_FILE, download_name="redshark-ips-signatures.rules", as_attachment=True)

if __name__=="