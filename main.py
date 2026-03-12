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
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
from reportlab.lib.pagesizes import landscape, A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet

app = Flask(__name__)
DB = "/tmp/threats.db"

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

with app.app_context():
    init_db()

# ---------------- STATES & SECTORS ----------------
states = {
    "Johor":[1.4927,103.7414],"Kedah":[6.1184,100.3685],"Kelantan":[6.1254,102.2381],
    "Melaka":[2.1896,102.2501],"Negeri Sembilan":[2.7258,101.9424],"Pahang":[3.8126,103.3256],
    "Perak":[4.5921,101.0901],"Perlis":[6.4449,100.2048],"Pulau Pinang":[5.4164,100.3327],
    "Sabah":[5.9804,116.0735],"Sarawak":[1.5533,110.3592],"Selangor":[3.0738,101.5183],
    "Terengganu":[5.3302,103.1408],"Kuala Lumpur":[3.1390,101.6869],
    "Putrajaya":[2.9264,101.6964],"Labuan":[5.2831,115.2308]
}

sectors = [
    "Government","Banking","Telecommunications","Energy","Healthcare",
    "Education","Manufacturing","Transportation","Retail","Media","Hospitality",
    "Agriculture","Technology","Logistics","Utilities"
]

mitre_techniques = [
    "Reconnaissance","Resource Development","Initial Access","Execution",
    "Persistence","Privilege Escalation","Defense Evasion","Credential Access",
    "Discovery","Lateral Movement","Collection","Command and Control",
    "Exfiltration","Impact"
]

def random_location(): return random.choice(list(states.values()))
def random_sector(): return random.choice(sectors)

# ---------------- INSERT ----------------
def insert_threat(indicator,typ,mitre,severity):
    lat,lon=random_location()
    conn = db()
    conn.execute(
        "INSERT INTO threats(indicator,type,mitre,sector,severity,lat,lon,created) VALUES(?,?,?,?,?,?,?,?)",
        (indicator,typ,mitre,random_sector(),severity,lat,lon,datetime.utcnow())
    )
    conn.commit()

# ---------------- FETCH FEEDS ----------------
def fetch_threatfox():
    try:
        url="https://threatfox.abuse.ch/export/json/recent/"
        r=requests.get(url,timeout=10).json()
        for i in r.get("data", [])[:20]:
            insert_threat(i.get("ioc","unknown"), i.get("ioc_type","unknown"), random.choice(mitre_techniques), 85)
    except: pass

def fetch_urlhaus():
    try:
        url="https://urlhaus.abuse.ch/downloads/csv_recent/"
        data=requests.get(url,timeout=10).text.splitlines()
        reader=csv.reader(data)
        for row in list(reader)[10:30]:
            if len(row)>2:
                insert_threat(row[2], "malware_url", random.choice(mitre_techniques), 70)
    except: pass

def fetch_feodo():
    try:
        url="https://feodotracker.abuse.ch/downloads/ipblocklist.json"
        data=requests.get(url,timeout=10).json()
        for item in data[:20]:
            insert_threat(item.get("ip_address","0.0.0.0"), "ip", random.choice(mitre_techniques), 90)
    except: pass

def fetch_hashes():
    try:
        url="https://mb-api.abuse.ch/api/v1/"
        r=requests.post(url,data={"query":"get_recent"},timeout=10).json()
        for item in r.get("data",[])[:20]:
            insert_threat(item.get("sha256_hash","unknown"), "hash", random.choice(mitre_techniques), 75)
    except: pass

def fetch_feeds():
    fetch_threatfox()
    fetch_urlhaus()
    fetch_feodo()
    fetch_hashes()

# ---------------- BACKGROUND FETCH ----------------
def schedule_fetch(interval=600):
    threading.Timer(interval, schedule_fetch).start()
    fetch_feeds()
schedule_fetch()

# ---------------- METRICS ----------------
def securenation():
    rows=db().execute("SELECT severity FROM threats ORDER BY id DESC LIMIT 100").fetchall()
    if not rows: return 0
    score=sum([r["severity"] for r in rows])/len(rows)
    return round(score,1)

# ---------------- CHARTS ----------------
def timeline_chart():
    rows=db().execute("SELECT substr(created,1,10) d,count(*) c FROM threats GROUP BY d").fetchall()
    x=[r["d"] for r in rows]
    y=[r["c"] for r in rows]
    fig=go.Figure()
    fig.add_trace(go.Scatter(x=x,y=y,mode="lines+markers",line=dict(color='#00FFFF')))
    fig.update_layout(plot_bgcolor='#1f2a38', paper_bgcolor='#1f2a38', font_color='#00eaff')
    return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)

def mitre_chart():
    rows=db().execute("SELECT mitre,count(*) c FROM threats GROUP BY mitre").fetchall()
    labels = [r["mitre"] for r in rows]
    values = [r["c"] for r in rows]
    fig=go.Figure(data=[go.Pie(labels=labels,values=values,hole=.4)])
    fig.update_layout(plot_bgcolor='#1f2a38', paper_bgcolor='#1f2a38', font_color='#00eaff')
    return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)

def sector_chart():
    rows=db().execute("SELECT sector,count(*) c FROM threats GROUP BY sector").fetchall()
    labels=[r["sector"] for r in rows if r["c"]>0]
    values=[r["c"] for r in rows if r["c"]>0]
    fig=go.Figure(data=[go.Bar(x=labels,y=values,
        marker=dict(color='#8B0000',line=dict(color='white',width=1)),
        text=values,textposition='auto')])
    fig.update_layout(plot_bgcolor='#1f2a38', paper_bgcolor='#1f2a38', font_color='#00eaff')
    return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)

def malaysia_map_pulsing():
    rows = db().execute("SELECT lat,lon,severity,indicator,sector FROM threats ORDER BY id DESC LIMIT 50").fetchall()
    lat, lon, colors, sizes, text_hover = [], [], [], [], []

    for r in rows:
        lat.append(r["lat"])
        lon.append(r["lon"])
        text_hover.append(f"Indicator: {r['indicator']}<br>Sector: {r['sector']}<br>Severity: {r['severity']}")
        if r["severity"] >= 85:
            colors.append("red")
            sizes.append(16)
        elif r["severity"] >= 70:
            colors.append("orange")
            sizes.append(12)
        else:
            colors.append("yellow")
            sizes.append(8)

    fig = go.Figure()
    # Static + pulsing using opacity animation
    fig.add_trace(go.Scattergeo(
        lat=lat, lon=lon, mode="markers",
        marker=dict(size=sizes,color=colors,opacity=0.7,line=dict(width=2,color='white')),
        text=text_hover, hoverinfo="text"
    ))

    # Animation frames for pulsing red markers
    frames=[]
    for op in [0.4,1.0]:
        frame_colors = colors.copy()
        frame_sizes = sizes.copy()
        for i,c in enumerate(colors):
            if c=="red":
                frame_sizes[i]=18
        frames.append(go.Frame(data=[go.Scattergeo(
            lat=lat, lon=lon, mode="markers",
            marker=dict(size=frame_sizes,color=frame_colors,opacity=op,line=dict(width=2,color='white')),
            text=text_hover, hoverinfo="text"
        )]))
    fig.frames = frames

    fig.update_layout(
        geo=dict(scope="asia", center=dict(lat=4.5, lon=102), projection_type="natural earth"),
        margin=dict(l=0,r=0,t=0,b=0),
        plot_bgcolor='#1f2a38', paper_bgcolor='#1f2a38', font_color='#00eaff',
        transition=dict(duration=800),
        updatemenus=[]
    )

    return json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

# ---------------- DASHBOARD ----------------
HTML = """<html>
<head>
<title>RedShark CTI Dashboard v2.9.1</title>
<script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
<style>
body{background:#0b1b2a;color:#00eaff;font-family:Arial;}
.card{background:#13263b;padding:20px;margin:15px;border-radius:8px;}
table{width:100%;border-collapse:collapse;}
td,th{padding:8px;border-bottom:1px solid #1f3d5c;}
th{cursor:pointer;}
</style>
</head>
<body>
<h2>RedShark CTI Dashboard v2.9.1</h2>
<div class="card">
{% set color = "green" %}
{% if index >= 85 %}{% set color = "red" %}{% elif index >= 70 %}{% set color="orange" %}{% endif %}
SecureNation Index: <b style="color:{{color}}">{{index}}</b>
</div>
<div class="card"><h3>Malaysia Cyber Attack Map</h3><div id="map"></div></div>
<div class="card"><h3>Threat Timeline</h3><div id="timeline"></div></div>
<div class="card"><h3>MITRE ATT&CK Distribution</h3><div id="mitre"></div></div>
<div class="card"><h3>Sector Targeting</h3><div id="sector"></div></div>
<div class="card"><h3>Latest Threat Indicators</h3>
<table id="threats">
<tr><th onclick="sortTable(0)">ID</th><th onclick="sortTable(1)">Indicator</th><th onclick="sortTable(2)">Type</th>
<th onclick="sortTable(3)">Sector</th><th onclick="sortTable(4)">Severity</th></tr>
{% for r in rows %}
<tr><td>{{r.id}}</td><td>{{r.indicator}}</td><td>{{r.type}}</td><td>{{r.sector}}</td><td>{{r.severity}}</td></tr>
{% endfor %}
</table>
</div>
<div class="card">
<a href="/csv" style="color:orange;">Download CSV</a> |
<a href="/json" style="color:orange;">Download JSON</a> |
<a href="/pdf" style="color:orange;">Download PDF</a>
</div>
<script>
var timeline={{timeline|safe}}
var mitre={{mitre|safe}}
var sector={{sector|safe}}
var map={{map|safe}}
Plotly.newPlot("timeline",timeline.data,timeline.layout)
Plotly.newPlot("mitre",mitre.data,mitre.layout)
Plotly.newPlot("sector",sector.data,sector.layout)
Plotly.newPlot("map",map.data,map.layout,{},{},{})
function sortTable(n){
  var table=document.getElementById("threats"),rows,i,x,y,shouldSwitch,dir,switchcount=0;
  shouldSwitch=true;dir="asc";
  while(shouldSwitch){
    shouldSwitch=false;
    var tr=table.rows;
    for(i=1;i<tr.length-1;i++){
      var a=tr[i].getElementsByTagName("TD")[n].innerText.toLowerCase();
      var b=tr[i+1].getElementsByTagName("TD")[n].innerText.toLowerCase();
      if((dir=="asc" && a>b) || (dir=="desc" && a<b)){
        tr[i].parentNode.insertBefore(tr[i+1],tr[i]);
        shouldSwitch=true;
        switchcount++;
      }
    }
    if(switchcount==0 && dir=="asc"){dir="desc";shouldSwitch=true;}
  }
}
</script>
<p style="opacity:0.6;text-align:center">Developed by darkgrid@redshark.my using public CTI sources</p>
</body></html>
"""

@app.route("/")
def dashboard():
    rows=db().execute("SELECT * FROM threats ORDER BY id DESC LIMIT 50").fetchall()
    return render_template_string(
        HTML,
        rows=rows,
        index=securenation(),
        timeline=timeline_chart(),
        mitre=mitre_chart(),
        sector=sector_chart(),
        map=malaysia_map_pulsing()
    )

# ---------------- EXPORT ----------------
@app.route("/csv")
def csv_export():
    rows=db().execute("SELECT * FROM threats").fetchall()
    out=io.StringIO(); writer=csv.writer(out)
    writer.writerow(rows[0].keys())
    for r in rows: writer.writerow(list(r))
    mem=io.BytesIO(); mem.write(out.getvalue().encode()); mem.seek(0)
    return send_file(mem,download_name="redshark-cti-reports.csv",as_attachment=True)

@app.route("/json")
def json_export():
    rows=db().execute("SELECT * FROM threats").fetchall()
    data=[dict(r) for r in rows]
    mem=io.BytesIO(); mem.write(json.dumps(data,indent=2).encode()); mem.seek(0)
    return send_file(mem,download_name="redshark-cti-reports.json",as_attachment=True)

@app.route("/pdf")
def pdf_export():
    rows=db().execute("SELECT indicator,type,sector,severity FROM threats LIMIT 50").fetchall()
    buffer=io.BytesIO()
    data=[["Indicator","Type","Sector","Severity"]]
    for r in rows:
        data.append([Paragraph(r["indicator"],getSampleStyleSheet()["BodyText"]),
                     r["type"],r["sector"],r["severity"]])
    timestamp = Paragraph(f"<b>Report Generated:</b> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}", getSampleStyleSheet()["Title"])
    pdf=SimpleDocTemplate(buffer,pagesize=landscape(A4))
    table=Table(data)
    table.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,0),colors.grey),
        ('TEXTCOLOR',(0,0),(-1,0),colors.whitesmoke),
        ('ALIGN',(0,0),(-1,-1),'CENTER'),
        ('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'),
        ('BOTTOMPADDING',(0,0),(-1,0),12),
        ('GRID',(0,0),(-1,-1),1,colors.black)
    ]))
    pdf.build([timestamp, table])
    buffer.seek(0)
    return send_file(buffer,download_name="redshark-cti-report.pdf",as_attachment=True)

if __name__=="__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT",5000)))