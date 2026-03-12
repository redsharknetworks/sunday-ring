import os, sqlite3, threading, random
from datetime import datetime
from flask import Flask, render_template_string
import requests, csv, json
import plotly.graph_objs as go
from plotly.utils import PlotlyJSONEncoder

app = Flask(__name__)
DB = "/tmp/soc.db"

# ---------------- Database -----------------
def init_db():
    with sqlite3.connect(DB) as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS threats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator TEXT,
            type TEXT,
            source TEXT,
            city TEXT,
            severity TEXT,
            mitre TEXT,
            created_at TEXT
        )
        """)

init_db()

# ---------------- Cities / States & Severity -----------------
MALAYSIA_STATES = {
    "Johor": [1.4927,103.7414],
    "Kedah": [6.1164,100.3678],
    "Kelantan": [6.1254,102.2381],
    "Melaka": [2.1896,102.2501],
    "Negeri Sembilan": [2.7290,101.9383],
    "Pahang": [3.8167,103.3333],
    "Perak": [4.5929,101.0900],
    "Perlis": [6.4400,100.2000],
    "Penang": [5.4164,100.3327],
    "Sabah": [5.9804,116.0735],
    "Sarawak": [1.5533,110.3592],
    "Selangor": [3.1390,101.6869],
    "Terengganu": [5.3300,103.1400],
    "Kuala Lumpur": [3.1390,101.6869],
    "Putrajaya": [2.9264,101.6981],
    "Labuan": [5.2833,115.2333]
}

SEVERITIES = ["Low","Medium","High","Critical"]

MITRE_TACTICS = ["Reconnaissance","Initial Access","Execution","Persistence","Privilege Escalation",
                 "Defense Evasion","Credential Access","Discovery","Lateral Movement",
                 "Collection","Exfiltration","Command and Control"]

# ---------------- Insert Threat -----------------
def insert_threat(indicator, type_, source, city=None, severity=None, mitre=None):
    city = city or random.choice(list(MALAYSIA_STATES.keys()))
    severity = severity or random.choice(SEVERITIES)
    mitre = mitre or random.choice(MITRE_TACTICS)
    with sqlite3.connect(DB) as conn:
        conn.execute("""
        INSERT INTO threats (indicator,type,source,city,severity,mitre,created_at)
        VALUES (?,?,?,?,?,?,?)
        """,(indicator,type_,source,city,severity,mitre,datetime.utcnow().isoformat()))

# ---------------- External Feeds -----------------
def fetch_urlhaus():
    url="https://urlhaus.abuse.ch/downloads/csv_online/"
    try:
        resp=requests.get(url,timeout=10)
        reader=csv.reader(resp.text.splitlines())
        entries=list(reader)[9:50]
        for row in entries:
            if len(row)<3: continue
            insert_threat(row[2].strip(),"URL","URLhaus")
    except: pass

def fetch_spamhaus_drop():
    url="https://www.spamhaus.org/drop/drop.txt"
    try:
        resp=requests.get(url,timeout=10)
        for line in resp.text.splitlines():
            if line.startswith(";") or not line.strip(): continue
            insert_threat(line.split(";")[0].strip(),"IP","Spamhaus")
    except: pass

def fetch_firehol():
    url="https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"
    try:
        resp=requests.get(url,timeout=10)
        for line in resp.text.splitlines():
            if line.startswith("#") or not line.strip(): continue
            insert_threat(line.strip(),"IP","FireHOL")
    except: pass

# ---------------- Scheduler -----------------
def scheduler():
    while True:
        fetch_urlhaus()
        fetch_spamhaus_drop()
        fetch_firehol()
        threading.Event().wait(3600)

threading.Thread(target=scheduler,daemon=True).start()

# ---------------- Charts -----------------
def trend_chart():
    with sqlite3.connect(DB) as conn:
        conn.row_factory = sqlite3.Row
        rows=conn.execute("SELECT substr(created_at,1,10) as d, COUNT(*) as cnt FROM threats GROUP BY d").fetchall()
    x=[r["d"] for r in rows] if rows else ["No Data"]
    y=[r["cnt"] for r in rows] if rows else [0]
    fig=go.Figure(data=[go.Scatter(x=x,y=y,mode="lines+markers",line=dict(color="#00e6ff"))])
    fig.update_layout(title="Threat Timeline (Last 30 Days)",
                      paper_bgcolor="#0b1b2a",plot_bgcolor="#0b1b2a",font_color="#00e6ff")
    return json.dumps(fig,cls=PlotlyJSONEncoder)

def type_chart():
    with sqlite3.connect(DB) as conn:
        conn.row_factory = sqlite3.Row
        rows=conn.execute("SELECT type, COUNT(*) as cnt FROM threats GROUP BY type").fetchall()
    labels=[r["type"] for r in rows] if rows else ["No Data"]
    values=[r["cnt"] for r in rows] if rows else [0]
    fig=go.Figure(data=[go.Bar(x=labels,y=values,marker_color="#00e6ff")])
    fig.update_layout(title="Threat Types",
                      paper_bgcolor="#0b1b2a",plot_bgcolor="#0b1b2a",font_color="#00e6ff")
    return json.dumps(fig,cls=PlotlyJSONEncoder)

def severity_chart():
    with sqlite3.connect(DB) as conn:
        conn.row_factory = sqlite3.Row
        rows=conn.execute("SELECT severity, COUNT(*) as cnt FROM threats GROUP BY severity").fetchall()
    labels=[r["severity"] for r in rows] if rows else ["No Data"]
    values=[r["cnt"] for r in rows] if rows else [0]
    fig=go.Figure(data=[go.Pie(labels=labels, values=values, marker_colors=["#00ff00","#ffff00","#ff8000","#ff0000"])])
    fig.update_layout(title="Severity Distribution",
                      paper_bgcolor="#0b1b2a",plot_bgcolor="#0b1b2a",font_color="#00e6ff")
    return json.dumps(fig,cls=PlotlyJSONEncoder)

# ---------------- Malaysia Heatmap -----------------
def malaysia_heatmap():
    with sqlite3.connect(DB) as conn:
        conn.row_factory = sqlite3.Row
        rows=conn.execute("SELECT city,severity,COUNT(*) as cnt FROM threats GROUP BY city,severity").fetchall()
    lats,lons,sizes,colors,texts=[],[],[],[],[]
    color_map={"Low":"#00ff00","Medium":"#ffff00","High":"#ff8000","Critical":"#ff0000"}
    for r in rows:
        lat,lng=MALAYSIA_STATES.get(r["city"],[3.1390,101.6869])
        lats.append(lat); lons.append(lng)
        sizes.append(r["cnt"]*10)
        colors.append(color_map.get(r["severity"],"#00e6ff"))
        texts.append(f"{r['city']} - {r['severity']}: {r['cnt']} threats")
    fig=go.Figure()
    for lat,lon,size,color,text in zip(lats,lons,sizes,colors,texts):
        fig.add_trace(go.Scattermapbox(lat=[lat],lon=[lon],mode="markers",
                                       marker=go.scattermapbox.Marker(size=size,color=color,opacity=0.7),
                                       text=text,hoverinfo="text"))
    fig.update_layout(mapbox_style="open-street-map",
                      mapbox_zoom=5,mapbox_center={"lat":4.2,"lon":101.9758},
                      paper_bgcolor="#0b1b2a",plot_bgcolor="#0b1b2a",font_color="#00e6ff",
                      margin=dict(l=0,r=0,t=0,b=0))
    return json.dumps(fig,cls=PlotlyJSONEncoder)

# ---------------- Top Indicators -----------------
def top_indicators(limit=10):
    with sqlite3.connect(DB) as conn:
        conn.row_factory = sqlite3.Row
        return conn.execute("SELECT indicator,type,severity,mitre,COUNT(*) as cnt FROM threats GROUP BY indicator ORDER BY cnt DESC LIMIT ?",(limit,)).fetchall()

# ---------------- SecureNation Index -----------------
def secure_index():
    with sqlite3.connect(DB) as conn:
        conn.row_factory = sqlite3.Row
        rows=conn.execute("SELECT severity FROM threats").fetchall()
    if not rows: return 0
    weight={"Low":0.2,"Medium":0.5,"High":0.7,"Critical":1.0}
    score=sum([weight.get(r["severity"],0.5) for r in rows])
    return round(score/len(rows)*100,1)

# ---------------- Dashboard Template -----------------
TEMPLATE="""
<html>
<head>
<title>Sunday-Ring Professional SOC Dashboard</title>
<script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
<style>
body{background:#0b1b2a;color:#00e6ff;font-family:sans-serif;margin:0;padding:0;}
.container{width:95%;margin:auto;}
h1,h2{padding:10px;text-align:center;color:#00e6ff;}
.card{background:#002f4d;padding:15px;margin:10px;border-radius:8px;box-shadow:0 2px 5px rgba(0,0,0,0.5);}
table{width:100%;border-collapse:collapse;margin-top:10px;}
th,td{padding:8px;text-align:left;border:1px solid #00e6ff;}
th{background:#004d66;}
tr:nth-child(even){background:#00384d;}
</style>
</head>
<body>
<div class="container">
<h1>RedShark Threat Intelligence Dashboard</h1>
<div class="card">
<h2>SecureNation Index: {{index}}/100</h2>
<div style="background:#004d66;width:300px;height:25px;border-radius:5px;">
  <div style="height:25px;width:{{index}}%;background:#00e6ff;text-align:center;color:#0b1b2a;font-weight:bold;">{{index}}/100</div>
</div>
</div>

<div class="card">
<h2>Threat Timeline</h2>
<div id="trend"></div>
</div>

<div class="card">
<h2>Threat Types</h2>
<div id="types"></div>
</div>

<div class="card">
<h2>Severity Distribution</h2>
<div id="severity"></div>
</div>

<div class="card">
<h2>Malaysia Threat Heatmap</h2>
<div id="heatmap" style="height:500px;"></div>
</div>

<div class="card">
<h2>Top Indicators</h2>
<table>
<tr><th>Indicator</th><th>Type</th><th>Severity</th><th>MITRE</th><th>Count</th></tr>
{% for t in top %}
<tr><td>{{t['indicator']}}</td><td>{{t['type']}}</td><td>{{t['severity']}}</td><td>{{t['mitre']}}</td><td>{{t['cnt']}}</td></tr>
{% endfor %}
</table>
</div>

</div>
<script>
Plotly.newPlot('trend', {{trend|safe}}.data, {{trend|safe}}.layout,{responsive:true});
Plotly.newPlot('types', {{types|safe}}.data, {{types|safe}}.layout,{responsive:true});
Plotly.newPlot('severity', {{severity|safe}}.data, {{severity|safe}}.layout,{responsive:true});
Plotly.newPlot('heatmap', {{heatmap|safe}}.data, {{heatmap|safe}}.layout,{responsive:true});
</script>
</body>
</html>
"""

# ---------------- Route -----------------
@app.route("/")
def dashboard():
    return render_template_string(
        TEMPLATE,
        index=secure_index(),
        trend=trend_chart(),
        types=type_chart(),
        severity=severity_chart(),
        heatmap=malaysia_heatmap(),
        top=top_indicators()
    )

# ---------------- Start -----------------
if __name__=="__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT",5000)), debug=False)