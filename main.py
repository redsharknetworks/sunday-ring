import os, sqlite3, threading, random
from datetime import datetime
from flask import Flask, render_template_string, request
import plotly.graph_objs as go
from plotly.utils import PlotlyJSONEncoder
import requests, csv, json

app = Flask(__name__)
DB="/tmp/soc.db"

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
            created_at TEXT
        )
        """)
init_db()

# ---------------- Insert Threat -----------------
CITIES=["Kuala Lumpur","Penang","Johor Bahru","Kota Kinabalu","Kuching"]
SEVERITIES=["Low","Medium","High","Critical"]

def insert_threat(indicator,type_,source,city=None,severity=None):
    city=city or random.choice(CITIES)
    severity=severity or random.choice(SEVERITIES)
    with sqlite3.connect(DB) as conn:
        conn.execute("""
        INSERT INTO threats (indicator,type,source,city,severity,created_at)
        VALUES (?,?,?,?,?,?)
        """,(indicator,type_,source,city,severity,datetime.utcnow().isoformat()))

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
def trend_chart(filter_sev=None, filter_type=None, filter_city=None):
    query="SELECT substr(created_at,1,10) as d, COUNT(*) as cnt FROM threats WHERE 1=1"
    params=[]
    if filter_sev: query+=" AND severity=?"; params.append(filter_sev)
    if filter_type: query+=" AND type=?"; params.append(filter_type)
    if filter_city: query+=" AND city=?"; params.append(filter_city)
    query+=" GROUP BY d"
    with sqlite3.connect(DB) as conn:
        conn.row_factory=sqlite3.Row
        rows=conn.execute(query, params).fetchall()
    x=[r["d"] for r in rows] if rows else ["No Data"]
    y=[r["cnt"] for r in rows] if rows else [0]
    fig=go.Figure(data=[go.Scatter(x=x,y=y,mode="lines+markers",line=dict(color="#00e6ff"))])
    fig.update_layout(title="Threat Timeline (Last 30 Days)",
                      paper_bgcolor="#0b1b2a",plot_bgcolor="#0b1b2a",font_color="#00e6ff")
    return json.dumps(fig,cls=PlotlyJSONEncoder)

def type_chart(filter_sev=None, filter_city=None):
    query="SELECT type, COUNT(*) as cnt FROM threats WHERE 1=1"
    params=[]
    if filter_sev: query+=" AND severity=?"; params.append(filter_sev)
    if filter_city: query+=" AND city=?"; params.append(filter_city)
    query+=" GROUP BY type"
    with sqlite3.connect(DB) as conn:
        conn.row_factory=sqlite3.Row
        rows=conn.execute(query, params).fetchall()
    labels=[r["type"] for r in rows] if rows else ["No Data"]
    values=[r["cnt"] for r in rows] if rows else [0]
    fig=go.Figure(data=[go.Bar(x=labels,y=values,marker_color="#00e6ff")])
    fig.update_layout(title="Threat Types",
                      paper_bgcolor="#0b1b2a",plot_bgcolor="#0b1b2a",font_color="#00e6ff")
    return json.dumps(fig,cls=PlotlyJSONEncoder)

# ---------------- Malaysia Bubble Map -----------------
CITY_COORDS={
    "Kuala Lumpur":[3.1390,101.6869],
    "Penang":[5.4164,100.3327],
    "Johor Bahru":[1.4927,103.7414],
    "Kota Kinabalu":[5.9804,116.0735],
    "Kuching":[1.5533,110.3592]
}

def heatmap_chart(filter_sev=None, filter_type=None):
    query="SELECT city, severity, COUNT(*) as cnt FROM threats WHERE 1=1"
    params=[]
    if filter_sev: query+=" AND severity=?"; params.append(filter_sev)
    if filter_type: query+=" AND type=?"; params.append(filter_type)
    query+=" GROUP BY city,severity"
    with sqlite3.connect(DB) as conn:
        conn.row_factory=sqlite3.Row
        rows=conn.execute(query, params).fetchall()
    lats,lons,sizes,colors,texts=[],[],[],[],[]
    color_map={"Low":"#00ff00","Medium":"#ffff00","High":"#ff8000","Critical":"#ff0000"}
    for r in rows:
        lat,lng=CITY_COORDS.get(r["city"],[3.1390,101.6869])
        lats.append(lat)
        lons.append(lng)
        sizes.append(r["cnt"]*8)
        colors.append(color_map.get(r["severity"],"#00e6ff"))
        texts.append(f"{r['city']}<br>{r['severity']}: {r['cnt']} threats")
    fig=go.Figure()
    for i,(lat,lon,size,color,text) in enumerate(zip(lats,lons,sizes,colors,texts)):
        fig.add_trace(go.Scattermapbox(lat=[lat],lon=[lon],mode="markers",
                                       marker=go.scattermapbox.Marker(size=size,color=color,opacity=0.7),
                                       text=text, hoverinfo="text"))
    fig.update_layout(mapbox_style="open-street-map", mapbox_zoom=5, mapbox_center={"lat":4.2,"lon":101.9758})
    fig.update_layout(paper_bgcolor="#0b1b2a",plot_bgcolor="#0b1b2a",font_color="#00e6ff",margin=dict(l=0,r=0,t=0,b=0))
    return json.dumps(fig,cls=PlotlyJSONEncoder)

# ---------------- Top indicators & Severity stats -----------------
def top_indicators(filter_city=None):
    query="SELECT indicator, COUNT(*) as cnt FROM threats WHERE 1=1"
    params=[]
    if filter_city: query+=" AND city=?"; params.append(filter_city)
    query+=" GROUP BY indicator ORDER BY cnt DESC LIMIT 10"
    with sqlite3.connect(DB) as conn:
        conn.row_factory=sqlite3.Row
        return conn.execute(query, params).fetchall()

def severity_stats(filter_city=None):
    query="SELECT severity, COUNT(*) as cnt FROM threats WHERE 1=1"
    params=[]
    if filter_city: query+=" AND city=?"; params.append(filter_city)
    query+=" GROUP BY severity"
    with sqlite3.connect(DB) as conn:
        conn.row_factory=sqlite3.Row
        return conn.execute(query, params).fetchall()

# ---------------- SecureNation Index -----------------
def secure_index():
    with sqlite3.connect(DB) as conn:
        conn.row_factory=sqlite3.Row
        rows=conn.execute("SELECT severity FROM threats").fetchall()
    if not rows: return 0
    severity_weight={"Low":0.2,"Medium":0.5,"High":0.7,"Critical":1.0}
    score=sum([severity_weight.get(r["severity"],0.5) for r in rows])
    return round(score/len(rows)*100,1)

# ---------------- Dashboard Template -----------------
TEMPLATE="""
<html><head>
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
</head><body>
<div class="container">
<h1>Sunday-Ring Professional SOC Dashboard</h1>

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
<h2>Malaysia Threat Bubble Map</h2>
<div id="heatmap" style="height:500px;"></div>
</div>

<div class="card">
<h2>Top 10 Indicators</h2>
<table>
<tr><th>Indicator</th><th>Count</th></tr>
{% for t in top %}
<tr><td>{{t['indicator']}}</td><td>{{t['cnt']}}</td></tr>
{% endfor %}
</table>
</div>

<div class="card">
<h2>Severity Stats</h2>
<table>
<tr><th>Severity</th><th>Count</th></tr>
{% for s in severity %}
<tr><td>{{s['severity']}}</td><td>{{s['cnt']}}</td></tr>
{% endfor %}
</table>
</div>

</div>

<script>
Plotly.newPlot('trend', {{trend|safe}}.data, {{trend|safe}}.layout, {responsive:true});
Plotly.newPlot('types', {{types|safe}}.data, {{types|safe}}.layout, {responsive:true});
Plotly.newPlot('heatmap', {{heatmap|safe}}.data, {{heatmap|safe}}.layout, {responsive:true});
</script>
</body></html>
"""

# ---------------- Route -----------------
@app.route("/")
def dashboard():
    filter_city=request.args.get("city")
    filter_sev=request.args.get("severity")
    filter_type=request.args.get("type")
    return render_template_string(
        TEMPLATE,
        index=secure_index(),
        trend=trend_chart(filter_sev,filter_type,filter_city),
        types=type_chart(filter_sev,filter_city),
        heatmap=heatmap_chart(filter_sev,filter_type),
        top=top_indicators(filter_city),
        severity=severity_stats(filter_city)
    )

if __name__=="__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT",5000)), debug=False)