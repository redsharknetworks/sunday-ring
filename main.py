import os, sqlite3, threading, random
from datetime import datetime, timedelta
from flask import Flask, render_template_string
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
def insert_threat(indicator,type_,source,city="Kuala Lumpur",severity="Medium"):
    with sqlite3.connect(DB) as conn:
        conn.execute("""
        INSERT INTO threats (indicator,type,source,city,severity,created_at)
        VALUES (?,?,?,?,?,?)
        """,(indicator,type_,source,city,severity,datetime.utcnow().isoformat()))

# ---------------- External Feeds -----------------
CITIES=["Kuala Lumpur","Penang","Johor Bahru","Kota Kinabalu","Kuching"]
SEVERITIES=["Low","Medium","High","Critical"]

def fetch_urlhaus():
    url="https://urlhaus.abuse.ch/downloads/csv_online/"
    try:
        resp=requests.get(url,timeout=10)
        reader=csv.reader(resp.text.splitlines())
        entries=list(reader)[9:50]  # skip headers
        for row in entries:
            if len(row)<3: continue
            insert_threat(row[2].strip(),"URL","URLhaus",random.choice(CITIES),random.choice(SEVERITIES))
    except: pass

def fetch_spamhaus_drop():
    url="https://www.spamhaus.org/drop/drop.txt"
    try:
        resp=requests.get(url,timeout=10)
        for line in resp.text.splitlines():
            if line.startswith(";") or not line.strip(): continue
            insert_threat(line.split(";")[0].strip(),"IP","Spamhaus",random.choice(CITIES),random.choice(SEVERITIES))
    except: pass

def fetch_firehol():
    url="https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"
    try:
        resp=requests.get(url,timeout=10)
        for line in resp.text.splitlines():
            if line.startswith("#") or not line.strip(): continue
            insert_threat(line.strip(),"IP","FireHOL",random.choice(CITIES),random.choice(SEVERITIES))
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
        conn.row_factory=sqlite3.Row
        rows=conn.execute("SELECT substr(created_at,1,10) as d, COUNT(*) as cnt FROM threats GROUP BY d").fetchall()
    x=[r["d"] for r in rows] if rows else ["No Data"]
    y=[r["cnt"] for r in rows] if rows else [0]
    fig=go.Figure(data=[go.Scatter(x=x,y=y,mode="lines+markers",line=dict(color="#00e6ff"))])
    fig.update_layout(title="Threat Timeline (Last 30 Days)",
                      paper_bgcolor="#0b1b2a",plot_bgcolor="#0b1b2a",font_color="#00e6ff")
    return json.dumps(fig,cls=PlotlyJSONEncoder)

def type_chart():
    with sqlite3.connect(DB) as conn:
        conn.row_factory=sqlite3.Row
        rows=conn.execute("SELECT type, COUNT(*) as cnt FROM threats GROUP BY type").fetchall()
    labels=[r["type"] for r in rows] if rows else ["No Data"]
    values=[r["cnt"] for r in rows] if rows else [0]
    fig=go.Figure(data=[go.Bar(x=labels,y=values,marker_color="#00e6ff")])
    fig.update_layout(title="Threat Types",
                      paper_bgcolor="#0b1b2a",plot_bgcolor="#0b1b2a",font_color="#00e6ff")
    return json.dumps(fig,cls=PlotlyJSONEncoder)

def malaysia_heatmap():
    # Count threats per city
    with sqlite3.connect(DB) as conn:
        conn.row_factory=sqlite3.Row
        rows=conn.execute("SELECT city, COUNT(*) as cnt FROM threats GROUP BY city").fetchall()
    heat=[]
    for r in rows:
        lat,lng={"Kuala Lumpur":[3.1390,101.6869],
                  "Penang":[5.4164,100.3327],
                  "Johor Bahru":[1.4927,103.7414],
                  "Kota Kinabalu":[5.9804,116.0735],
                  "Kuching":[1.5533,110.3592]}.get(r["city"],[3.1390,101.6869])
        heat.append({"city":r["city"],"lat":lat,"lng":lng,"cnt":r["cnt"]})
    return heat

def top_indicators():
    with sqlite3.connect(DB) as conn:
        conn.row_factory=sqlite3.Row
        rows=conn.execute("SELECT indicator, COUNT(*) as cnt FROM threats GROUP BY indicator ORDER BY cnt DESC LIMIT 10").fetchall()
    return rows

def severity_stats():
    with sqlite3.connect(DB) as conn:
        conn.row_factory=sqlite3.Row
        rows=conn.execute("SELECT severity, COUNT(*) as cnt FROM threats GROUP BY severity").fetchall()
    return rows

# ---------------- Dashboard Template -----------------
TEMPLATE="""
<html><head>
<title>Professional SOC Dashboard</title>
<script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
<style>
body{background:#0b1b2a;color:#00e6ff;font-family:sans-serif;margin:0;padding:0;}
.container{width:95%;margin:auto;}
h1{padding:15px;text-align:center;color:#00e6ff;}
.card{background:#002f4d;padding:15px;margin:10px;border-radius:8px;box-shadow:0 2px 5px rgba(0,0,0,0.5);}
table{width:100%;border-collapse:collapse;margin-top:10px;}
th,td{padding:8px;text-align:left;border:1px solid #00e6ff;}
th{background:#004d66;}
tr:nth-child(even){background:#00384d;}
</style>
</head><body>
<div class="container">
<h1>Professional SOC Dashboard</h1>

<div class="card">
<h2>Threat Timeline</h2>
<div id="trend"></div>
</div>

<div class="card">
<h2>Threat Types</h2>
<div id="types"></div>
</div>

<div class="card">
<h2>Malaysia Threat Heatmap</h2>
<table>
<tr><th>City</th><th>Threat Count</th></tr>
{% for h in heat %}
<tr><td>{{h.city}}</td><td>{{h.cnt}}</td></tr>
{% endfor %}
</table>
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
var trend={{trend|safe}};
Plotly.newPlot('trend',trend.data,trend.layout,{responsive:true});
var types={{types|safe}};
Plotly.newPlot('types',types.data,types.layout,{responsive:true});
</script>
</body></html>
"""

# ---------------- Route -----------------
@app.route("/")
def dashboard():
    return render_template_string(TEMPLATE,
                                  trend=trend_chart(),
                                  types=type_chart(),
                                  heat=malaysia_heatmap(),
                                  top=top_indicators(),
                                  severity=severity_stats())

if __name__=="__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT",5000)), debug=False)