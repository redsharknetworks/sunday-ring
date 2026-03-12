import os, sqlite3, random, threading
from datetime import datetime
from flask import Flask, render_template_string
import plotly.graph_objs as go
from plotly.utils import PlotlyJSONEncoder

app = Flask(__name__)
DB = "/tmp/soc.db"

# ----------------- Database -----------------
def init_db():
    with sqlite3.connect(DB) as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS threats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator TEXT,
            type TEXT,
            source TEXT,
            created_at TEXT,
            country TEXT
        )
        """)
init_db()

def insert_indicator(indicator, type_, source, country="MY"):
    with sqlite3.connect(DB) as conn:
        conn.execute("""
        INSERT INTO threats (indicator,type,source,created_at,country)
        VALUES (?,?,?,?,?)
        """,(indicator,type_,source,datetime.utcnow().isoformat(),country))

# ----------------- Feeds -----------------
def fetch_urlhaus():
    url="https://urlhaus.abuse.ch/downloads/csv_online/"
    try:
        import csv, requests
        resp=requests.get(url,timeout=10)
        reader=csv.reader(resp.text.splitlines())
        entries=list(reader)[9:100]  # skip headers, limit rows
        for row in entries:
            if len(row)<3: continue
            insert_indicator(row[2].strip(),"url","URLhaus")
    except: pass

def fetch_spamhaus_drop():
    url="https://www.spamhaus.org/drop/drop.txt"
    try:
        resp=requests.get(url,timeout=10)
        for line in resp.text.splitlines():
            if line.startswith(";") or not line.strip(): continue
            insert_indicator(line.split(";")[0].strip(),"ip","Spamhaus")
    except: pass

# Scheduler
def scheduler():
    while True:
        fetch_urlhaus()
        fetch_spamhaus_drop()
        threading.Event().wait(3600)
threading.Thread(target=scheduler,daemon=True).start()

# ----------------- Charts -----------------
def trend_chart():
    with sqlite3.connect(DB) as conn:
        conn.row_factory=sqlite3.Row
        rows=conn.execute("SELECT substr(created_at,1,10) as d, COUNT(*) as cnt FROM threats GROUP BY d").fetchall()
    x=[r["d"] for r in rows] if rows else ["No Data"]
    y=[r["cnt"] for r in rows] if rows else [0]
    fig=go.Figure(data=[go.Scatter(x=x,y=y,mode="lines+markers",line=dict(color="#00e6ff"))])
    fig.update_layout(title="Threat Timeline",paper_bgcolor="#0b1b2a",plot_bgcolor="#0b1b2a",font_color="#00e6ff")
    return fig

def type_chart():
    with sqlite3.connect(DB) as conn:
        conn.row_factory=sqlite3.Row
        rows=conn.execute("SELECT type, COUNT(*) as cnt FROM threats GROUP BY type").fetchall()
    labels=[r["type"] for r in rows] if rows else ["No Data"]
    values=[r["cnt"] for r in rows] if rows else [0]
    fig=go.Figure(data=[go.Bar(x=labels,y=values,marker_color="#00e6ff")])
    fig.update_layout(title="Threat Types",paper_bgcolor="#0b1b2a",plot_bgcolor="#0b1b2a",font_color="#00e6ff")
    return fig

# ----------------- Malaysia Heatmap -----------------
MALAYSIA_COORDS = {
    "Kuala Lumpur": [3.1390,101.6869],
    "Penang": [5.4164,100.3327],
    "Johor Bahru": [1.4927,103.7414],
    "Kota Kinabalu": [5.9804,116.0735],
    "Kuching": [1.5533,110.3592]
}

def malaysia_heatmap():
    with sqlite3.connect(DB) as conn:
        conn.row_factory=sqlite3.Row
        rows=conn.execute("SELECT country, COUNT(*) as cnt FROM threats GROUP BY country").fetchall()
    heat_data=[]
    for city,coords in MALAYSIA_COORDS.items():
        cnt = random.randint(1,15)  # demo random value if no real country mapping
        heat_data.append({"city":city,"lat":coords[0],"lng":coords[1],"cnt":cnt})
    return heat_data

# ----------------- Top Indicators -----------------
def top_indicators():
    with sqlite3.connect(DB) as conn:
        conn.row_factory=sqlite3.Row
        rows=conn.execute("SELECT indicator, COUNT(*) as cnt FROM threats GROUP BY indicator ORDER BY cnt DESC LIMIT 10").fetchall()
    return rows

# ----------------- Dashboard -----------------
TEMPLATE = """
<html><head>
<title>SOC Dashboard - Modern</title>
<script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
<style>
body{font-family:sans-serif;background:#0b1b2a;color:#00e6ff;margin:0;padding:0;}
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
<h1>Sunday-Ring SOC Dashboard</h1>

<div class="card">
<h2>Threat Timeline</h2>
<div id="trend"></div>
</div>

<div class="card">
<h2>Threat Types</h2>
<div id="types"></div>
</div>

<div class="card">
<h2>Malaysia Heatmap</h2>
<table>
<tr><th>City</th><th>Count</th></tr>
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
</div>

<script>
var trend={{trend|safe}};
Plotly.newPlot('trend',trend.data,trend.layout,{responsive:true});
var types={{types|safe}};
Plotly.newPlot('types',types.data,types.layout,{responsive:true});
</script>

</body></html>
"""

@app.route("/")
def dashboard():
    return render_template_string(TEMPLATE,
                                  trend=trend_chart().to_json(),
                                  types=type_chart().to_json(),
                                  heat=malaysia_heatmap(),
                                  top=top_indicators())

if __name__=="__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT",5000)), debug=False)