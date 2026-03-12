import os, sqlite3, random, threading, csv, io, json
from datetime import datetime
from flask import Flask, render_template_string, send_file
import plotly.graph_objs as go
from plotly.utils import PlotlyJSONEncoder
import requests

app = Flask(__name__)
DB="/tmp/soc.db"

# -----------------------------------
# Initialize SQLite DB
# -----------------------------------
def init_db():
    conn=sqlite3.connect(DB)
    c=conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS threats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        indicator TEXT,
        type TEXT,
        source TEXT,
        created_at TEXT
    )
    """)
    conn.commit()
    conn.close()

init_db()

# -----------------------------------
# Insert Threat Helpers
# -----------------------------------
def insert_indicator(indicator, type_, source):
    conn=sqlite3.connect(DB)
    c=conn.cursor()
    c.execute("""
    INSERT INTO threats (indicator,type,source,created_at)
    VALUES (?, ?, ?, ?)
    """, (indicator, type_, source, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()

# -----------------------------------
# Real External Feeds (no API keys)
# -----------------------------------
def fetch_spamhaus_drop():
    url="https://www.spamhaus.org/drop/drop.txt"
    try:
        resp=requests.get(url,timeout=10)
        for line in resp.text.splitlines():
            if line.startswith(";") or not line.strip():
                continue
            # IP or network block
            indicator=line.split(";")[0].strip()
            insert_indicator(indicator,"ip","Spamhaus DROP")
    except Exception as e:
        print("Spamhaus error:",e)

def fetch_urlhaus():
    url="https://urlhaus.abuse.ch/downloads/csv_online/"
    try:
        resp=requests.get(url,timeout=10)
        reader=csv.reader(resp.text.splitlines())
        entries=list(reader)[9:200]  # skip header, limit rows
        for row in entries:
            if len(row)<3: continue
            url=row[2].strip()
            if not url: continue
            insert_indicator(url,"url","URLhaus")
    except Exception as e:
        print("URLhaus error:",e)

# FireHOL IP Blocklists (example)
def fetch_firehol_ip():
    url="https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"
    try:
        resp=requests.get(url,timeout=10)
        for line in resp.text.splitlines():
            if line.startswith("#") or not line.strip():
                continue
            insert_indicator(line.strip(),"ip","FireHOL")
    except Exception as e:
        print("FireHOL error:",e)

# -----------------------------------
# Scheduler Ingestion
# -----------------------------------
def scheduled_feeds():
    while True:
        fetch_spamhaus_drop()
        fetch_urlhaus()
        fetch_firehol_ip()
        threading.Event().wait(3600)   # every hour

threading.Thread(target=scheduled_feeds,daemon=True).start()

# -----------------------------------
# Plotly Charts
# -----------------------------------
def heatmap_data():
    conn=sqlite3.connect(DB)
    conn.row_factory=sqlite3.Row
    c=conn.cursor()
    rows=c.execute("""
    SELECT type, COUNT(*) AS cnt
    FROM threats GROUP BY type
    """).fetchall()
    conn.close()
    labels=[r["type"] for r in rows]
    values=[r["cnt"] for r in rows]
    fig=go.Figure(data=[go.Bar(x=labels,y=values,marker_color="red")])
    fig.update_layout(title="Threats by Type",paper_bgcolor="#0b1b2a",font_color="#00FFFF")
    return json.dumps(fig,cls=PlotlyJSONEncoder)

def trend_data():
    conn=sqlite3.connect(DB)
    conn.row_factory=sqlite3.Row
    c=conn.cursor()
    rows=c.execute("""
    SELECT substr(created_at,1,10) AS d, COUNT(*) AS cnt
    FROM threats GROUP BY d
    """).fetchall()
    conn.close()
    x=[r["d"] for r in rows]
    y=[r["cnt"] for r in rows]
    if not x: x=["No Data"]
    if not y: y=[0]
    fig=go.Figure(data=[go.Scatter(x=x,y=y,mode="lines+markers",line=dict(color="#00FFFF"))])
    fig.update_layout(title="Threat Timeline",paper_bgcolor="#0b1b2a",font_color="#00FFFF")
    return json.dumps(fig,cls=PlotlyJSONEncoder)

def top_indicators():
    conn=sqlite3.connect(DB)
    conn.row_factory=sqlite3.Row
    c=conn.cursor()
    rows=c.execute("""
    SELECT indicator, COUNT(*) AS cnt
    FROM threats
    GROUP BY indicator
    ORDER BY cnt DESC
    LIMIT 10
    """).fetchall()
    conn.close()
    return rows

# -----------------------------------
# Dashboard Template
# -----------------------------------
DASHBOARD_HTML = """
<html><head><title>SOC Dashboard</title>
<script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
<style>
body{background:#0b1b2a;color:#00FFFF;font-family:sans-serif;padding:15px;}
table{width:100%;border-collapse:collapse;margin-top:20px;}
th,td{border:1px solid #00FFFF;padding:6px;}
th{background:#00274d;}
</style></head><body>

<h1>Sunday‑Ring SOC Dashboard</h1>

<div id="heatmap"></div>
<div id="trend"></div>

<h3>Top 10 Indicators</h3>
<table>
<tr><th>Indicator</th><th>Count</th></tr>
{% for r in top %}
<tr><td>{{r['indicator']}}</td><td>{{r['cnt']}}</td></tr>
{% endfor %}
</table>

<h3>Latest Threats</h3>
<table>
<tr><th>ID</th><th>Indicator</th><th>Type</th><th>Source</th><th>Time</th></tr>
{% for r in rows %}
<tr>
<td>{{r['id']}}</td>
<td>{{r['indicator']}}</td>
<td>{{r['type']}}</td>
<td>{{r['source']}}</td>
<td>{{r['created_at']}}</td>
</tr>
{% endfor %}
</table>

<script>
var heat={{heat|safe}};
Plotly.newPlot('heatmap',heat.data,heat.layout);

var tr={{trend|safe}};
Plotly.newPlot('trend',tr.data,tr.layout);
</script>

</body></html>
"""

# -----------------------------------
# Routes
# -----------------------------------
@app.route("/")
def dashboard():
    conn=sqlite3.connect(DB)
    conn.row_factory=sqlite3.Row
    rows=conn.cursor().execute("SELECT * FROM threats ORDER BY created_at DESC LIMIT 50").fetchall()
    conn.close()
    return render_template_string(DASHBOARD_HTML,
                                  heat=heatmap_data(),
                                  trend=trend_data(),
                                  top=top_indicators(),
                                  rows=rows)

# Adds CSV/JSON/PDF routes similar to earlier version
# (omitted for brevity; we can re‑add if needed)

if __name__=="__main__":
    app.run(host="0.0.0.0",port=int(os.environ.get("PORT",5000)),debug=False)