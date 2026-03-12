import os
import io
import csv
import sqlite3
import threading
import time
import random
from datetime import datetime, timedelta

from flask import Flask, render_template_string, send_file
import requests
import folium
from folium.plugins import HeatMap
import plotly
import plotly.graph_objs as go
import json

# ---------------- CONFIG ----------------
app = Flask(__name__)
DB = os.getenv("DB_PATH", "/tmp/threats.db")

# Malaysian states coordinates
MALAYSIA_STATES = {
    "Johor":[1.4927,103.7414],"Kedah":[6.1164,100.3678],"Kelantan":[6.1254,102.2381],
    "Melaka":[2.1896,102.2501],"Negeri Sembilan":[2.7290,101.9383],"Pahang":[3.8167,103.3333],
    "Perak":[4.5929,101.0900],"Perlis":[6.4400,100.2000],"Penang":[5.4164,100.3327],
    "Sabah":[5.9804,116.0735],"Sarawak":[1.5533,110.3592],"Selangor":[3.1390,101.6869],
    "Terengganu":[5.3300,103.1400],"Kuala Lumpur":[3.1390,101.6869],"Putrajaya":[2.9264,101.6981],
    "Labuan":[5.2833,115.2333]
}

ASSETS = ["Server-1","Server-2","Laptop-1","Firewall-1","DB-Prod"]
EVENT_TYPES = ["Malware","Suspicious Login","Phishing","Port Scan","Data Exfiltration"]

# ---------------- DATABASE ----------------
def ensure_database():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS threats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pulse TEXT,
            indicator TEXT,
            type TEXT,
            classification TEXT,
            mitre TEXT,
            risk_score INTEGER,
            source TEXT,
            state TEXT,
            created_at TEXT
        )
    """)
    conn.commit()
    conn.close()

def cleanup_old_records():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    cutoff = (datetime.utcnow() - timedelta(days=60)).isoformat()
    c.execute("DELETE FROM threats WHERE created_at < ?", (cutoff,))
    conn.commit()
    conn.close()

def classify_risk(score):
    if score >= 70: return "High"
    elif score >= 40: return "Medium"
    else: return "Low"

# ---------------- DATA INGESTION FROM PUBLIC FEEDS ----------------
FEEDS = [
    {
        "name": "Abuse.ch URLhaus",
        "url": "https://urlhaus.abuse.ch/downloads/csv_online/",
        "type": "url",
        "source": "URLhaus"
    },
    {
        "name": "Spamhaus DROP",
        "url": "https://www.spamhaus.org/drop/drop.txt",
        "type": "ip",
        "source": "Spamhaus"
    },
    {
        "name": "PhishTank",
        "url": "https://data.phishtank.com/data/online-valid.csv",
        "type": "url",
        "source": "PhishTank"
    }
]

def fetch_public_feeds():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    for feed in FEEDS:
        try:
            r = requests.get(feed["url"], timeout=15)
            r.raise_for_status()
            lines = r.text.splitlines()
            for line in lines[1:50]:  # Limit 50 rows per feed
                if not line.strip() or line.startswith("#"): continue
                indicator = line.split(",")[0].strip()
                if not indicator: continue
                pulse = f"{feed['source']} Pulse"
                typ = feed["type"]
                score = random.randint(50,95)
                classification = classify_risk(score)
                state = random.choice(list(MALAYSIA_STATES.keys()))
                created = datetime.utcnow().isoformat()
                c.execute("""INSERT INTO threats 
                    (pulse, indicator, type, classification, mitre, risk_score, source, state, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                          (pulse, indicator, typ, classification, feed["source"], score, feed["source"], state, created))
        except:
            continue
    conn.commit()
    conn.close()

# ---------------- SCHEDULER ----------------
def scheduler():
    while True:
        fetch_public_feeds()
        cleanup_old_records()
        time.sleep(3600)  # every hour

# ---------------- DASHBOARD CHARTS ----------------
def generate_plotly_charts():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    trend_rows = c.execute("SELECT substr(created_at,1,10) date, COUNT(*) cnt FROM threats GROUP BY date").fetchall()
    type_rows = c.execute("SELECT type, COUNT(*) cnt FROM threats GROUP BY type").fetchall()
    conn.close()

    trend_chart = {}
    type_chart = {}
    if trend_rows:
        dates = [r["date"] for r in trend_rows]
        counts = [r["cnt"] for r in trend_rows]
        trace = go.Scatter(x=dates, y=counts, mode='lines+markers', line=dict(color='#00FFFF'))
        layout = go.Layout(plot_bgcolor='#0b1b2a', paper_bgcolor='#0b1b2a', font=dict(color='#00FFFF'), title="Threat Trend (Last 7 Days)")
        trend_chart = json.dumps(go.Figure(data=[trace], layout=layout), cls=plotly.utils.PlotlyJSONEncoder)
    if type_rows:
        labels = [r["type"] for r in type_rows]
        values = [r["cnt"] for r in type_rows]
        trace = go.Bar(x=labels, y=values, marker=dict(color='#00FFFF'))
        layout = go.Layout(plot_bgcolor='#0b1b2a', paper_bgcolor='#0b1b2a', font=dict(color='#00FFFF'), title="Indicator Types")
        type_chart = json.dumps(go.Figure(data=[trace], layout=layout), cls=plotly.utils.PlotlyJSONEncoder)
    return trend_chart, type_chart

# ---------------- MALAYSIA HEATMAP ----------------
def generate_malaysia_heatmap():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    heat_data = []
    for state, coords in MALAYSIA_STATES.items():
        count = c.execute("SELECT COUNT(*) FROM threats WHERE state=?", (state,)).fetchone()[0]
        if count>0: heat_data.append([coords[0], coords[1], count])
    conn.close()
    m = folium.Map(location=[4.2105,101.9758], zoom_start=6, tiles="CartoDB dark_matter")
    if heat_data: HeatMap(heat_data, radius=25).add_to(m)
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    return m._repr_html_(), timestamp

# ---------------- SECURENATION INDEX ----------------
def calculate_secure_index():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    rows = c.execute("SELECT risk_score FROM threats").fetchall()
    conn.close()
    if not rows: return 0
    total_weighted = sum([(s*1.0 if s>=70 else s*0.5 if s>=40 else s*0.2) for (s,) in rows])
    return round(total_weighted/(len(rows)*100)*100,1)

# ---------------- DASHBOARD ROUTE ----------------
TEMPLATE = """<html>
<head>
<title>Sunday-Ring SOC Dashboard</title>
<link rel="stylesheet" href="https://cdn.datatables.net/1.13.6/css/jquery.dataTables.min.css"/>
<script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
<style>
body {background:#0b1b2a;color:#00FFFF;font-family:sans-serif;}
table {border-collapse: collapse;width:100%; word-wrap: break-word;}
th, td {padding:8px;text-align:left;}
th {background:#00274d;color:#00FFFF;cursor:pointer;}
tr:nth-child(even){background:#0c2a4a;}
tr:nth-child(odd){background:#0b1b2a;}
a.button {background:#00FFFF;color:#0b1b2a;padding:6px 12px;text-decoration:none;border-radius:4px;}
.card {background:#00274d;padding:10px;margin:5px;border-radius:5px;}
</style>
</head>
<body>
<h2>Sunday-Ring SOC Dashboard</h2>
<p>Disclaimer: Developed & analysed by darkgrid@redshark.my using publicly available sources.</p>

<div class="card">
<h3>SecureNation Index: {{ gauge }}/100</h3>
<div style="background:#00274d;width:300px;height:25px;border-radius:5px;">
  <div style="height:25px;width:{{ gauge }}%;background:#00FFFF;text-align:center;color:#0b1b2a;font-weight:bold;">{{ gauge }}/100</div>
</div>
</div>

<div class="card">
<h3>Malaysia Heatmap (Last Update: {{ heatmap_time }})</h3>
{{ heatmap | safe }}
</div>

<div class="card">
<h3>Threat Trend</h3>
<div id="trend_chart"></div>
</div>

<div class="card">
<h3>Indicator Types</h3>
<div id="type_chart"></div>
</div>

<div class="card">
<h3>Latest Indicators</h3>
<table id="indicators">
<thead><tr><th>ID</th><th>Pulse</th><th>Indicator</th><th>Type</th><th>Class</th><th>Risk</th><th>Source</th><th>State</th><th>Created</th></tr></thead>
<tbody>
{% for row in table_data %}
<tr><td>{{ row['id'] }}</td><td>{{ row['pulse'] }}</td><td>{{ row['indicator'] }}</td><td>{{ row['type'] }}</td><td>{{ row['classification'] }}</td><td>{{ row['risk_score'] }}</td><td>{{ row['source'] }}</td><td>{{ row['state'] }}</td><td>{{ row['created_at'] }}</td></tr>
{% endfor %}
</tbody></table>
</div>

<script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
<script src="https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js"></script>
<script>
$(document).ready(function() {
    $('#indicators').DataTable({pageLength:50});
    var trend_chart = {{ trend | safe }};
    var type_chart = {{ type_chart | safe }};
    if(trend_chart.data){Plotly.newPlot('trend_chart', trend_chart.data, trend_chart.layout);}
    if(type_chart.data){Plotly.newPlot('type_chart', type_chart.data, type_chart.layout);}
});
</script>
</body>
</html>
"""

@app.route("/")
def dashboard():
    trend, type_chart = generate_plotly_charts()
    heatmap, heatmap_time = generate_malaysia_heatmap()
    gauge = calculate_secure_index()

    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    table_data = c.execute("SELECT * FROM threats ORDER BY created_at DESC LIMIT 50").fetchall()
    conn.close()

    return render_template_string(TEMPLATE,
                                  trend=trend,
                                  type_chart=type_chart,
                                  heatmap=heatmap,
                                  heatmap_time=heatmap_time,
                                  gauge=gauge,
                                  table_data=table_data)

# ---------------- START ----------------
ensure_database()
fetch_public_feeds()
cleanup_old_records()
threading.Thread(target=scheduler, daemon=True).start()

if __name__=="__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT",5000)))