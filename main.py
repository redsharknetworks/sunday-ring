import os
import io
import csv
import sqlite3
import threading
import time
import random
from datetime import datetime, timedelta
from flask import Flask, render_template_string, send_file
import plotly
import plotly.graph_objs as go
import json
from plotly.utils import PlotlyJSONEncoder
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet

app = Flask(__name__)
DB = "/tmp/threats.db"

# ---------------- CONFIG ----------------
ASSETS = ["Server-1","Server-2","Firewall-1","DB-Prod","Laptop-1"]
EVENT_TYPES = ["Malware","Phishing","Port Scan","Data Exfiltration","Suspicious Login"]

MALAYSIA_STATES = {
    "Johor":[1.4927,103.7414],"Kedah":[6.1164,100.3678],"Kelantan":[6.1254,102.2381],
    "Melaka":[2.1896,102.2501],"Negeri Sembilan":[2.7290,101.9383],"Pahang":[3.8167,103.3333],
    "Perak":[4.5929,101.0900],"Perlis":[6.4400,100.2000],"Penang":[5.4164,100.3327],
    "Sabah":[5.9804,116.0735],"Sarawak":[1.5533,110.3592],"Selangor":[3.1390,101.6869],
    "Terengganu":[5.3300,103.1400],"Kuala Lumpur":[3.1390,101.6869],
    "Putrajaya":[2.9264,101.6981],"Labuan":[5.2833,115.2333]
}

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
        city TEXT,
        severity TEXT,
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

def insert_threat(pulse, indicator, typ, severity, score, source, city):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("""INSERT INTO threats (pulse, indicator, type, classification, mitre, risk_score, source, city, severity, created_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
              (pulse, indicator, typ, severity, "MITRE-T", score, source, city, severity, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()

def insert_dummy_data(n=20):
    for _ in range(n):
        score = random.randint(10,95)
        severity = "Critical" if score >= 70 else "High" if score>=40 else "Medium"
        city = random.choice(list(MALAYSIA_STATES.keys()))
        insert_threat(f"Pulse {random.randint(1,20)}", f"malicious{random.randint(1,50)}.com",
                      random.choice(EVENT_TYPES), severity, score, "dummy", city)

def scheduler():
    while True:
        insert_dummy_data()
        cleanup_old_records()
        time.sleep(3600)

# ---------------- CHARTS ----------------
def generate_trend_chart():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT substr(created_at,1,10) as d, COUNT(*) as cnt FROM threats GROUP BY d").fetchall()
    conn.close()
    x = [r["d"] for r in rows] if rows else [datetime.utcnow().strftime("%Y-%m-%d")]
    y = [r["cnt"] for r in rows] if rows else [0]
    fig = go.Figure(data=[go.Scatter(x=x,y=y,mode="lines+markers",line=dict(color="#00e6ff"))])
    fig.update_layout(title="Threat Timeline",
                      paper_bgcolor="#0b1b2a",plot_bgcolor="#0b1b2a",font_color="#00e6ff")
    return json.dumps(fig,cls=PlotlyJSONEncoder)

def generate_type_chart():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT type, COUNT(*) as cnt FROM threats GROUP BY type").fetchall()
    conn.close()
    labels = [r["type"] for r in rows] if rows else ["No Data"]
    values = [r["cnt"] for r in rows] if rows else [0]
    fig = go.Figure(data=[go.Pie(labels=labels, values=values, hole=0.3)])
    fig.update_layout(title="Threat Type Distribution",
                      paper_bgcolor="#0b1b2a",plot_bgcolor="#0b1b2a",font_color="#00e6ff")
    return json.dumps(fig,cls=PlotlyJSONEncoder)

def generate_critical_cities():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT city FROM threats WHERE severity='Critical'").fetchall()
    conn.close()
    return [r["city"] for r in rows]

# ---------------- DASHBOARD TEMPLATE ----------------
TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
<title>RedShark Threat Intelligence Dashboard</title>
<script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
<link rel="stylesheet" href="https://cdn.datatables.net/1.13.6/css/jquery.dataTables.min.css"/>
<script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
<script src="https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js"></script>
<style>
body {background:#0b1b2a;color:#00e6ff;font-family:sans-serif;}
table {border-collapse: collapse;width:100%; word-wrap: break-word;}
th, td {padding:8px;text-align:left;}
th {background:#00274d;color:#00e6ff;cursor:pointer;}
tr:nth-child(even){background:#0c2a4a;}
tr:nth-child(odd){background:#0b1b2a;}
a.button {background:#00e6ff;color:#0b1b2a;padding:6px 12px;text-decoration:none;border-radius:4px;}
.card {background:#00274d;padding:10px;margin:5px;border-radius:5px;}
</style>
</head>
<body>
<h2>RedShark Threat Intelligence Dashboard</h2>
<p>Disclaimer: Developed & analyzed by darkgrid@redshark.my using publicly available sources.</p>

<div class="card">
<h3>Threat Timeline</h3>
<div id="trend_chart"></div>
</div>

<div class="card">
<h3>Threat Type Distribution</h3>
<div id="type_chart"></div>
</div>

<div class="card">
<h3>Critical Threats by State</h3>
<ul>
{% for city in critical_cities %}
<li>{{ city }}</li>
{% endfor %}
</ul>
</div>

<div class="card">
<h3>Latest Threats</h3>
<table id="indicators">
<thead><tr><th>ID</th><th>Pulse</th><th>Indicator</th><th>Type</th><th>Severity</th><th>City</th><th>Created</th></tr></thead>
<tbody>
{% for row in table_data %}
<tr>
<td>{{ row['id'] }}</td>
<td>{{ row['pulse'] }}</td>
<td>{{ row['indicator'] }}</td>
<td>{{ row['type'] }}</td>
<td>{{ row['severity'] }}</td>
<td>{{ row['city'] }}</td>
<td>{{ row['created_at'] }}</td>
</tr>
{% endfor %}
</tbody>
</table>
<a class="button" href="/download/csv">Download CSV</a>
<a class="button" href="/download/json">Download JSON</a>
</div>

<script>
$(document).ready(function() {
    $('#indicators').DataTable({pageLength:50});
    var trend = {{ trend|safe }};
    var type_chart = {{ type_chart|safe }};
    Plotly.newPlot('trend_chart', trend.data, trend.layout);
    Plotly.newPlot('type_chart', type_chart.data, type_chart.layout);
});
</script>
</body>
</html>
"""

# ---------------- DOWNLOAD ----------------
@app.route("/download/csv")
def download_csv():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM threats ORDER BY created_at DESC").fetchall()
    conn.close()
    si = io.StringIO()
    cw = csv.DictWriter(si, fieldnames=rows[0].keys() if rows else [])
    if rows: cw.writeheader()
    cw.writerows([dict(r) for r in rows])
    output = io.BytesIO()
    output.write(si.getvalue().encode("utf-8"))
    output.seek(0)
    return send_file(output, mimetype="text/csv", download_name="threats.csv", as_attachment=True)

@app.route("/download/json")
def download_json():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM threats ORDER BY created_at DESC").fetchall()
    conn.close()
    data = [dict(r) for r in rows]
    output = io.BytesIO()
    output.write(json.dumps(data, indent=2).encode("utf-8"))
    output.seek(0)
    return send_file(output, mimetype="application/json", download_name="threats.json", as_attachment=True)

# ---------------- DASHBOARD ----------------
@app.route("/")
def dashboard():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    table_data = [dict(r) for r in conn.execute("SELECT * FROM threats ORDER BY created_at DESC LIMIT 50").fetchall()]
    conn.close()
    trend = generate_trend_chart()
    type_chart = generate_type_chart()
    critical_cities = generate_critical_cities()
    return render_template_string(TEMPLATE, table_data=table_data,
                                  trend=trend,
                                  type_chart=type_chart,
                                  critical_cities=critical_cities)

# ---------------- START ----------------
ensure_database()
insert_dummy_data()
threading.Thread(target=scheduler, daemon=True).start()

if __name__=="__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT",5000)))