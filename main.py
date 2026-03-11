import os
import io
import csv
import sqlite3
import threading
import time
import random
from datetime import datetime, timedelta

from flask import Flask, render_template_string, send_file
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import folium
from folium.plugins import HeatMap
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT

# ---------------- CONFIG ----------------
app = Flask(__name__)
DB = os.getenv("DB_PATH", "/tmp/threats.db")

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

# ---------------- DUMMY DATA ----------------
def classify_risk(score):
    if score >= 70:
        return "High"
    elif score >= 40:
        return "Medium"
    else:
        return "Low"

def insert_dummy_data():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    for i in range(20):
        created = datetime.utcnow().isoformat()
        score = random.randint(10,95)
        classification = classify_risk(score)
        c.execute("""
        INSERT INTO threats (pulse, indicator, type, classification, mitre, risk_score, source, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            f"Dummy Pulse {i+1}",
            f"malicious{i+1}.com",
            "domain",
            classification,
            "OTX",
            score,
            "dummy",
            created
        ))
    conn.commit()
    conn.close()

# ---------------- TALOS LOOKUP (simple example) ----------------
def fetch_talos_lookup():
    # placeholder: normally you'd scrape or pull CSV from Talos community
    # here we just insert dummy Talos indicators
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    for i in range(5):
        created = datetime.utcnow().isoformat()
        score = random.randint(40,90)
        classification = classify_risk(score)
        c.execute("""
        INSERT INTO threats (pulse, indicator, type, classification, mitre, risk_score, source, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            f"Talos Pulse {i+1}",
            f"badip{i+1}.talos.com",
            "ip",
            classification,
            "Talos",
            score,
            "talos",
            created
        ))
    conn.commit()
    conn.close()

# ---------------- SURICATA LOGS PARSE ----------------
def parse_suricata_logs():
    # placeholder: insert dummy suricata alerts
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    for i in range(5):
        created = datetime.utcnow().isoformat()
        score = random.randint(50,95)
        classification = classify_risk(score)
        c.execute("""
        INSERT INTO threats (pulse, indicator, type, classification, mitre, risk_score, source, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            f"Suricata Alert {i+1}",
            f"malicious{i+1}.suricata",
            "domain",
            classification,
            "Suricata",
            score,
            "suricata",
            created
        ))
    conn.commit()
    conn.close()

# ---------------- SCHEDULER ----------------
def scheduler():
    while True:
        insert_dummy_data()
        fetch_talos_lookup()
        parse_suricata_logs()
        cleanup_old_records()
        time.sleep(3600)  # refresh every hour

# ---------------- CHART GENERATION ----------------
def generate_charts():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    trend_rows = c.execute("SELECT substr(created_at,1,10) date, COUNT(*) cnt FROM threats GROUP BY date").fetchall()
    type_rows = c.execute("SELECT type, COUNT(*) cnt FROM threats GROUP BY type").fetchall()
    conn.close()

    imgs = {}
    # Trend chart
    if trend_rows:
        dates = [r["date"] for r in trend_rows]
        counts = [r["cnt"] for r in trend_rows]
        plt.figure(figsize=(6,3))
        plt.plot(dates, counts, marker='o', color='#00FFFF')
        plt.title("Threat Trend (Last 7 Days)", color='#00FFFF')
        plt.xticks(rotation=45, color='#00FFFF')
        plt.yticks(color='#00FFFF')
        plt.grid(color='#0b1b2a')
        buf = io.BytesIO()
        plt.savefig(buf, format="png", facecolor='#0b1b2a')
        plt.close()
        imgs["trend"] = base64.b64encode(buf.getvalue()).decode()
    # Type chart
    if type_rows:
        labels = [r["type"] for r in type_rows]
        values = [r["cnt"] for r in type_rows]
        plt.figure(figsize=(6,3))
        plt.bar(labels, values, color='#00FFFF')
        plt.title("Indicator Types", color='#00FFFF')
        plt.xticks(rotation=30, color='#00FFFF')
        plt.yticks(color='#00FFFF')
        plt.grid(color='#0b1b2a')
        buf = io.BytesIO()
        plt.savefig(buf, format="png", facecolor='#0b1b2a')
        plt.close()
        imgs["type"] = base64.b64encode(buf.getvalue()).decode()

    return imgs.get("trend"), imgs.get("type")

# ---------------- MALAYSIA HEATMAP ----------------
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

def generate_malaysia_heatmap():
    tz = timedelta(hours=8)
    timestamp = (datetime.utcnow() + tz).strftime("%Y-%m-%d %H:%M:%S GMT+8")
    m = folium.Map(location=[4.2105,101.9758], zoom_start=6, tiles="CartoDB dark_matter")
    heat_data = []
    for coords in MALAYSIA_STATES.values():
        count = random.randint(1,10)
        heat_data.append([coords[0], coords[1], count])
    HeatMap(heat_data, radius=25).add_to(m)
    return m._repr_html_(), timestamp

# ---------------- SECURENATION INDEX ----------------
def calculate_secure_index():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT risk_score FROM threats")
    rows = c.fetchall()
    conn.close()
    if not rows:
        return 0
    total_weighted = sum([(score*1.0 if score>=70 else score*0.5 if score>=40 else score*0.2) for (score,) in rows])
    max_possible = len(rows)*100
    return round(total_weighted/max_possible*100,1)

# ---------------- DASHBOARD ----------------
TEMPLATE = """
<html>
<head>
<title>Sunday-Ring Dashboard</title>
<link rel="stylesheet" href="https://cdn.datatables.net/1.13.6/css/jquery.dataTables.min.css"/>
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
<h2>Sunday-Ring Threat Intelligence Dashboard</h2>
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
<h3>Trend (Last 7 Days)</h3>
{% if trend %}<img src="data:image/png;base64,{{ trend }}">{% else %}<p>No trend data</p>{% endif %}
</div>

<div class="card">
<h3>Indicator Types</h3>
{% if type_chart %}<img src="data:image/png;base64,{{ type_chart }}">{% else %}<p>No type data</p>{% endif %}
</div>

<div class="card">
<h3>Latest Indicators</h3>
<table id="indicators">
<thead>
<tr><th>ID</th><th>Pulse</th><th>Indicator</th><th>Type</th><th>Class</th><th>Risk</th><th>Source</th><th>Created</th></tr>
</thead>
<tbody>
{% for row in table_data %}
<tr>
<td>{{ row['id'] }}</td><td>{{ row['pulse'] }}</td><td>{{ row['indicator'] }}</td><td>{{ row['type'] }}</td><td>{{ row['classification'] }}</td><td>{{ row['risk_score'] }}</td><td>{{ row['source'] }}</td><td>{{ row['created_at'] }}</td>
</tr>
{% endfor %}
</tbody>
</table>
</div>

<div class="card">
<h3>Download Reports</h3>
<a class="button" href="/report/pdf">PDF</a>
<a class="button" href="/report/csv">CSV</a>
<a class="button" href="/report/json">JSON</a>
</div>

<script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
<script src="https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js"></script>
<script>
$(document).ready(function() {
    $('#indicators').DataTable({pageLength:50});
});
</script>
</body>
</html>
"""

@app.route("/")
def dashboard():
    trend, type_chart = generate_charts()
    heatmap, heatmap_time = generate_malaysia_heatmap()
    gauge = calculate_secure_index()

    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    table_data = c.execute("SELECT * FROM threats ORDER BY created_at DESC LIMIT 50").fetchall()
    conn.close()

    return render_template_string(
        TEMPLATE,
        trend=trend,
        type_chart=type_chart,
        heatmap=heatmap,
        heatmap_time=heatmap_time,
        gauge=gauge,
        table_data=table_data
    )

# ---------------- REPORTS ----------------
# Use the PDF code I provided earlier with matplotlib charts (safe for Railway)
# CSV and JSON remain unchanged

# ---------------- START ----------------
ensure_database()
insert_dummy_data()
fetch_talos_lookup()
parse_suricata_logs()
cleanup_old_records()

if not os.getenv("RUN_MAIN"):
    threading.Thread(target=scheduler, daemon=True).start()

if __name__=="__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT",5000)))