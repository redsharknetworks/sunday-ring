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
import folium
from folium import CircleMarker
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors

app = Flask(__name__)
DB = "/tmp/threats.db"

# ---------------- CONFIG ----------------
ASSETS = ["Server-1","Server-2","Firewall-1","DB-Prod","Laptop-1"]
EVENT_TYPES = ["Malware","Phishing","Port Scan","Data Exfiltration","Suspicious Login"]

# Malaysia states center coordinates
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

# ---------------- DATA INGESTION ----------------
def insert_dummy_data(n=30):
    for _ in range(n):
        score = random.randint(10,95)
        severity = "Critical" if score >= 70 else "High" if score>=40 else "Medium"
        city = random.choice(list(MALAYSIA_STATES.keys()))
        insert_threat(f"Pulse {random.randint(1,50)}", f"malicious{random.randint(1,100)}.com",
                      random.choice(EVENT_TYPES), severity, score, "dummy", city)

# ---------------- SECURENATION INDEX ----------------
def calculate_secure_index():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    rows = c.execute("SELECT risk_score FROM threats").fetchall()
    conn.close()
    if not rows: return 0
    total = sum([r[0] if r[0]>=70 else r[0]*0.7 if r[0]>=40 else r[0]*0.4 for r in rows])
    return round(total/(len(rows)*100)*100,1)

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

# ---------------- MALAYSIA HEATMAP ----------------
def generate_malaysia_heatmap():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    critical_rows = conn.execute("SELECT city FROM threats WHERE severity='Critical'").fetchall()
    conn.close()
    critical_cities = [r["city"] for r in critical_rows]
    
    m = folium.Map(location=[4.2105,101.9758], zoom_start=6, tiles="CartoDB dark_matter")
    
    for city in critical_cities:
        coords = MALAYSIA_STATES.get(city)
        if coords:
            CircleMarker(location=coords,
                         radius=7,
                         color="#ff0000",
                         fill=True,
                         fill_opacity=0.8,
                         popup=f"{city} - Critical Threat").add_to(m)
    return m._repr_html_()

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
<h3>SecureNation Index: {{ gauge }}/100</h3>
<div style="background:#00274d;width:300px;height:25px;border-radius:5px;">
  <div style="height:25px;width:{{ gauge }}%;background:#00e6ff;text-align:center;color:#0b1b2a;font-weight:bold;">{{ gauge }}/100</div>
</div>
</div>

<div class="card">
<h3>Malaysia Critical Threats Map</h3>
{{ heatmap|safe }}
</div>

<div class="card">
<h3>Threat Timeline</h3>
<div id="trend_chart"></div>
</div>

<div class="card">
<h3>Threat Type Distribution</h3>
<div id="type_chart"></div>
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
<a class="button" href="/download/pdf">Download PDF</a>
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

# ---------------- DOWNLOAD PDF ----------------
@app.route("/download/pdf")
def download_pdf():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM threats ORDER BY created_at DESC").fetchall()
    conn.close()

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4)
    elements = []
    styles = getSampleStyleSheet()
    elements.append(Paragraph("RedShark Threat Intelligence Dashboard", styles['Title']))
    elements.append(Spacer(1,12))

    # Table
    data = [["ID","Pulse","Indicator","Type","Severity","City","Created"]]
    for r in rows[:50]:
        data.append([r["id"],r["pulse"],r["indicator"],r["type"],r["severity"],r["city"],r["created_at"]])
    table = Table(data, hAlign='LEFT')
    table.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.darkblue),
                               ('TEXTCOLOR',(0,0),(-1,0),colors.white),
                               ('BACKGROUND',(0,1),(-1,-1),colors.HexColor('#00274d')),
                               ('GRID',(0,0),(-1,-1),1,colors.white)]))
    elements.append(table)
    doc.build(elements)
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name="threats.pdf", mimetype="application/pdf")

# ---------------- DASHBOARD ----------------
@app.route("/")
def dashboard():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    table_data = [dict(r) for r in conn.execute("SELECT * FROM threats ORDER BY created_at DESC LIMIT 50").fetchall()]
    conn.close()
    trend = generate_trend_chart()
    type_chart = generate_type_chart()
    heatmap = generate_malaysia_heatmap()
    gauge = calculate_secure_index()
    return render_template_string(TEMPLATE, table_data=table_data,
                                  trend=trend,
                                  type_chart=type_chart,
                                  heatmap=heatmap,
                                  gauge=gauge)

# ---------------- START ----------------
ensure_database()
insert_dummy_data()
threading.Thread(target=lambda: scheduler(), daemon=True).start()

if __name__=="__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT",5000)))