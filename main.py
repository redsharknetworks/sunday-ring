import os
import io
import csv
import sqlite3
import threading
import time
import random
from datetime import datetime, timedelta

from flask import Flask, render_template_string, send_file
import folium
from folium.plugins import HeatMap
import plotly
import plotly.graph_objs as go
import json
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors

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
        city TEXT,
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

# ---------------- DATA ----------------
MALAYSIA_STATES = {
    "Johor": [1.4927,103.7414],"Kedah": [6.1164,100.3678],"Kelantan": [6.1254,102.2381],"Melaka": [2.1896,102.2501],
    "Negeri Sembilan": [2.7290,101.9383],"Pahang": [3.8167,103.3333],"Perak": [4.5929,101.0900],"Perlis": [6.4400,100.2000],
    "Penang": [5.4164,100.3327],"Sabah": [5.9804,116.0735],"Sarawak": [1.5533,110.3592],"Selangor": [3.1390,101.6869],
    "Terengganu": [5.3300,103.1400],"Kuala Lumpur": [3.1390,101.6869],"Putrajaya": [2.9264,101.6981],"Labuan": [5.2833,115.2333]
}

MITRE_TECHNIQUES = ["T1059","T1566","T1071","T1070","T1021","T1082","T1003"]

EVENT_TYPES = ["Malware","Phishing","C2","Recon","Exfiltration"]

def classify_risk(score):
    if score >= 70: return "Critical"
    elif score >= 40: return "High"
    else: return "Medium"

def generate_dummy_data(n=50):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    for _ in range(n):
        created = datetime.utcnow().isoformat()
        score = random.randint(10,95)
        classification = classify_risk(score)
        city = random.choice(list(MALAYSIA_STATES.keys()))
        mitre = random.choice(MITRE_TECHNIQUES)
        indicator = f"malicious{random.randint(1,1000)}.com"
        pulse = f"Pulse-{random.randint(1,100)}"
        typ = random.choice(EVENT_TYPES)
        c.execute("""INSERT INTO threats (pulse, indicator, type, classification, mitre, risk_score, city, created_at)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                  (pulse, indicator, typ, classification, mitre, score, city, created))
    conn.commit()
    conn.close()

# ---------------- SCHEDULER ----------------
def scheduler():
    while True:
        generate_dummy_data(5)  # add 5 new events per hour
        cleanup_old_records()
        time.sleep(3600)

# ---------------- CHARTS ----------------
def generate_plotly_charts():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    # Trend by date
    trend_rows = c.execute("SELECT substr(created_at,1,10) date, COUNT(*) cnt FROM threats GROUP BY date").fetchall()
    # Pie by MITRE technique
    pie_rows = c.execute("SELECT mitre, COUNT(*) cnt FROM threats GROUP BY mitre").fetchall()
    conn.close()

    trend_chart = {}
    if trend_rows:
        dates = [r["date"] for r in trend_rows]
        counts = [r["cnt"] for r in trend_rows]
        trace = go.Scatter(x=dates, y=counts, mode='lines+markers',
                           line=dict(color='#00FFFF', width=3),
                           marker=dict(size=8))
        layout = go.Layout(plot_bgcolor='#0b1b2a', paper_bgcolor='#0b1b2a',
                           font=dict(color='#00FFFF'),
                           title="Threat Timeline (Last 60 Days)")
        trend_chart = json.dumps(go.Figure(data=[trace], layout=layout), cls=plotly.utils.PlotlyJSONEncoder)

    pie_chart = {}
    if pie_rows:
        labels = [r["mitre"] for r in pie_rows]
        values = [r["cnt"] for r in pie_rows]
        trace = go.Pie(labels=labels, values=values, hole=0.4,
                       marker=dict(colors=['#00FFFF','#00FF80','#FF8000','#FF0000','#FF00FF','#FFFF00','#FF4040']))
        layout = go.Layout(plot_bgcolor='#0b1b2a', paper_bgcolor='#0b1b2a',
                           font=dict(color='#00FFFF'),
                           title="MITRE ATT&CK Distribution")
        pie_chart = json.dumps(go.Figure(data=[trace], layout=layout), cls=plotly.utils.PlotlyJSONEncoder)

    return trend_chart, pie_chart

# ---------------- SECURE NATION ----------------
def calculate_secure_index():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT risk_score FROM threats")
    rows = c.fetchall()
    conn.close()
    if not rows: return 0
    total_weighted = sum([(s*1.0 if s>=70 else s*0.5 if s>=40 else s*0.2) for (s,) in rows])
    return round(total_weighted / (len(rows)*100) * 100,1)

# ---------------- MALAYSIA HEATMAP ----------------
def generate_heatmap():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    critical_rows = c.execute("SELECT indicator, city, severity, risk_score FROM threats WHERE risk_score>=70 ORDER BY created_at DESC LIMIT 50").fetchall()
    conn.close()
    m = folium.Map(location=[4.2105,101.9758], zoom_start=6, tiles="CartoDB dark_matter")
    for r in critical_rows:
        coord = MALAYSIA_STATES.get(r["city"])
        if coord:
            folium.CircleMarker(
                location=coord,
                radius=7,
                color="#FF0000",
                fill=True,
                fill_color="#FF0000",
                fill_opacity=0.7,
                popup=f"{r['indicator']} | {r['city']} | Severity: {r['risk_score']}"
            ).add_to(m)
    return m._repr_html_(), datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

# ---------------- DASHBOARD TEMPLATE ----------------
TEMPLATE = """
<html>
<head>
<title>RedShark Threat Intelligence Dashboard</title>
<link rel="stylesheet" href="https://cdn.datatables.net/1.13.6/css/jquery.dataTables.min.css"/>
<script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
<style>
body {background:#0b1b2a;color:#00FFFF;font-family:sans-serif;margin:0;padding:0;}
h2,h3{color:#00FFFF;margin:10px 0;}
.card {background:#00274d;padding:15px;margin:10px;border-radius:6px;}
table {border-collapse: collapse;width:100%; word-wrap: break-word;}
th, td {padding:8px;text-align:left;color:#00FFFF;}
th {background:#001f3f;cursor:pointer;}
tr:nth-child(even){background:#0c2a4a;}
tr:nth-child(odd){background:#0b1b2a;}
a.button {background:#00FFFF;color:#0b1b2a;padding:6px 12px;text-decoration:none;border-radius:4px;margin:5px;}
</style>
</head>
<body>
<h2>RedShark Threat Intelligence Dashboard</h2>
<p>Disclaimer: Developed & analyzed by darkgrid@redshark.my from publicly available sources.</p>

<div class="card">
<h3>SecureNation Index: {{ gauge }}/100</h3>
<div style="background:#00274d;width:300px;height:25px;border-radius:5px;">
  <div style="height:25px;width:{{ gauge }}%;background:#00FFFF;text-align:center;color:#0b1b2a;font-weight:bold;" title="Hover for gauge">{{ gauge }}/100</div>
</div>
</div>

<div class="card">
<h3>Malaysia Heatmap (Last Update: {{ heatmap_time }})</h3>
{{ heatmap|safe }}
</div>

<div class="card">
<h3>Threat Timeline</h3>
<div id="trend_chart"></div>
</div>

<div class="card">
<h3>MITRE ATT&CK Distribution</h3>
<div id="pie_chart"></div>
</div>

<div class="card">
<h3>Latest Indicators</h3>
<table id="indicators">
<thead><tr><th>ID</th><th>Pulse</th><th>Indicator</th><th>Type</th><th>Class</th><th>Risk</th><th>MITRE</th><th>City</th><th>Created</th></tr></thead>
<tbody>
{% for row in table_data %}
<tr>
<td>{{ row['id'] }}</td>
<td>{{ row['pulse'] }}</td>
<td>{{ row['indicator'] }}</td>
<td>{{ row['type'] }}</td>
<td>{{ row['classification'] }}</td>
<td>{{ row['risk_score'] }}</td>
<td>{{ row['mitre'] }}</td>
<td>{{ row['city'] }}</td>
<td>{{ row['created_at'] }}</td>
</tr>
{% endfor %}
</tbody>
</table>
<div>
<a href="/download/csv" class="button">Download CSV</a>
<a href="/download/json" class="button">Download JSON</a>
<a href="/download/pdf" class="button">Download PDF</a>
</div>
</div>

<script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
<script src="https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js"></script>
<script>
$(document).ready(function() {
    $('#indicators').DataTable({pageLength:50});
    var trend_chart = {{ trend|safe }};
    var pie_chart = {{ pie|safe }};
    if(trend_chart.data){Plotly.newPlot('trend_chart', trend_chart.data, trend_chart.layout);}
    if(pie_chart.data){Plotly.newPlot('pie_chart', pie_chart.data, pie_chart.layout);}
});
</script>
</body>
</html>
"""

# ---------------- DASHBOARD ROUTE ----------------
@app.route("/")
def dashboard():
    trend, pie = generate_plotly_charts()
    heatmap, heatmap_time = generate_heatmap()
    gauge = calculate_secure_index()
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    table_data = c.execute("SELECT * FROM threats ORDER BY created_at DESC LIMIT 50").fetchall()
    conn.close()
    return render_template_string(TEMPLATE, trend=trend, pie=pie, heatmap=heatmap, heatmap_time=heatmap_time, gauge=gauge, table_data=table_data)

# ---------------- DOWNLOAD ROUTES ----------------
@app.route("/download/csv")
def download_csv():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    rows = c.execute("SELECT * FROM threats").fetchall()
    conn.close()
    si = io.StringIO()
    cw = csv.DictWriter(si, fieldnames=rows[0].keys() if rows else [])
    cw.writeheader()
    cw.writerows([dict(r) for r in rows])
    output = io.BytesIO()
    output.write(si.getvalue().encode("utf-8"))
    output.seek(0)
    return send_file(output, mimetype="text/csv", download_name="threats.csv", as_attachment=True)

@app.route("/download/json")
def download_json():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    rows = c.execute("SELECT * FROM threats").fetchall()
    conn.close()
    output = io.BytesIO()
    output.write(json.dumps([dict(r) for r in rows], indent=2).encode("utf-8"))
    output.seek(0)
    return send_file(output, mimetype="application/json", download_name="threats.json", as_attachment=True)

@app.route("/download/pdf")
def download_pdf():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    rows = c.execute("SELECT * FROM threats ORDER BY created_at DESC LIMIT 50").fetchall()
    conn.close()
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4)
    elements = []
    styles = getSampleStyleSheet()
    elements.append(Paragraph("RedShark Threat Intelligence Dashboard - PDF Report", styles["Title"]))
    elements.append(Spacer(1,12))
    table_data = [list(rows[0].keys()) if rows else []] + [list(r) for r in rows]
    t=Table(table_data, repeatRows=1)
    t.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,0),colors.HexColor("#001f3f")),
        ('TEXTCOLOR',(0,0),(-1,0),colors.white),
        ('GRID',(0,0),(-1,-1),1,colors.HexColor("#00FFFF")),
        ('BACKGROUND',(0,1),(-1,-1),colors.HexColor("#00274d")),
        ('ALIGN',(0,0),(-1,-1),'LEFT')
    ]))
    elements.append(t)
    doc.build(elements)
    buffer.seek(0)
    return send_file(buffer, mimetype="application/pdf", download_name="threats.pdf", as_attachment=True)

# ---------------- START ----------------
ensure_database()
generate_dummy_data(50)
threading.Thread(target=scheduler, daemon=True).start()

if __name__=="__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT",5000)))