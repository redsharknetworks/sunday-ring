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
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from plotly.utils import PlotlyJSONEncoder

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

# ---------------- DUMMY DATA ----------------
MALAYSIA_STATES = {
    "Johor":[1.4927,103.7414],"Kedah":[6.1164,100.3678],"Kelantan":[6.1254,102.2381],
    "Melaka":[2.1896,102.2501],"Negeri Sembilan":[2.7290,101.9383],"Pahang":[3.8167,103.3333],
    "Perak":[4.5929,101.0900],"Perlis":[6.4400,100.2000],"Penang":[5.4164,100.3327],
    "Sabah":[5.9804,116.0735],"Sarawak":[1.5533,110.3592],"Selangor":[3.1390,101.6869],
    "Terengganu":[5.3300,103.1400],"Kuala Lumpur":[3.1390,101.6869],
    "Putrajaya":[2.9264,101.6981],"Labuan":[5.2833,115.2333]
}

ASSETS = ["Server-1","Server-2","Firewall-1","DB-Prod","Laptop-1"]
EVENT_TYPES = ["Malware","Phishing","Port Scan","Data Exfiltration","Suspicious Login"]

def classify_risk(score):
    if score >= 70: return "Critical"
    elif score >= 40: return "High"
    else: return "Medium"

def insert_dummy_data(n=50):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    for _ in range(n):
        created = datetime.utcnow().isoformat()
        score = random.randint(10,95)
        severity = classify_risk(score)
        city = random.choice(list(MALAYSIA_STATES.keys()))
        c.execute("""INSERT INTO threats (pulse, indicator, type, classification, mitre, risk_score, source, city, severity, created_at)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                  (f"Pulse {random.randint(1,20)}",
                   f"malicious{random.randint(1,50)}.com",
                   random.choice(EVENT_TYPES),
                   severity, "MITRE-T", score,
                   random.choice(["dummy","otx","talos"]), city, severity, created))
    conn.commit()
    conn.close()

# ---------------- SCHEDULER ----------------
def scheduler():
    while True:
        insert_dummy_data()
        cleanup_old_records()
        time.sleep(3600)

# ---------------- PLOTLY CHARTS ----------------
def generate_trend_chart():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT substr(created_at,1,10) as d, COUNT(*) as cnt FROM threats GROUP BY d").fetchall()
    conn.close()
    x = [r["d"] for r in rows] if rows else [datetime.utcnow().strftime("%Y-%m-%d")]
    y = [r["cnt"] for r in rows] if rows else [0]
    fig = go.Figure(data=[go.Scatter(x=x,y=y,mode="lines+markers",line=dict(color="#00e6ff"))])
    fig.update_layout(title="Threat Timeline (Last 30 Days)",
                      paper_bgcolor="#0b1b2a",plot_bgcolor="#0b1b2a",font_color="#00e6ff")
    return json.dumps(fig,cls=PlotlyJSONEncoder)

def generate_type_chart():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT type, COUNT(*) as cnt FROM threats GROUP BY type").fetchall()
    conn.close()
    labels = [r["type"] for r in rows] if rows else ["No Data"]
    values = [r["cnt"] for r in rows] if rows else [0]
    fig = go.Figure(data=[go.Pie(labels=labels, values=values, hole=0.3,
                                 marker=dict(colors=["#00e6ff","#006699","#003366","#00ffff","#3399ff"],
                                             line=dict(color='#ffffff',width=2)))])
    fig.update_traces(textinfo='label+percent', pull=[0.1 if v>0 else 0 for v in values])
    fig.update_layout(title="Threat Type Distribution",
                      paper_bgcolor="#0b1b2a",plot_bgcolor="#0b1b2a",font_color="#00e6ff")
    return json.dumps(fig,cls=PlotlyJSONEncoder)

# ---------------- HEATMAP ----------------
def generate_heatmap():
    with sqlite3.connect(DB) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT city FROM threats WHERE severity='Critical'").fetchall()
    critical_cities = [r["city"] for r in rows]
    return critical_cities

# ---------------- SECURE INDEX ----------------
def calculate_secure_index():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT risk_score FROM threats")
    rows = c.fetchall()
    conn.close()
    if not rows: return 0
    total_weighted = sum([(s*1.0 if s>=70 else s*0.5 if s>=40 else s*0.2) for (s,) in rows])
    return round(total_weighted/(len(rows)*100)*100,1)

# ---------------- PDF ----------------
def generate_pdf():
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer,pagesize=A4)
    elements=[]
    styles = getSampleStyleSheet()
    elements.append(Paragraph("RedShark Threat Intelligence Report", styles['Title']))
    elements.append(Spacer(1,12))
    with sqlite3.connect(DB) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM threats ORDER BY created_at DESC LIMIT 100").fetchall()
    if not rows:
        elements.append(Paragraph("No data available.", styles['Normal']))
    else:
        data=[["ID","Indicator","Type","Source","City","Severity","MITRE","Created"]]
        for r in rows:
            data.append([r["id"],r["indicator"],r["type"],r["source"],r["city"],r["severity"],r["mitre"],r["created_at"]])
        t = Table(data, repeatRows=1)
        t.setStyle(TableStyle([
            ('BACKGROUND',(0,0),(-1,0),colors.HexColor("#004d66")),
            ('TEXTCOLOR',(0,0),(-1,0),colors.white),
            ('GRID',(0,0),(-1,-1),0.5,colors.HexColor("#00e6ff")),
            ('BACKGROUND',(0,1),(-1,-1),colors.HexColor("#002f4d")),
        ]))
        elements.append(t)
    doc.build(elements)
    buffer.seek(0)
    return buffer

# ---------------- DASHBOARD TEMPLATE ----------------
TEMPLATE = """
<html>
<head>
<title>RedShark Threat Intelligence Dashboard</title>
<script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
<style>
body {background:#0b1b2a;color:#00e6ff;font-family:sans-serif;margin:0;padding:0;}
h2 {text-align:center;padding:10px;}
.card {background:#00274d;padding:12px;margin:10px;border-radius:6px;}
table {border-collapse:collapse;width:100%;word-wrap:break-word;}
th,td{padding:6px;text-align:left;}
th{background:#004d66;color:#00e6ff;}
tr:nth-child(even){background:#0c2a4a;}
tr:nth-child(odd){background:#0b1b2a;}
a.button {background:#00e6ff;color:#0b1b2a;padding:6px 12px;text-decoration:none;border-radius:4px;margin-right:6px;}
</style>
</head>
<body>
<h2>RedShark Threat Intelligence Dashboard</h2>
<p style="text-align:center;font-size:12px;">Disclaimer: Developed & analyzed by darkgrid@redshark.my using publicly available sources.</p>

<div class="card">
<h3>SecureNation Index: {{ gauge }}/100</h3>
<div style="background:#00274d;width:300px;height:25px;border-radius:5px;">
<div style="height:25px;width:{{ gauge }}%;background:#00e6ff;text-align:center;color:#0b1b2a;font-weight:bold;">{{ gauge }}/100</div>
</div>
</div>

<div class="card">
<h3>Malaysia Critical Threat Heatmap</h3>
<canvas id="heatmap" width="600" height="400"></canvas>
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
<h3>Latest Indicators</h3>
<table id="indicators">
<thead><tr><th>ID</th><th>Pulse</th><th>Indicator</th><th>Type</th><th>Class</th><th>Risk</th><th>Source</th><th>City</th><th>Severity</th><th>Created</th></tr></thead>
<tbody>
{% for row in table_data %}
<tr><td>{{ row['id'] }}</td><td>{{ row['pulse'] }}</td><td>{{ row['indicator'] }}</td><td>{{ row['type'] }}</td><td>{{ row['classification'] }}</td><td>{{ row['risk_score'] }}</td><td>{{ row['source'] }}</td><td>{{ row['city'] }}</td><td>{{ row['severity'] }}</td><td>{{ row['created_at'] }}</td></tr>
{% endfor %}
</tbody>
</table>
</div>

<div style="text-align:center;margin:20px;">
<a href="/download/csv" class="button">Download CSV</a>
<a href="/download/json" class="button">Download JSON</a>
<a href="/download/pdf" class="button">Download PDF</a>
</div>

<script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
<script>
$(document).ready(function() {
    var trend_chart = {{ trend | safe }};
    var type_chart = {{ type_chart | safe }};
    Plotly.newPlot('trend_chart', trend_chart.data, trend_chart.layout);
    Plotly.newPlot('type_chart', type_chart.data, type_chart.layout);

    // Heatmap canvas with glowing circles for Critical events
    var heatmapCanvas = document.getElementById('heatmap');
    var ctx = heatmapCanvas.getContext('2d');
    ctx.clearRect(0,0,heatmapCanvas.width,heatmapCanvas.height);

    var critical_cities = {{ critical_cities | safe }};
    var positions = {{ positions | safe }};
    
    critical_cities.forEach(function(c){
        var p = positions[c];
        if(p){
            ctx.save();
            ctx.beginPath();
            ctx.shadowBlur = 10;
            ctx.shadowColor = "#ff3300";
            ctx.fillStyle = "#ff6600";
            ctx.arc(p[0], p[1], 6, 0, 2*Math.PI);
            ctx.fill();
            ctx.restore();
        }
    });
});
</script>
</body>
</html>
"""

# ---------------- DASHBOARD ROUTE ----------------
@app.route("/")
def dashboard():
    trend = generate_trend_chart()
    type_chart = generate_type_chart()
    critical_cities = generate_heatmap()
    gauge = calculate_secure_index()

    # map city name to canvas positions
    positions = {}
    width,height=600,400
    for city,coords in MALAYSIA_STATES.items():
        positions[city]=[coords[1]/116*width, height - (coords[0]/7*height)]

    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    table_data = conn.execute("SELECT * FROM threats ORDER BY created_at DESC LIMIT 50").fetchall()
    conn.close()

    return render_template_string(TEMPLATE,
                                  trend=trend,
                                  type_chart=type_chart,
                                  critical_cities=critical_cities,
                                  positions=positions,
                                  gauge=gauge,
                                  table_data=table_data)

# ---------------- DOWNLOAD ROUTES ----------------
@app.route("/download/csv")
def download_csv():
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=["id","pulse","indicator","type","classification","risk_score","source","city","severity","created_at"])
    writer.writeheader()
    with sqlite3.connect(DB) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM threats").fetchall()
    for r in rows: writer.writerow(r)
    outb = io.BytesIO()
    outb.write(output.getvalue().encode()); outb.seek(0)
    return send_file(outb, mimetype="text/csv", download_name="soc_report.csv", as_attachment=True)

@app.route("/download/json")
def download_json():
    with sqlite3.connect(DB) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM threats").fetchall()
        data = [dict(r) for r in rows]
    outb = io.BytesIO()
    outb.write(json.dumps(data,indent=2).encode()); outb.seek(0)
    return send_file(outb, mimetype="application/json", download_name="soc_report.json", as_attachment=True)

@app.route("/download/pdf")
def download_pdf():
    return send_file(generate_pdf(), mimetype="application/pdf", download_name="soc_report.pdf", as_attachment=True)

# ---------------- START ----------------
ensure_database()
insert_dummy_data()
threading.Thread(target=scheduler,daemon=True).start()

if __name__=="__main__":
    app.run(host="0.0.0.0",port=int(os.getenv("PORT",5000)))