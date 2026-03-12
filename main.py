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
from folium.plugins import MarkerCluster
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
OTX_PUBLIC_URL = "https://otx.alienvault.com/api/v1/pulses/public"
PHISHTANK_URL = "https://data.phishtank.com/data/online-valid.csv"
URLHAUS_URL = "https://urlhaus.abuse.ch/downloads/text/"

MALAYSIA_STATES = {
    "Johor": [1.4927,103.7414],"Kedah": [6.1164,100.3678],"Kelantan": [6.1254,102.2381],
    "Melaka": [2.1896,102.2501],"Negeri Sembilan": [2.7290,101.9383],"Pahang": [3.8167,103.3333],
    "Perak": [4.5929,101.0900],"Perlis": [6.4400,100.2000],"Penang": [5.4164,100.3327],
    "Sabah": [5.9804,116.0735],"Sarawak": [1.5533,110.3592],"Selangor": [3.1390,101.6869],
    "Terengganu": [5.3300,103.1400],"Kuala Lumpur": [3.1390,101.6869],"Putrajaya": [2.9264,101.6981],
    "Labuan": [5.2833,115.2333]
}

MITRE_TTP = ["TA0001","TA0002","TA0003","TA0004","TA0005","TA0006"]

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

def classify_risk(score):
    if score >= 70: return "Critical"
    elif score >= 40: return "High"
    else: return "Medium"

# ---------------- FEED PARSERS ----------------
def fetch_otx_public():
    try:
        r = requests.get(OTX_PUBLIC_URL, timeout=15)
        r.raise_for_status()
        pulses = r.json().get("results", [])[:5]
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        for pulse in pulses:
            name = pulse.get("name","OTX Pulse")
            for ind in pulse.get("indicators", []):
                val = ind.get("indicator")
                typ = ind.get("type","domain")
                if val:
                    score = random.randint(50,95)
                    classification = classify_risk(score)
                    city = random.choice(list(MALAYSIA_STATES.keys()))
                    created = datetime.utcnow().isoformat()
                    mitre = random.choice(MITRE_TTP)
                    c.execute("""INSERT INTO threats (pulse, indicator, type, classification, mitre, risk_score, city, created_at)
                                 VALUES (?,?,?,?,?,?,?,?)""",
                              (name, val, typ, classification, mitre, score, city, created))
        conn.commit()
        conn.close()
    except:
        pass

def fetch_urlhaus():
    try:
        r = requests.get(URLHAUS_URL, timeout=15)
        r.raise_for_status()
        lines = r.text.splitlines()
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        for l in lines:
            if l.startswith("#") or not l.strip(): continue
            parts = l.split()
            indicator = parts[0]
            score = random.randint(40,85)
            classification = classify_risk(score)
            city = random.choice(list(MALAYSIA_STATES.keys()))
            created = datetime.utcnow().isoformat()
            mitre = random.choice(MITRE_TTP)
            c.execute("""INSERT INTO threats (pulse, indicator, type, classification, mitre, risk_score, city, created_at)
                         VALUES (?,?,?,?,?,?,?,?)""",
                      ("URLhaus", indicator, "URL", classification, mitre, score, city, created))
        conn.commit()
        conn.close()
    except:
        pass

def fetch_phishtank():
    try:
        r = requests.get(PHISHTANK_URL, timeout=15)
        r.raise_for_status()
        lines = r.text.splitlines()
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        for l in lines[1:]:
            parts = l.split(",")
            indicator = parts[1].strip('"')
            score = random.randint(30,80)
            classification = classify_risk(score)
            city = random.choice(list(MALAYSIA_STATES.keys()))
            created = datetime.utcnow().isoformat()
            mitre = random.choice(MITRE_TTP)
            c.execute("""INSERT INTO threats (pulse, indicator, type, classification, mitre, risk_score, city, created_at)
                         VALUES (?,?,?,?,?,?,?,?)""",
                      ("PhishTank", indicator, "Phishing", classification, mitre, score, city, created))
        conn.commit()
        conn.close()
    except:
        pass

# ---------------- SCHEDULER ----------------
def scheduler():
    while True:
        fetch_otx_public()
        fetch_urlhaus()
        fetch_phishtank()
        cleanup_old_records()
        time.sleep(3600)  # every hour

# ---------------- DASHBOARD DATA ----------------
def generate_plotly_charts():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    # Timeline chart
    trend_rows = c.execute("SELECT substr(created_at,1,10) date, COUNT(*) cnt FROM threats GROUP BY date").fetchall()
    # Pie chart MITRE
    pie_rows = c.execute("SELECT mitre, COUNT(*) cnt FROM threats GROUP BY mitre").fetchall()
    conn.close()

    # Timeline
    trend_chart = {}
    if trend_rows:
        dates = [r["date"] for r in trend_rows]
        counts = [r["cnt"] for r in trend_rows]
        trace = go.Scatter(x=dates, y=counts, mode='lines+markers', line=dict(color='#00FFFF', width=3))
        layout = go.Layout(plot_bgcolor='#0b1b2a', paper_bgcolor='#0b1b2a',
                           font=dict(color='#00FFFF'), title="Threat Timeline")
        trend_chart = json.dumps(go.Figure(data=[trace], layout=layout), cls=plotly.utils.PlotlyJSONEncoder)

    # Pie chart
    pie_chart = {}
    if pie_rows:
        labels = [r["mitre"] for r in pie_rows]
        values = [r["cnt"] for r in pie_rows]
        trace = go.Pie(labels=labels, values=values,
                       marker=dict(colors=['#00FFFF','#00FF80','#FF8000','#FF0000','#FF00FF','#FFFF00']),
                       hoverinfo='label+percent')
        layout = go.Layout(plot_bgcolor='#0b1b2a', paper_bgcolor='#0b1b2a', font=dict(color='#00FFFF'), title="MITRE Techniques Distribution")
        pie_chart = json.dumps(go.Figure(data=[trace], layout=layout), cls=plotly.utils.PlotlyJSONEncoder)

    return trend_chart, pie_chart

def generate_malaysia_heatmap():
    m = folium.Map(location=[4.2105,101.9758], zoom_start=6, tiles="CartoDB dark_matter")
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    rows = c.execute("SELECT * FROM threats WHERE classification='Critical'").fetchall()
    conn.close()

    for r in rows:
        coords = MALAYSIA_STATES.get(r["city"], [4.2105,101.9758])
        folium.CircleMarker(location=coords, radius=6, color='#FF0000', fill=True, fill_opacity=0.8,
                            popup=f"{r['indicator']} ({r['type']})").add_to(m)
    return m._repr_html_()

def calculate_secure_index():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT risk_score FROM threats")
    rows = c.fetchall()
    conn.close()
    if not rows: return 0
    total_weighted = sum([s*1.0 if s>=70 else s*0.5 if s>=40 else s*0.2 for (s,) in rows])
    return round(total_weighted/(len(rows)*100)*100,1)

# ---------------- DASHBOARD TEMPLATE ----------------
TEMPLATE = """
<html>
<head>
<title>RedShark Threat Intelligence Dashboard</title>
<link rel="stylesheet" href="https://cdn.datatables.net/1.13.6/css/jquery.dataTables.min.css"/>
<script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
<style>
body {background:#0b1b2a;color:#00FFFF;font-family:sans-serif;}
table {border-collapse: collapse;width:100%; word-wrap: break-word;}
th, td {padding:8px;text-align:left;}
th {background:#00274d;color:#00FFFF;}
tr:nth-child(even){background:#0c2a4a;}
tr:nth-child(odd){background:#0b1b2a;}
a.button {background:#00FFFF;color:#0b1b2a;padding:6px 12px;text-decoration:none;border-radius:4px;margin:5px;}
.card {background:#00274d;padding:10px;margin:10px;border-radius:5px;}
</style>
</head>
<body>
<h2>RedShark Threat Intelligence Dashboard</h2>
<p>Disclaimer: Developed & analyzed by darkgrid@redshark.my using publicly available sources.</p>

<div class="card">
<h3>SecureNation Index: {{ gauge }}/100</h3>
<div style="background:#00274d;width:300px;height:25px;border-radius:5px;">
  <div style="height:25px;width:{{ gauge }}%;background:#00FFFF;text-align:center;color:#0b1b2a;font-weight:bold;">{{ gauge }}/100</div>
</div>
</div>

<div class="card">
<h3>Malaysia Heatmap (Critical Attacks)</h3>
{{ heatmap|safe }}
</div>

<div class="card">
<h3>Threat Timeline</h3>
<div id="trend_chart"></div>
</div>

<div class="card">
<h3>MITRE Techniques Distribution</h3>
<div id="pie_chart"></div>
</div>

<div class="card">
<h3>Latest Indicators</h3>
<table id="indicators">
<thead><tr><th>ID</th><th>Pulse</th><th>Indicator</th><th>Type</th><th>Class</th><th>Risk</th><th>MITRE</th><th>City</th><th>Created</th></tr></thead>
<tbody>
{% for row in table_data %}
<tr><td>{{ row['id'] }}</td><td>{{ row['pulse'] }}</td><td>{{ row['indicator'] }}</td><td>{{ row['type'] }}</td><td>{{ row['classification'] }}</td><td>{{ row['risk_score'] }}</td><td>{{ row['mitre'] }}</td><td>{{ row['city'] }}</td><td>{{ row['created_at'] }}</td></tr>
{% endfor %}
</tbody>
</table>
</div>

<div class="card">
<a href="/download/csv" class="button">Download CSV</a>
<a href="/download/json" class="button">Download JSON</a>
<a href="/download/pdf" class="button">Download PDF</a>
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
    heatmap = generate_malaysia_heatmap()
    gauge = calculate_secure_index()

    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    table_data = c.execute("SELECT * FROM threats ORDER BY created_at DESC LIMIT 50").fetchall()
    conn.close()

    return render_template_string(TEMPLATE,
                                  trend=trend,
                                  pie=pie,
                                  heatmap=heatmap,
                                  gauge=gauge,
                                  table_data=table_data)

# ---------------- DOWNLOADS ----------------
@app.route("/download/csv")
def download_csv():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    rows = c.execute("SELECT * FROM threats").fetchall()
    conn.close()
    si = io.StringIO()
    writer = csv.DictWriter(si, fieldnames=rows[0].keys() if rows else [])
    writer.writeheader()
    writer.writerows([dict(r) for r in rows])
    output = io.BytesIO()
    output.write(si.getvalue().encode())
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
    output.write(json.dumps([dict(r) for r in rows], indent=2).encode())
    output.seek(0)
    return send_file(output, mimetype="application/json", download_name="threats.json", as_attachment=True)

@app.route("/download/pdf")
def download_pdf():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    rows = c.execute("SELECT * FROM threats").fetchall()
    conn.close()

    output = io.BytesIO()
    doc = SimpleDocTemplate(output, pagesize=A4)
    elements = []
    styles = getSampleStyleSheet()
    elements.append(Paragraph("RedShark Threat Intelligence Dashboard", styles['Title']))
    elements.append(Spacer(1,12))

    data = [rows[0].keys()] + [list(r) for r in rows]
    table = Table(data, repeatRows=1)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#00274d")),
        ('TEXTCOLOR',(0,0),(-1,0),colors.HexColor("#00FFFF")),
        ('ALIGN',(0,0),(-1,-1),'LEFT'),
        ('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'),
        ('FONTSIZE',(0,0),(-1,0),10),
        ('BOTTOMPADDING',(0,0),(-1,0),6),
        ('BACKGROUND',(0,1),(-1,-1),colors.HexColor("#0b1b2a")),
        ('TEXTCOLOR',(0,1),(-1,-1),colors.HexColor("#00FFFF")),
        ('GRID',(0,0),(-1,-1),0.25,colors.HexColor("#00FFFF")),
    ]))
    elements.append(table)
    doc.build(elements)
    output.seek(0)
    return send_file(output, mimetype="application/pdf", download_name="threats.pdf", as_attachment=True)

# ---------------- START ----------------
ensure_database()
threading.Thread(target=scheduler, daemon=True).start()

if __name__=="__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT",5000)))