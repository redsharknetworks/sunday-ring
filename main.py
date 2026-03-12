import os
import io
import csv
import sqlite3
import threading
import random
from datetime import datetime, timedelta
from flask import Flask, render_template_string, send_file, jsonify
import folium
import plotly
import plotly.graph_objs as go
import json
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet

# ---------------- CONFIG ----------------
app = Flask(__name__)
DB_PATH = os.getenv("DB_PATH", "/tmp/threats.db")

# ---------------- DATABASE ----------------
def get_db_connection():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def ensure_database():
    conn = get_db_connection()
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
            created_at TEXT
        )
    """)
    conn.commit()
    conn.close()

def cleanup_old_records():
    conn = get_db_connection()
    c = conn.cursor()
    cutoff = (datetime.utcnow() - timedelta(days=60)).isoformat()
    c.execute("DELETE FROM threats WHERE created_at < ?", (cutoff,))
    conn.commit()
    conn.close()

# ---------------- SAMPLE DATA ----------------
MITRE_ATTACKS = ["Initial Access","Execution","Persistence","Privilege Escalation",
                 "Defense Evasion","Credential Access","Discovery","Lateral Movement",
                 "Collection","Exfiltration","Command and Control"]

MALAYSIA_STATES = {
    "Johor": [1.4927,103.7414],"Kedah": [6.1164,100.3678],"Kelantan": [6.1254,102.2381],
    "Melaka": [2.1896,102.2501],"Negeri Sembilan": [2.7290,101.9383],"Pahang": [3.8167,103.3333],
    "Perak": [4.5929,101.0900],"Perlis": [6.4400,100.2000],"Penang": [5.4164,100.3327],
    "Sabah": [5.9804,116.0735],"Sarawak": [1.5533,110.3592],"Selangor": [3.1390,101.6869],
    "Terengganu": [5.3300,103.1400],"Kuala Lumpur": [3.1390,101.6869],"Putrajaya": [2.9264,101.6981],
    "Labuan": [5.2833,115.2333]
}

def classify_risk(score):
    if score >= 70: return "Critical"
    elif score >= 40: return "High"
    else: return "Medium"

def insert_dummy_data(n=3):
    conn = get_db_connection()
    c = conn.cursor()
    for _ in range(n):
        created = datetime.utcnow().isoformat()
        score = random.randint(10,95)
        classification = classify_risk(score)
        mitre = random.choice(MITRE_ATTACKS)
        c.execute("""INSERT INTO threats (pulse, indicator, type, classification, mitre, risk_score, created_at)
                     VALUES (?, ?, ?, ?, ?, ?, ?)""",
                  (f"Pulse-{random.randint(1,50)}",
                   f"malicious-{random.randint(1,100)}.com",
                   "domain",
                   classification,
                   mitre,
                   score,
                   created))
    conn.commit()
    conn.close()

# ---------------- SCHEDULER ----------------
def scheduler():
    while True:
        insert_dummy_data(3)
        cleanup_old_records()
        # run every 30 min
        threading.Event().wait(1800)

# ---------------- DASHBOARD DATA ----------------
def fetch_dashboard_data(limit=50):
    conn = get_db_connection()
    rows = conn.cursor().execute(
        "SELECT * FROM threats ORDER BY created_at DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def calculate_secure_index():
    rows = fetch_dashboard_data(50)
    if not rows: return 0
    total = 0
    for r in rows:
        s = r.get("risk_score",0)
        if s >=70: total += s*1.0
        elif s >=40: total += s*0.5
        else: total += s*0.2
    return round(total/(len(rows)*100)*100,1)

def generate_plotly_charts():
    rows = fetch_dashboard_data(50)
    # Timeline
    date_counts = {}
    for r in rows:
        date = r["created_at"][:10]
        date_counts[date] = date_counts.get(date,0)+1
    dates = sorted(date_counts.keys())
    counts = [date_counts[d] for d in dates]
    timeline_chart = go.Figure()
    timeline_chart.add_trace(go.Scatter(x=dates, y=counts, mode='lines+markers', line=dict(color='#00FFFF')))
    timeline_chart.update_layout(title="Threat Timeline", plot_bgcolor='#0b1b2a', paper_bgcolor='#0b1b2a', font_color='#00FFFF')

    # MITRE pie
    mitre_counts = {}
    for r in rows:
        mitre = r.get("mitre","Unknown")
        mitre_counts[mitre] = mitre_counts.get(mitre,0)+1
    labels = list(mitre_counts.keys())
    values = list(mitre_counts.values())
    pie_chart = go.Figure()
    pie_chart.add_trace(go.Pie(labels=labels, values=values, hole=0.4,
                               marker=dict(colors=[f'rgba(0,255,255,{0.7+0.3*random.random()})' for _ in labels])))
    pie_chart.update_layout(title="MITRE Attack Distribution", plot_bgcolor='#0b1b2a', paper_bgcolor='#0b1b2a', font_color='#00FFFF')

    return json.dumps(timeline_chart, cls=plotly.utils.PlotlyJSONEncoder), json.dumps(pie_chart, cls=plotly.utils.PlotlyJSONEncoder)

def generate_heatmap():
    rows = [r for r in fetch_dashboard_data(50) if r["risk_score"]>=70][:10]  # only top 10 critical
    m = folium.Map(location=[4.2105,101.9758], zoom_start=6, tiles='CartoDB dark_matter')
    for r in rows:
        state = random.choice(list(MALAYSIA_STATES.keys()))
        coords = MALAYSIA_STATES[state]
        folium.CircleMarker(location=coords,
                            radius=6,
                            color='red',
                            fill=True,
                            fill_opacity=0.8,
                            popup=f"{r['indicator']} - {r['classification']}").add_to(m)
    return m._repr_html_()

# ---------------- PDF ----------------
def generate_pdf(rows):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=landscape(A4))
    elements = []
    styles = getSampleStyleSheet()
    elements.append(Paragraph("RedShark Threat Intelligence Dashboard", styles['Heading1']))
    elements.append(Spacer(1,12))
    table_data = [["ID","Pulse","Indicator","Type","Class","MITRE","Risk","Created"]]
    for r in rows:
        table_data.append([r["id"], r["pulse"], r["indicator"], r["type"], r["classification"], r["mitre"], r["risk_score"], r["created_at"]])
    table = Table(table_data, repeatRows=1)
    table.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,0),colors.HexColor("#00274d")),
        ('TEXTCOLOR',(0,0),(-1,0),colors.white),
        ('GRID',(0,0),(-1,-1),1,colors.HexColor("#00FFFF")),
        ('BACKGROUND',(0,1),(-1,-1),colors.HexColor("#0b1b2a")),
        ('ALIGN',(0,0),(-1,-1),'CENTER'),
    ]))
    elements.append(table)
    doc.build(elements)
    buffer.seek(0)
    return buffer

# ---------------- TEMPLATE ----------------
TEMPLATE = """<html>
<head>
<title>RedShark Threat Intelligence Dashboard</title>
<link rel="stylesheet" href="https://cdn.datatables.net/1.13.6/css/jquery.dataTables.min.css"/>
<script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
<style>
body {background:#0b1b2a;color:#00FFFF;font-family:sans-serif;margin:0;padding:0;}
h2,h3{color:#00FFFF;}
table.dataTable{width:100% !important;}
th, td {padding:8px;text-align:left;}
th {background:#00274d;color:#00FFFF;}
tr:nth-child(even){background:#0c2a4a;}
tr:nth-child(odd){background:#0b1b2a;}
a.button {background:#00FFFF;color:#0b1b2a;padding:6px 12px;text-decoration:none;border-radius:4px;margin-right:8px;}
.card {background:#00274d;padding:10px;margin:10px;border-radius:5px;}
</style>
</head>
<body>
<h2>RedShark Threat Intelligence Dashboard</h2>
<p>Disclaimer: Developed & analyzed by darkgrid@redshark.my using publicly available sources.</p>

<div class="card">
<h3>SecureNation Index: {{ gauge }}/100</h3>
<div style="background:#00274d;width:300px;height:25px;border-radius:5px;">
  <div style="height:25px;width:{{ gauge }}%;background:#00FFFF;text-align:center;color:#0b1b2a;font-weight:bold;" title="SecureNation Index">{{ gauge }}/100</div>
</div>
</div>

<div class="card">
<h3>Malaysia Heatmap</h3>
{{ heatmap | safe }}
</div>

<div class="card">
<h3>Threat Timeline</h3>
<div id="timeline_chart"></div>
</div>

<div class="card">
<h3>MITRE Attack Distribution</h3>
<div id="pie_chart"></div>
</div>

<div class="card">
<h3>Latest Indicators</h3>
<table id="indicators">
<thead><tr><th>ID</th><th>Pulse</th><th>Indicator</th><th>Type</th><th>Class</th><th>MITRE</th><th>Risk</th><th>Created</th></tr></thead>
<tbody>
{% for row in table_data %}
<tr>
<td>{{ row['id'] }}</td><td>{{ row['pulse'] }}</td><td>{{ row['indicator'] }}</td><td>{{ row['type'] }}</td>
<td>{{ row['classification'] }}</td><td>{{ row['mitre'] }}</td><td>{{ row['risk_score'] }}</td><td>{{ row['created_at'] }}</td>
</tr>
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
    Plotly.newPlot('timeline_chart', {{ timeline | safe }}.data, {{ timeline | safe }}.layout);
    Plotly.newPlot('pie_chart', {{ pie | safe }}.data, {{ pie | safe }}.layout);
});
</script>
</body>
</html>
"""

# ---------------- ROUTES ----------------
@app.route("/")
def dashboard():
    table_data = fetch_dashboard_data()
    gauge = calculate_secure_index()
    heatmap = generate_heatmap()
    timeline, pie = generate_plotly_charts()
    return render_template_string(TEMPLATE,
                                  table_data=table_data,
                                  gauge=gauge,
                                  heatmap=heatmap,
                                  timeline=timeline,
                                  pie=pie)

@app.route("/download/csv")
def download_csv():
    rows = fetch_dashboard_data(50)
    si = io.StringIO()
    cw = csv.DictWriter(si, fieldnames=["id","pulse","indicator","type","classification","mitre","risk_score","created_at"])
    cw.writeheader()
    cw.writerows(rows)
    output = io.BytesIO()
    output.write(si.getvalue().encode())
    output.seek(0)
    return send_file(output, mimetype="text/csv", download_name="threats.csv", as_attachment=True)

@app.route("/download/json")
def download_json():
    rows = fetch_dashboard_data(50)
    output = io.BytesIO()
    output.write(json.dumps(rows, indent=2).encode())
    output.seek(0)
    return send_file(output, mimetype="application/json", download_name="threats.json", as_attachment=True)

@app.route("/download/pdf")
def download_pdf():
    rows = fetch_dashboard_data(50)
    buffer = generate_pdf(rows)
    return send_file(buffer, mimetype="application/pdf", download_name="threats.pdf", as_attachment=True)

# ---------------- START ----------------
if __name__=="__main__":
    ensure_database()
    insert_dummy_data(5)
    threading.Thread(target=scheduler, daemon=True).start()
    app.run(host="0.0.0.0", port=int(os.getenv("PORT",5000)))