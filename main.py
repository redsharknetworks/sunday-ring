import os
import io
import csv
import base64
import sqlite3
import threading
import time
import random
from datetime import datetime

import requests
from flask import Flask, render_template_string, send_file, jsonify

from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle, PageBreak
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

import folium
from folium.plugins import HeatMap

# -------------------------------------------------
# CONFIG
# -------------------------------------------------
app = Flask(__name__)
DB = os.getenv("DB_PATH", "/tmp/threats.db")
OTX_KEY = os.getenv("OTX_KEY")
OTX_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"

# -------------------------------------------------
# DATABASE
# -------------------------------------------------
def ensure_database():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS threats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pulse TEXT,
        signal TEXT,
        type TEXT,
        classification TEXT,
        mitre TEXT,
        risk_score INTEGER,
        created_at TEXT
    )""")
    conn.commit()
    conn.close()

# -------------------------------------------------
# DUMMY DATA
# -------------------------------------------------
def insert_dummy_data():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    for i in range(20):
        pulse = f"Dummy Pulse {i+1}"
        signal = f"malicious{i+1}.com"
        created = datetime.utcnow().isoformat()
        score = random.randint(60, 95)
        c.execute("""
        INSERT INTO threats (pulse, signal, type, classification, mitre, risk_score, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)""",
                  (pulse, signal, "domain", "Medium", "OTX", score, created))
    conn.commit()
    conn.close()
    print("Inserted dummy data")

# -------------------------------------------------
# OTX FETCH
# -------------------------------------------------
def fetch_otx_data():
    ensure_database()
    if not OTX_KEY:
        print("No OTX key found — inserting dummy data")
        insert_dummy_data()
        return
    headers = {"X-OTX-API-KEY": OTX_KEY}
    try:
        r = requests.get(OTX_URL, headers=headers, timeout=15)
        r.raise_for_status()
        pulses = r.json().get("results", [])
    except Exception as e:
        print("OTX fetch failed:", e)
        insert_dummy_data()
        return

    conn = sqlite3.connect(DB)
    c = conn.cursor()
    for pulse in pulses[:10]:
        name = pulse.get("name", "OTX Pulse")
        indicators = pulse.get("indicators", [])
        for ind in indicators:
            val = ind.get("indicator")
            typ = ind.get("type", "domain")
            if not val:
                continue
            created = datetime.utcnow().isoformat()
            score = random.randint(60, 95)
            c.execute("""
            INSERT INTO threats (pulse, signal, type, classification, mitre, risk_score, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)""",
                      (name, val, typ, "Medium", "OTX", score, created))
    conn.commit()
    conn.close()
    print("OTX data updated")

# -------------------------------------------------
# SCHEDULER
# -------------------------------------------------
def scheduler():
    while True:
        fetch_otx_data()
        time.sleep(3600)

# -------------------------------------------------
# CHARTS
# -------------------------------------------------
def generate_trend_chart():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    trend = c.execute("""
    SELECT substr(created_at,1,10) as date, COUNT(*) as cnt
    FROM threats
    GROUP BY date ORDER BY date
    """).fetchall()
    conn.close()

    if not trend:
        return None

    dates = [x["date"] for x in trend]
    counts = [x["cnt"] for x in trend]

    plt.figure(figsize=(6,3))
    ax = plt.gca()
    # Boxing ring background if exists
    if os.path.exists("boxing_ring.png"):
        bg = plt.imread("boxing_ring.png")
        ax.imshow(bg, extent=[0,len(dates)-1,0,max(counts)+5], aspect='auto', alpha=0.2)

    plt.plot(dates, counts, marker="o", color="crimson")
    plt.title("Threat Trend")
    plt.xticks(rotation=45)
    plt.tight_layout()
    buf = io.BytesIO()
    plt.savefig(buf, format="png", facecolor="#0B3D91")  # dark blue background
    plt.close()
    buf.seek(0)
    return base64.b64encode(buf.getvalue()).decode()

def generate_type_chart():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    types = c.execute("""
    SELECT type, COUNT(*) as cnt
    FROM threats
    GROUP BY type
    """).fetchall()
    conn.close()
    if not types:
        return None
    labels = [x["type"] for x in types]
    values = [x["cnt"] for x in types]

    plt.figure(figsize=(4,3))
    plt.bar(labels, values, color="crimson")
    plt.title("Signal Types")
    plt.tight_layout()
    buf = io.BytesIO()
    plt.savefig(buf, format="png", facecolor="#0B3D91")
    plt.close()
    buf.seek(0)
    return base64.b64encode(buf.getvalue()).decode()

# -------------------------------------------------
# MALAYSIA HEATMAP
# -------------------------------------------------
def generate_heatmap():
    malaysia_coords = [
        [3.1390,101.6869,5],  # KL
        [2.1896,102.2501,3],  # Melaka
        [1.4927,103.7414,3],  # Johor
        [5.9804,116.0735,2],  # Kota Kinabalu
        [1.5533,110.3592,2],  # Kuching
        [6.1164,100.3678,2],  # Alor Setar
        [5.4164,100.3327,2],  # Penang
        [6.1254,102.2381,2],  # Kelantan
        [2.7290,101.9383,2],  # Seremban
        [4.5929,101.0900,2],  # Ipoh
        [5.3300,103.1400,2],  # Kuala Terengganu
        [3.8167,103.3333,2],  # Kuantan
    ]
    m = folium.Map(location=[4.2105,101.9758], zoom_start=6)
    HeatMap(malaysia_coords, radius=25).add_to(m)
    return m._repr_html_()

# -------------------------------------------------
# SUMMARY
# -------------------------------------------------
def generate_summary():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    total_signals = c.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
    high_risk = c.execute("SELECT COUNT(*) FROM threats WHERE risk_score>=85").fetchone()[0]
    types = c.execute("SELECT type, COUNT(*) as cnt FROM threats GROUP BY type").fetchall()
    conn.close()
    summary = f"RedShark has detected {total_signals} signals. {high_risk} high-risk signals observed. Signals by type: " + ", ".join([f"{x['type']}({x['cnt']})" for x in types])
    return summary

# -------------------------------------------------
# REPORT GENERATION
# -------------------------------------------------
def get_timestamp():
    return datetime.now().strftime("%Y%m%d%H%M%S")

def generate_pdf_report(trend_img, type_img, table_data, summary_text):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4)
    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph("RedShark Threat Intelligence Dashboard", styles['Title']))
    elements.append(Paragraph(summary_text, styles['Normal']))
    elements.append(Spacer(1,12))
    if trend_img:
        img = io.BytesIO(base64.b64decode(trend_img))
        elements.append(Image(img, width=400, height=200))
    if type_img:
        img2 = io.BytesIO(base64.b64decode(type_img))
        elements.append(Spacer(1,12))
        elements.append(Image(img2, width=300, height=200))
    # Table
    data = [["ID","Pulse","Signal","Type","Class","MITRE","Risk","Created"]]
    for row in table_data:
        data.append([row['id'], row['pulse'], row['signal'], row['type'], row['classification'], row['mitre'], row['risk_score'], row['created_at']])
    table = Table(data, repeatRows=1)
    table.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,0),colors.darkblue),
        ('TEXTCOLOR',(0,0),(-1,0),colors.whitesmoke),
        ('FONTNAME',(0,0),(-1,-1),'Helvetica'),
        ('FONTSIZE',(0,0),(-1,-1),9),
        ('ALIGN',(0,0),(-1,-1),'CENTER'),
        ('BACKGROUND',(0,1),(-1,-1),colors.lightblue),
        ('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.darkblue, colors.lightblue])
    ]))
    elements.append(Spacer(1,12))
    elements.append(table)
    # Disclaimer
    elements.append(Spacer(1,12))
    elements.append(Paragraph("Disclaimer: Developed by DarkGrid@redshark.my from publicly available sources", styles['Normal']))
    doc.build(elements)
    buffer.seek(0)
    return buffer

def generate_csv_report(table_data):
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(["ID","Pulse","Signal","Type","Class","MITRE","Risk","Created"])
    for row in table_data:
        cw.writerow([row['id'], row['pulse'], row['signal'], row['type'], row['classification'], row['mitre'], row['risk_score'], row['created_at']])
    output = io.BytesIO()
    output.write(si.getvalue().encode())
    output.seek(0)
    return output

def generate_json_report(table_data):
    return jsonify([dict(row) for row in table_data])

# -------------------------------------------------
# DASHBOARD TEMPLATE
# -------------------------------------------------
TEMPLATE = """
<html>
<head>
<title>RedShark Threat Intelligence Dashboard</title>
<link rel="stylesheet" href="https://cdn.datatables.net/1.13.6/css/jquery.dataTables.min.css">
<script src="https://code.jquery.com/jquery-3.7.1.js"></script>
<script src="https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js"></script>
<style>
body { background-color:#0B3D91; color:white; font-family:Arial, sans-serif; }
table.dataTable tbody tr:nth-child(odd){ background-color:#0B3D91; }
table.dataTable tbody tr:nth-child(even){ background-color:#4682B4; }
th, td { color:white; text-align:center; }
</style>
</head>
<body>
<h2>RedShark Threat Intelligence Dashboard</h2>

<h3>Malaysia Heatmap</h3>
{{ heatmap | safe }}

<h3>Trend</h3>
{% if trend %}
<img src="data:image/png;base64,{{ trend }}">
{% else %}<p>No trend data</p>{% endif %}

<h3>Signal Types</h3>
{% if type_chart %}
<img src="data:image/png;base64,{{ type_chart }}">
{% else %}<p>No type data</p>{% endif %}

<h3>Latest Signals</h3>
<p>{{ summary_text }}</p>
<table id="signals" class="display">
<thead>
<tr>
<th>ID</th>
<th>Pulse</th>
<th>Signal</th>
<th>Type</th>
<th>Class</th>
<th>MITRE</th>
<th>Risk</th>
<th>Created</th>
</tr>
</thead>
<tbody>
{% for row in table_data %}
<tr>
<td>{{ row['id'] }}</td>
<td>{{ row['pulse'] }}</td>
<td>{{ row['signal'] }}</td>
<td>{{ row['type'] }}</td>
<td>{{ row['classification'] }}</td>
<td>{{ row['mitre'] }}</td>
<td>{{ row['risk_score'] }}</td>
<td>{{ row['created_at'] }}</td>
</tr>
{% endfor %}
</tbody>
</table>

<script>
$(document).ready(function() {
    $('#signals').DataTable({
        "pageLength": 50,
        "order": [[7, "desc"]],
        "columnDefs": [{"orderable": true, "targets": "_all"}]
    });
});
</script>
</body>
</html>
"""

# -------------------------------------------------
# ROUTES
# -------------------------------------------------
@app.route("/")
def dashboard():
    trend = generate_trend_chart()
    type_chart = generate_type_chart()
    heatmap = generate_heatmap()
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    table_data = c.execute("SELECT * FROM threats ORDER BY created_at DESC LIMIT 50").fetchall()
    conn.close()
    summary_text = generate_summary()
    return render_template_string(TEMPLATE, trend=trend, type_chart=type_chart, heatmap=heatmap, table_data=table_data, summary_text=summary_text)

@app.route("/report/pdf")
def report_pdf():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    table_data = c.execute("SELECT * FROM threats ORDER BY created_at DESC").fetchall()
    conn.close()
    trend = generate_trend_chart()
    type_chart = generate_type_chart()
    summary_text = generate_summary()
    buf = generate_pdf_report(trend, type_chart, table_data, summary_text)
    filename = f"RedShark_DarkGrid_report{get_timestamp()}.pdf"
    return send_file(buf, as_attachment=True, download_name=filename)

@app.route("/report/csv")
def report_csv():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    table_data = c.execute("SELECT * FROM threats ORDER BY created_at DESC").fetchall()
    conn.close()
    buf = generate_csv_report(table_data)
    filename = f"RedShark_DarkGrid_report{get_timestamp()}.csv"
    return send_file(buf, as_attachment=True, download_name=filename)

@app.route("/report/json")
def report_json():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    table_data = c.execute("SELECT * FROM threats ORDER BY created_at DESC").fetchall()
    conn.close()
    return generate_json_report(table_data)

# -------------------------------------------------
# START
# -------------------------------------------------
ensure_database()
fetch_otx_data()
if not os.getenv("RUN_MAIN"):
    threading.Thread(target=scheduler, daemon=True).start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT",5000)))
