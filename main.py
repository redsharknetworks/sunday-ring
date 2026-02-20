import os
import io
import csv
import json
import base64
import sqlite3
import threading
import time
import random
from datetime import datetime

import requests
from flask import Flask, render_template_string, send_file

from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle, PageBreak
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

import folium
from folium.plugins import HeatMap

# ---------------- CONFIG ----------------
app = Flask(__name__)
DB = os.getenv("DB_PATH", "/tmp/threats.db")
OTX_KEY = os.getenv("OTX_KEY")
OTX_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"
BOXING_RING = "boxing_ring.png"

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
        created_at TEXT
    )""")
    conn.commit()
    conn.close()

# ---------------- DUMMY DATA ----------------
def insert_dummy_data():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    for i in range(20):
        pulse = f"Dummy Pulse {i+1}"
        indicator = f"malicious{i+1}.com"
        score = random.randint(60, 95)
        created = datetime.utcnow().isoformat()
        c.execute("""
        INSERT INTO threats
        (pulse, indicator, type, classification, mitre, risk_score, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (pulse, indicator, "domain", "Medium", "T1059", score, created))
    conn.commit()
    conn.close()

# ---------------- OTX FETCH ----------------
def fetch_otx_data():
    ensure_database()
    if not OTX_KEY:
        insert_dummy_data()
        return
    headers = {"X-OTX-API-KEY": OTX_KEY}
    try:
        r = requests.get(OTX_URL, headers=headers, timeout=15)
        r.raise_for_status()
        pulses = r.json().get("results", [])
    except:
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
            score = random.randint(60, 95)
            created = datetime.utcnow().isoformat()
            c.execute("""
            INSERT INTO threats
            (pulse, indicator, type, classification, mitre, risk_score, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (name, val, typ, "Medium", "T1059", score, created))
    conn.commit()
    conn.close()

# ---------------- SCHEDULER ----------------
def scheduler():
    while True:
        fetch_otx_data()
        time.sleep(3600)

# ---------------- SECURE INDEX ----------------
def calculate_secure_index():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT AVG(risk_score) FROM threats")
    avg = c.fetchone()[0]
    conn.close()
    return round(avg or 0, 1)

def generate_gauge():
    index = calculate_secure_index()
    fig, ax = plt.subplots(figsize=(4,2))
    ax.barh([0],[index], color="#ff7f00")
    ax.set_xlim(0,100)
    ax.set_yticks([])
    ax.set_title(f"SecureNation Index: {index}", color="white")
    buf = io.BytesIO()
    plt.tight_layout()
    plt.savefig(buf, format="png", facecolor="#0d1b2a")
    plt.close()
    return base64.b64encode(buf.getvalue()).decode()

# ---------------- CHARTS ----------------
def generate_charts():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    trend = c.execute("""
        SELECT substr(created_at,1,10) as date, COUNT(*) as cnt
        FROM threats GROUP BY date ORDER BY date
    """).fetchall()

    types = c.execute("""
        SELECT type, COUNT(*) as cnt
        FROM threats GROUP BY type
    """).fetchall()

    conn.close()

    trend_img = None
    type_img = None

    if trend:
        dates = [x["date"] for x in trend]
        counts = [x["cnt"] for x in trend]
        plt.figure(figsize=(6,3))
        plt.plot(dates, counts, marker="o", color="#ff7f00")
        plt.xticks(rotation=45)
        plt.title("Threat Trend")
        buf = io.BytesIO()
        plt.tight_layout()
        plt.savefig(buf, format="png", facecolor="#0d1b2a")
        plt.close()
        trend_img = base64.b64encode(buf.getvalue()).decode()

    if types:
        labels = [x["type"] for x in types]
        values = [x["cnt"] for x in types]
        plt.figure(figsize=(6,4))
        plt.bar(labels, values, color="#ff7f00")
        plt.title("Indicator Types")
        buf = io.BytesIO()
        plt.tight_layout()
        plt.savefig(buf, format="png", facecolor="#0d1b2a")
        plt.close()
        type_img = base64.b64encode(buf.getvalue()).decode()

    return trend_img, type_img

# ---------------- HEATMAP ----------------
def generate_heatmap():
    m = folium.Map(location=[4.2105,101.9758], zoom_start=6, tiles="CartoDB dark_matter")
    heat_data = [[random.uniform(1,7), random.uniform(100,120), random.randint(1,10)] for _ in range(20)]
    HeatMap(heat_data, radius=25).add_to(m)
    return m._repr_html_()

# ---------------- DASHBOARD ----------------
TEMPLATE = """
<html>
<head>
<title>RedShark Dashboard</title>
<style>
body {background:#0d1b2a;color:white;font-family:sans-serif;}
table {width:100%;border-collapse:collapse;}
th,td {padding:8px;}
th {background:#ff7f00;}
tr:nth-child(even){background:#1b2a44;}
.button {
background:#ff7f00;
padding:12px 20px;
color:white;
text-decoration:none;
border-radius:6px;
font-weight:bold;
margin-right:10px;
}
.button:hover {background:#ff9900;}
</style>
</head>
<body>
<h2>RedShark Threat Intelligence Dashboard</h2>
<p><b>Disclaimer:</b> Developed using publicly available threat intelligence sources.</p>

<h3>SecureNation Index</h3>
<img src="data:image/png;base64,{{ gauge }}">

<h3>Malaysia Heatmap</h3>
{{ heatmap|safe }}

<h3>Trend</h3>
{% if trend %}
<img src="data:image/png;base64,{{ trend }}">
{% endif %}

<h3>Indicator Types</h3>
{% if type_chart %}
<img src="data:image/png;base64,{{ type_chart }}">
{% endif %}

<h3>Summary</h3>
<p>{{ summary }}</p>

<h3>Latest Indicators</h3>
<table>
<tr><th>ID</th><th>Indicator</th><th>Type</th><th>MITRE</th><th>Risk</th></tr>
{% for row in rows %}
<tr>
<td>{{ row['id'] }}</td>
<td>{{ row['indicator'] }}</td>
<td>{{ row['type'] }}</td>
<td>{{ row['mitre'] }}</td>
<td>{{ row['risk_score'] }}</td>
</tr>
{% endfor %}
</table>

<h3>Download Reports</h3>
<a class="button" href="/report/pdf">Download PDF</a>
<a class="button" href="/report/csv">Download CSV</a>
<a class="button" href="/report/json">Download JSON</a>

</body>
</html>
"""

@app.route("/")
def dashboard():
    trend, type_chart = generate_charts()
    heatmap = generate_heatmap()
    gauge = generate_gauge()

    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    rows = c.execute("SELECT * FROM threats ORDER BY created_at DESC LIMIT 50").fetchall()
    summary_row = c.execute("SELECT COUNT(*), AVG(risk_score) FROM threats").fetchone()
    conn.close()

    total = summary_row[0] or 0
    avg = round(summary_row[1] or 0, 1)
    summary = f"Total Indicators: {total} | Average Risk Score: {avg}"

    return render_template_string(TEMPLATE,
                                  trend=trend,
                                  type_chart=type_chart,
                                  heatmap=heatmap,
                                  gauge=gauge,
                                  rows=rows,
                                  summary=summary)

# ---------------- REPORT ROUTES ----------------
@app.route("/report/csv")
def csv_report():
    output = io.StringIO()
    writer = csv.writer(output)
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    rows = c.execute("SELECT * FROM threats").fetchall()
    conn.close()
    writer.writerow(["ID","Pulse","Indicator","Type","Class","MITRE","Risk","Created"])
    writer.writerows(rows)
    mem = io.BytesIO()
    mem.write(output.getvalue().encode())
    mem.seek(0)
    return send_file(mem, as_attachment=True, download_name="report.csv", mimetype="text/csv")

@app.route("/report/json")
def json_report():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    rows = c.execute("SELECT * FROM threats").fetchall()
    conn.close()
    data = [dict(x) for x in rows]
    mem = io.BytesIO()
    mem.write(json.dumps(data, indent=4).encode())
    mem.seek(0)
    return send_file(mem, as_attachment=True, download_name="report.json", mimetype="application/json")

@app.route("/report/pdf")
def pdf_report():
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []
    elements.append(Paragraph("RedShark Threat Intelligence Report", styles["Title"]))
    elements.append(Spacer(1,12))
    elements.append(Paragraph(f"SecureNation Index: {calculate_secure_index()}", styles["Normal"]))
    elements.append(PageBreak())

    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    rows = c.execute("SELECT * FROM threats ORDER BY risk_score DESC LIMIT 20").fetchall()
    conn.close()

    data = [["ID","Indicator","Type","MITRE","Risk"]]
    for r in rows:
        data.append([r["id"], r["indicator"], r["type"], r["mitre"], r["risk_score"]])

    table = Table(data, colWidths=[40,150,80,80,50])
    table.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,0),colors.black),
        ('TEXTCOLOR',(0,0),(-1,0),colors.white),
        ('GRID',(0,0),(-1,-1),0.5,colors.grey),
        ('FONTSIZE',(0,0),(-1,-1),8)
    ]))
    elements.append(table)

    doc.build(elements)
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name="report.pdf", mimetype="application/pdf")

# ---------------- START ----------------
ensure_database()
fetch_otx_data()

if __name__ == "__main__":
    threading.Thread(target=scheduler, daemon=True).start()
    app.run(host="0.0.0.0", port=int(os.getenv("PORT",5000)))
