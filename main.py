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

from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer,
    Image, Table, TableStyle, PageBreak
)
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
        c.execute("""
        INSERT INTO threats
        (pulse, indicator, type, classification, mitre, risk_score, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (
            f"Dummy Pulse {i+1}",
            f"malicious{i+1}.com",
            "domain",
            "Medium",
            "T1059",
            random.randint(60,95),
            datetime.utcnow().isoformat()
        ))
    conn.commit()
    conn.close()

# ---------------- SECURE INDEX ----------------
def calculate_secure_index():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT AVG(risk_score) FROM threats")
    avg = c.fetchone()[0]
    conn.close()
    return round(avg or 0,1)

def generate_gauge():
    index = calculate_secure_index()
    fig, ax = plt.subplots(figsize=(5,2.5))
    ax.barh([0],[index], color="#ff7f00")
    ax.set_xlim(0,100)
    ax.set_yticks([])
    ax.set_title(f"SecureNation Index: {index}", color="white", pad=20)
    buf = io.BytesIO()
    plt.tight_layout(pad=3)
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
        plt.figure(figsize=(7,4))
        plt.plot(dates, counts, marker="o", color="#ff7f00")
        plt.xticks(rotation=45, ha='right')
        plt.title("Threat Trend", pad=20)
        plt.tight_layout(pad=3)
        buf = io.BytesIO()
        plt.savefig(buf, format="png", facecolor="#0d1b2a")
        plt.close()
        trend_img = base64.b64encode(buf.getvalue()).decode()

    if types:
        labels = [x["type"] for x in types]
        values = [x["cnt"] for x in types]
        plt.figure(figsize=(7,4))
        plt.bar(labels, values, color="#ff7f00")
        plt.xticks(rotation=30)
        plt.title("Indicator Types", pad=20)
        plt.tight_layout(pad=3)
        buf = io.BytesIO()
        plt.savefig(buf, format="png", facecolor="#0d1b2a")
        plt.close()
        type_img = base64.b64encode(buf.getvalue()).decode()

    return trend_img, type_img

# ---------------- MALAYSIA IBU NEGERI ----------------
IBU_NEGERI = {
    "Johor Bahru":[1.4927,103.7414],
    "Alor Setar":[6.1248,100.3678],
    "Kota Bharu":[6.1254,102.2381],
    "Melaka":[2.1896,102.2501],
    "Seremban":[2.7297,101.9381],
    "Kuantan":[3.8167,103.3333],
    "Ipoh":[4.5975,101.0901],
    "Kangar":[6.4400,100.1986],
    "George Town":[5.4141,100.3288],
    "Kota Kinabalu":[5.9804,116.0735],
    "Kuching":[1.5533,110.3592],
    "Shah Alam":[3.0738,101.5183],
    "Kuala Terengganu":[5.3302,103.1408],
    "Kuala Lumpur":[3.1390,101.6869],
    "Putrajaya":[2.9264,101.6964]
}

def generate_heatmap():
    m = folium.Map(location=[4.2,101.97], zoom_start=6, tiles="CartoDB dark_matter")
    heat_data = []
    for coords in IBU_NEGERI.values():
        heat_data.append([coords[0], coords[1], random.randint(1,10)])
    HeatMap(heat_data, radius=25).add_to(m)
    return m._repr_html_()

# ---------------- TEMPLATE ----------------
TEMPLATE = """
<html>
<head>
<title>RedShark Dashboard</title>
<style>
body {background:#0d1b2a;color:white;font-family:sans-serif;}
table {width:100%;border-collapse:collapse;}
th,td {padding:8px;word-wrap:break-word;}
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

<div style="display:flex;justify-content:space-between;">
<div>
<h1 style="margin:0;color:#ff7f00;">RedShark</h1>
<p style="opacity:0.7;">Threat Intelligence & National Risk Monitoring</p>
</div>
<div style="font-size:13px;opacity:0.6;">
{{ current_time }}
</div>
</div>
<hr style="border:1px solid #1b2a44;margin:20px 0;">

<p style="font-size:13px;opacity:0.75;">
<b>Disclaimer:</b> Developed and analysed by darkgrid@redshark.my using publicly available source.
</p>

<h3>SecureNation Index</h3>
<img src="data:image/png;base64,{{ gauge }}">

<h3>Malaysia (Ibu Negeri Heatmap)</h3>
{{ heatmap|safe }}

<h3>Threat Trend</h3>
{% if trend %}<img src="data:image/png;base64,{{ trend }}">{% endif %}

<h3>Indicator Types</h3>
{% if type_chart %}<img src="data:image/png;base64,{{ type_chart }}">{% endif %}

<h3>Executive Summary</h3>
<p>{{ summary }}</p>

<h3>Top 20 High Risk Indicators</h3>
<table>
<tr><th>ID</th><th>Indicator</th><th>Type</th><th>MITRE</th><th>Risk</th></tr>
{% for row in rows %}
<tr>
<td>{{ row['id'] }}</td>
<td style="max-width:200px;">{{ row['indicator'] }}</td>
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

# ---------------- ROUTES ----------------
@app.route("/")
def dashboard():
    ensure_database()
    trend, type_chart = generate_charts()
    heatmap = generate_heatmap()
    gauge = generate_gauge()

    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    rows = c.execute("SELECT * FROM threats ORDER BY risk_score DESC LIMIT 20").fetchall()
    total = c.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
    conn.close()

    avg = calculate_secure_index()

    summary = (
        f"{total} indicators analysed with average risk score {avg}. "
        f"Elevated malicious infrastructure detected. "
        f"Recommended actions: enable DNS filtering, deploy EDR, "
        f"review outbound firewall rules, enforce MFA, and conduct proactive threat hunting."
    )

    return render_template_string(
        TEMPLATE,
        trend=trend,
        type_chart=type_chart,
        heatmap=heatmap,
        gauge=gauge,
        rows=rows,
        summary=summary,
        current_time=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    )

# ---------------- REPORTS ----------------
@app.route("/report/csv")
def csv_report():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    rows = c.execute("SELECT * FROM threats").fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID","Pulse","Indicator","Type","Class","MITRE","Risk","Created"])
    writer.writerows(rows)

    mem = io.BytesIO()
    mem.write(output.getvalue().encode())
    mem.seek(0)

    return send_file(mem, as_attachment=True,
                     download_name="RedShark_Report.csv",
                     mimetype="text/csv")

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

    return send_file(mem, as_attachment=True,
                     download_name="RedShark_Report.json",
                     mimetype="application/json")

@app.route("/report/pdf")
def pdf_report():
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph("RedShark Threat Intelligence Report", styles["Title"]))
    elements.append(Spacer(1,12))
    elements.append(Paragraph(
        "Developed and analysed by darkgrid@redshark.my using publicly available source.",
        styles["Normal"]))
    elements.append(Spacer(1,12))
    elements.append(PageBreak())

    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    rows = c.execute("SELECT * FROM threats ORDER BY risk_score DESC LIMIT 20").fetchall()
    conn.close()

    data = [["ID","Indicator","Type","MITRE","Risk"]]
    for r in rows:
        data.append([r["id"], r["indicator"][:35], r["type"], r["mitre"], r["risk_score"]])

    table = Table(data, colWidths=[40,160,80,80,50], repeatRows=1)
    table.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,0),colors.black),
        ('TEXTCOLOR',(0,0),(-1,0),colors.white),
        ('GRID',(0,0),(-1,-1),0.3,colors.grey),
        ('FONTSIZE',(0,0),(-1,-1),8)
    ]))

    elements.append(table)

    def add_page_number(canvas, doc):
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.grey)
        canvas.drawRightString(580, 15, f"Page {doc.page}")
        canvas.drawString(40, 15, "RedShark Intelligence Report")

    doc.build(elements, onFirstPage=add_page_number, onLaterPages=add_page_number)
    buffer.seek(0)

    return send_file(buffer, as_attachment=True,
                     download_name="RedShark_Executive_Report.pdf",
                     mimetype="application/pdf")

# ---------------- START ----------------
ensure_database()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT",5000)))
