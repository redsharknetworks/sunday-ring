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
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfbase import pdfmetrics

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
    for i in range(5):
        pulse = f"Dummy Pulse {i+1}"
        indicator = f"malicious{i+1}.com"
        score = random.randint(60, 95)
        created = datetime.utcnow().isoformat()
        c.execute("""INSERT INTO threats
        (pulse, indicator, type, classification, mitre, risk_score, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (pulse, indicator, "domain", "Medium", "T1071", score, created))
    conn.commit()
    conn.close()
    print("Inserted dummy data")

# ---------------- OTX FETCH ----------------
def fetch_otx_data():
    ensure_database()
    if not OTX_KEY:
        print("No OTX key found — using dummy data.")
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
            score = random.randint(60, 95)
            created = datetime.utcnow().isoformat()
            c.execute("""INSERT INTO threats
            (pulse, indicator, type, classification, mitre, risk_score, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (name, val, typ, "Medium", "T1071", score, created))
    conn.commit()
    conn.close()
    print("OTX data updated")

# ---------------- SCHEDULER ----------------
def scheduler():
    while True:
        fetch_otx_data()
        time.sleep(3600)

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

    # Trend chart
    if trend:
        dates = [x["date"] for x in trend]
        counts = [x["cnt"] for x in trend]
        plt.figure(figsize=(8,3))
        ax = plt.gca()
        if os.path.exists(BOXING_RING):
            bg = plt.imread(BOXING_RING)
            ax.imshow(bg, extent=[0,len(dates)-1,0,max(counts)+5], aspect='auto', alpha=0.2)
        plt.plot(dates, counts, marker="o", color="#f77f00")
        plt.title("Threat Trend", color="white")
        plt.xticks(rotation=45, color="white")
        plt.yticks(color="white")
        buf = io.BytesIO()
        plt.tight_layout()
        plt.savefig(buf, format="png", facecolor="#0d1b2a")
        plt.close()
        trend_img = base64.b64encode(buf.getvalue()).decode()

    # Type chart
    if types:
        labels = [x["type"] for x in types]
        values = [x["cnt"] for x in types]
        plt.figure(figsize=(6,4))
        plt.bar(labels, values, color="#00b4d8")
        plt.title("Indicator Types", color="white")
        plt.xticks(rotation=45, color="white")
        plt.yticks(color="white")
        buf = io.BytesIO()
        plt.tight_layout()
        plt.savefig(buf, format="png", facecolor="#0d1b2a")
        plt.close()
        type_img = base64.b64encode(buf.getvalue()).decode()

    return trend_img, type_img

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
    m = folium.Map(location=[4.2105,101.9758], zoom_start=6, tiles="CartoDB dark_matter")
    heat_data = []
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    for state, coords in MALAYSIA_STATES.items():
        count = random.randint(1,10)
        heat_data.append([coords[0], coords[1], count])
    conn.close()
    HeatMap(heat_data, radius=25).add_to(m)
    return m._repr_html_()

# ---------------- SECURENATION INDEX ----------------
def calculate_secure_index():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT AVG(risk_score) as avg_risk FROM threats")
    avg_risk = c.fetchone()[0] or 0
    conn.close()
    return round(avg_risk,1)

def generate_secure_gauge():
    index = calculate_secure_index()
    fig, ax = plt.subplots(figsize=(4,2))
    ax.barh([0],[index], color="#f77f00")
    ax.set_xlim(0,100)
    ax.set_yticks([])
    ax.set_title(f"SecureNation Index: {index}", color="white")
    buf = io.BytesIO()
    plt.tight_layout()
    plt.savefig(buf, format="png", facecolor="#0d1b2a")
    plt.close()
    return base64.b64encode(buf.getvalue()).decode()

# ---------------- DASHBOARD TEMPLATE ----------------
TEMPLATE = """
<html>
<head>
<title>RedShark Threat Intelligence Dashboard</title>
<style>
body {background:#0d1b2a;color:white;font-family:sans-serif;}
table {border-collapse: collapse;width:100%;}
th,td {padding:6px;text-align:left;}
tr:nth-child(even){background:#1b2a44;}
tr:nth-child(odd){background:#0d1b2a;}
th {background:#1b2a44;color:#f77f00;cursor:pointer;}
button {margin:5px;padding:8px;background:#f77f00;color:white;border:none;border-radius:3px;cursor:pointer;}
</style>
</head>
<body>
<h2>RedShark Threat Intelligence Dashboard</h2>
<p><strong>Disclaimer:</strong> Developed by DarkGrid@redshark.my using publicly available sources.</p>

<button onclick="window.location='/report/pdf'">Download PDF</button>
<button onclick="window.location='/report/csv'">Download CSV</button>
<button onclick="window.location='/report/json'">Download JSON</button>

<h3>SecureNation Index</h3>
<img src="data:image/png;base64,{{ gauge }}">

<h3>Malaysia Heatmap</h3>
{{ heatmap | safe }}

<h3>Trend</h3>
{% if trend %}
<img src="data:image/png;base64,{{ trend }}">
{% else %}<p>No trend data</p>{% endif %}

<h3>Indicator Types</h3>
{% if type_chart %}
<img src="data:image/png;base64,{{ type_chart }}">
{% else %}<p>No type data</p>{% endif %}

<h3>Summary</h3>
<p>{{ summary_text }}</p>

<h3>Latest Indicators</h3>
<table>
<tr><th>ID</th><th>Pulse</th><th>Indicator</th><th>Type</th><th>MITRE</th><th>Risk</th><th>Created</th></tr>
{% for row in table_data %}
<tr>
<td>{{ row['id'] }}</td>
<td style="min-width:200px">{{ row['pulse'] }}</td>
<td>{{ row['indicator'] }}</td>
<td>{{ row['type'] }}</td>
<td>{{ row['mitre'] }}</td>
<td>{{ row['risk_score'] }}</td>
<td>{{ row['created_at'] }}</td>
</tr>
{% endfor %}
</table>
</body>
</html>
"""

# ---------------- DASHBOARD ROUTE ----------------
@app.route("/")
def dashboard():
    trend, type_chart = generate_charts()
    heatmap = generate_malaysia_heatmap()
    gauge = generate_secure_gauge()
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    table_data = c.execute("SELECT * FROM threats ORDER BY created_at DESC LIMIT 50").fetchall()
    summary_row = c.execute("SELECT COUNT(*) as total, AVG(risk_score) as avg_risk FROM threats").fetchone()
    conn.close()
    summary_text = (
        f"RedShark has detected {summary_row['total']} indicators with average risk score "
        f"{summary_row['avg_risk']:.1f}. Continuous monitoring is recommended."
    )
    return render_template_string(TEMPLATE,
                                  trend=trend,
                                  type_chart=type_chart,
                                  heatmap=heatmap,
                                  gauge=gauge,
                                  table_data=table_data,
                                  summary_text=summary_text)

# ---------------- REPORTS ----------------
def get_timestamp(): return datetime.now().strftime("%Y%m%d%H%M%S")

@app.route("/report/pdf")
def pdf_report():
    timestamp = get_timestamp()
    filename = f"RedShark_report_{timestamp}.pdf"
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer,pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    # Cover
    elements.append(Paragraph("RedShark Threat Intelligence Report", styles["Title"]))
    elements.append(Spacer(1,12))
    elements.append(Paragraph("Disclaimer and Executive Summary", styles["Heading2"]))
    elements.append(Paragraph(f"SecureNation Index: {calculate_secure_index()}/100", styles["Normal"]))
    elements.append(Spacer(1,12))

    # Charts
    trend, type_chart = generate_charts()
    if trend:
        img = io.BytesIO(base64.b64decode(trend))
        elements.append(Image(img,width=450,height=200))
    if type_chart:
        img2 = io.BytesIO(base64.b64decode(type_chart))
        elements.append(Spacer(1,12))
        elements.append(Image(img2,width=400,height=250))

    # Table
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    rows = c.execute("SELECT * FROM threats ORDER BY created_at DESC").fetchall()
    conn.close()
    data = [["ID","Pulse","Indicator","Type","MITRE","Risk","Created"]]
    for r in rows:
        data.append([r["id"], r["pulse"], r["indicator"], r["type"], r["mitre"], r["risk_score"], r["created_at"]])
    table = Table(data, repeatRows=1)
    table.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,0),colors.darkblue),
        ('TEXTCOLOR',(0,0),(-1,0),colors.white),
        ('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'),
        ('FONTSIZE',(0,0),(-1,0),10),
        ('ALIGN',(0,0),(-1,-1),'CENTER'),
        ('GRID',(0,0),(-1,-1),0.5,colors.white),
        ('BACKGROUND',(0,1),(-1,-1),colors.HexColor("#1b2a44")),
    ]))
    elements.append(Spacer(1,12))
    elements.append(table)
    doc.build(elements)
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name=filename)

@app.route("/report/csv")
def csv_report():
    timestamp = get_timestamp()
    filename = f"RedShark_report_{timestamp}.csv"
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    rows = c.execute("SELECT * FROM threats ORDER BY created_at DESC").fetchall()
    conn.close()
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(["ID","Pulse","Indicator","Type","MITRE","Risk","Created"])
    for r in rows:
        cw.writerow(r)
    buf = io.BytesIO()
    buf.write(si.getvalue().encode())
    buf.seek(0)
    return send_file(buf, as_attachment=True, download_name=filename)

@app.route("/report/json")
def json_report():
    timestamp = get_timestamp()
    filename = f"RedShark_report_{timestamp}.json"
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    rows = c.execute("SELECT * FROM threats ORDER BY created_at DESC").fetchall()
    conn.close()
    data = [dict(r) for r in rows]
    return jsonify(data)

# ---------------- START ----------------
ensure_database()
fetch_otx_data()
if not os.getenv("RUN_MAIN"):
    threading.Thread(target=scheduler, daemon=True).start()

if __name__=="__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT",5000)))
