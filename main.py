import os
import io
import csv
import base64
import sqlite3
import threading
import time
import random
from datetime import datetime, timedelta

import requests
from flask import Flask, render_template_string, send_file

from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_LEFT
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle, PageBreak
from reportlab.lib.pagesizes import A4
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
def insert_dummy_data():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    for i in range(20):
        created = datetime.utcnow().isoformat()
        # Random classification and score
        classification = random.choice(["Low","Medium","High"])
        score_map = {"Low": random.randint(20,39), "Medium": random.randint(40,69), "High": random.randint(70,100)}
        score = score_map[classification]
        c.execute("""
        INSERT INTO threats (pulse, indicator, type, classification, mitre, risk_score, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            f"Dummy Pulse {i+1}",
            f"malicious{i+1}.com",
            "domain",
            classification,
            "OTX",
            score,
            created
        ))
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
            # Random classification
            classification = random.choice(["Low","Medium","High"])
            score_map = {"Low": random.randint(20,39), "Medium": random.randint(40,69), "High": random.randint(70,100)}
            score = score_map[classification]
            created = datetime.utcnow().isoformat()
            c.execute("""
            INSERT INTO threats (pulse, indicator, type, classification, mitre, risk_score, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (name, val, typ, classification, "OTX", score, created))
    conn.commit()
    conn.close()

# ---------------- SCHEDULER ----------------
def scheduler():
    while True:
        fetch_otx_data()
        cleanup_old_records()
        time.sleep(3600)

# ---------------- CHARTS ----------------
def generate_charts():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    trend_rows = c.execute("""
        SELECT DATE(created_at, '+8 hours') as date, COUNT(*) as cnt
        FROM threats
        GROUP BY DATE(created_at, '+8 hours')
        ORDER BY DATE(created_at, '+8 hours')
    """).fetchall()

    type_rows = c.execute("""
        SELECT type, COUNT(*) as cnt
        FROM threats GROUP BY type
    """).fetchall()

    conn.close()
    trend_img = None
    type_img = None

    if trend_rows:
        trend_dict = {row["date"]: row["cnt"] for row in trend_rows}
        today = datetime.utcnow() + timedelta(hours=8)
        dates, counts = [], []
        for i in range(6,-1,-1):
            d = (today - timedelta(days=i)).strftime("%Y-%m-%d")
            dates.append(d)
            counts.append(trend_dict.get(d,0))
        plt.figure(figsize=(6,3))
        ax = plt.gca()
        plt.plot(dates, counts, marker="o", color="#d90429")
        plt.title("Threat Trend (Last 7 Days)", color="#d90429")
        ax.tick_params(colors='white')
        plt.xticks(rotation=45)
        plt.tight_layout()
        buf = io.BytesIO()
        plt.savefig(buf, format="png", facecolor="#0d1b2a")
        plt.close()
        trend_img = base64.b64encode(buf.getvalue()).decode()

    if type_rows:
        labels = [x["type"] for x in type_rows]
        values = [x["cnt"] for x in type_rows]
        plt.figure(figsize=(6,4))
        plt.bar(labels, values, color="#ff7f50")
        plt.title("Indicator Types", color="#d90429")
        ax = plt.gca()
        ax.tick_params(colors='white')
        plt.xticks(rotation=30)
        plt.tight_layout()
        buf = io.BytesIO()
        plt.savefig(buf, format="png", facecolor="#0d1b2a")
        plt.close()
        type_img = base64.b64encode(buf.getvalue()).decode()

    return trend_img, type_img

# ---------------- MALAYSIA HEATMAP ----------------
MALAYSIA_STATES = {
    "Johor": [1.4927,103.7414], "Kedah": [6.1164,100.3678], "Kelantan": [6.1254,102.2381],
    "Melaka": [2.1896,102.2501], "Negeri Sembilan": [2.7290,101.9383], "Pahang": [3.8167,103.3333],
    "Perak": [4.5929,101.0900], "Perlis": [6.4400,100.2000], "Penang": [5.4164,100.3327],
    "Sabah": [5.9804,116.0735], "Sarawak": [1.5533,110.3592], "Selangor": [3.1390,101.6869],
    "Terengganu": [5.3300,103.1400], "Kuala Lumpur": [3.1390,101.6869], "Putrajaya": [2.9264,101.6981],
    "Labuan": [5.2833,115.2333]
}

def generate_malaysia_heatmap():
    tz = timedelta(hours=8)
    timestamp = (datetime.utcnow()+tz).strftime("%Y-%m-%d %H:%M:%S GMT+8")
    m = folium.Map(location=[4.2105,101.9758], zoom_start=6, tiles="CartoDB dark_matter")
    folium.Marker([5.4164,100.3327], popup=f"Last update: {timestamp}").add_to(m)
    heat_data=[]
    for coords in MALAYSIA_STATES.values():
        count = random.randint(1,10)
        heat_data.append([coords[0],coords[1],count])
    HeatMap(heat_data,radius=25).add_to(m)
    return m._repr_html_(), timestamp

# ---------------- SECURENATION INDEX ----------------
def calculate_secure_index(start_date=None):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    query = "SELECT AVG(risk_score) FROM threats"
    params = ()
    if start_date:
        query += " WHERE created_at>=?"
        params=(start_date,)
    c.execute(query,params)
    avg_risk = c.fetchone()[0] or 0
    conn.close()
    return round(avg_risk,1)

def risk_summary(start_date=None):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    query = "SELECT classification, COUNT(*) FROM threats"
    params=()
    if start_date:
        query+=" WHERE created_at>=?"
        params=(start_date,)
    query+=" GROUP BY classification"
    c.execute(query,params)
    rows=c.fetchall()
    conn.close()
    summary = {"Low":0,"Medium":0,"High":0}
    for cls,count in rows:
        summary[cls]=count
    return summary

def generate_recommendations(summary):
    rec=[]
    if summary["High"]>0:
        rec.append("Immediate investigation required")
        rec.append("Isolate affected systems")
        rec.append("Notify security team")
    elif summary["Medium"]>0:
        rec.append("Monitor systems and logs")
        rec.append("Scan affected systems")
    elif summary["Low"]>0:
        rec.append("Regular review of indicators")
    else:
        rec.append("No significant threats detected")
    return rec

# ---------------- DASHBOARD TEMPLATE ----------------
TEMPLATE = """<html>
<head>
<title>RedShark Threat Intelligence Dashboard</title>
<link rel="stylesheet" type="text/css" href="https://cdn.datatables.net/1.13.6/css/jquery.dataTables.min.css"/>
<link rel="stylesheet" type="text/css" href="https://cdn.datatables.net/responsive/2.6.1/css/responsive.dataTables.min.css"/>
<style>
body {background:#0d1b2a;color:white;font-family:sans-serif;}
table {border-collapse: collapse;width:100%; word-wrap: break-word;}
th, td {padding:8px; text-align:left;}
th {cursor:pointer; background:crimson; color:white;}
tr:nth-child(even){background:#1b2a44;}
tr:nth-child(odd){background:#0d1b2a;}
a.button {background:#ff7f50;color:white;padding:6px 12px;text-decoration:none;border-radius:4px;}
.secure-bar {background:#1b2a44;width:300px;height:25px;border-radius:5px;margin:5px 0;}
.secure-fill {height:25px;border-radius:5px;text-align:center;color:white;font-weight:bold;}
</style>
</head>
<body>
<h2>RedShark Threat Intelligence Dashboard</h2>
<p>Disclaimer: Developed and analysed by darkgrid@redshark.my using publicly available source.</p>

<h3>SecureNation Index</h3>
{% set color = "#ff7f50" %}
{% if gauge >= 90 %} {% set color = "#28a745" %}
{% elif gauge >= 70 %} {% set color = "#ffc107" %}
{% elif gauge >= 40 %} {% set color = "#fd7e14" %}
{% else %} {% set color = "#dc3545" %} {% endif %}
<div class="secure-bar">
  <div class="secure-fill" style="width:{{ gauge }}%;background:{{ color }};">{{ gauge }}/100</div>
</div>

<h3>Malaysia Heatmap (Last Update: {{ heatmap_time }})</h3>
{{ heatmap | safe }}

<h3>Trend</h3>
{% if trend %}<img src="data:image/png;base64,{{ trend }}">{% else %}<p>No trend data</p>{% endif %}

<h3>Indicator Types</h3>
{% if type_chart %}<img src="data:image/png;base64,{{ type_chart }}">{% else %}<p>No type data</p>{% endif %}

<h3>Latest Indicators</h3>
<table id="indicators" class="display nowrap" style="width:100%">
<thead>
<tr><th>ID</th><th style="width:300px;">Pulse</th><th>Indicator</th><th>Type</th><th>MITRE</th><th>Risk</th><th>Created</th></tr>
</thead>
<tbody>
{% for row in table_data %}
<tr>
<td>{{ row['id'] }}</td>
<td>{{ row['pulse'] }}</td>
<td>{{ row['indicator'] }}</td>
<td>{{ row['type'] }}</td>
<td>{{ row['mitre'] }}</td>
<td>{{ row['risk_score'] }}</td>
<td>{{ row['created_at'] }}</td>
</tr>
{% endfor %}
</tbody>
</table>

<h3>Top 20 Indicators</h3>
<table>
<tr><th>Indicator</th><th>Count</th></tr>
{% for row in top20 %}
<tr><td>{{ row['indicator'] }}</td><td>{{ row['count'] }}</td></tr>
{% endfor %}
</table>

<h3>Download Reports</h3>
<a class="button" href="/report/pdf">Download PDF</a>
<a class="button" href="/report/csv">Download CSV</a>
<a class="button" href="/report/json">Download JSON</a>

<script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
<script src="https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js"></script>
<script src="https://cdn.datatables.net/responsive/2.6.1/js/dataTables.responsive.min.js"></script>
<script>
$(document).ready(function() {
    $('#indicators').DataTable({
        "pageLength": 50,
        "scrollX": true,
        responsive: true
    });
});
</script>
</body>
</html>
"""

# ---------------- DASHBOARD ROUTE ----------------
@app.route("/")
def dashboard():
    trend, type_chart = generate_charts()
    heatmap, heatmap_time = generate_malaysia_heatmap()
    gauge = calculate_secure_index()

    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    table_data = c.execute("SELECT * FROM threats ORDER BY created_at DESC LIMIT 50").fetchall()
    top20 = c.execute("SELECT indicator, COUNT(*) as count FROM threats GROUP BY indicator ORDER BY count DESC LIMIT 20").fetchall()
    conn.close()

    return render_template_string(
        TEMPLATE,
        trend=trend,
        type_chart=type_chart,
        heatmap=heatmap,
        heatmap_time=heatmap_time,
        gauge=gauge,
        table_data=table_data,
        top20=top20
    )

# ---------------- REPORT PDF ----------------
@app.route("/report/pdf")
def pdf_report():
    filename_ts = datetime.now().strftime("%Y%m%d%H%M%S")
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4,
                            leftMargin=36, rightMargin=36, topMargin=36, bottomMargin=36)
    styles = getSampleStyleSheet()
    elements = []

    # Header
    elements.append(Paragraph("RedShark Threat Intelligence Report", styles["Title"]))
    elements.append(Spacer(1,12))
    elements.append(Paragraph(f"Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles["Normal"]))
    elements.append(Spacer(1,12))

    # Daily summary
    today_start = (datetime.utcnow() - timedelta(hours=8)).replace(hour=0, minute=0, second=0, microsecond=0)
    daily_summary = risk_summary(today_start.isoformat())
    daily_gauge = calculate_secure_index(today_start.isoformat())
    elements.append(Paragraph(f"Today's SecureNation Index: {daily_gauge} / 100", styles["Heading2"]))
    elements.append(Spacer(1,6))
    elements.append(Paragraph(f"Summary of today's threats: {daily_summary}", styles["Normal"]))
    rec = generate_recommendations(daily_summary)
    elements.append(Paragraph("Recommendations:", styles["Heading3"]))
    for r in rec:
        elements.append(Paragraph(f"• {r}", styles["Normal"]))
    elements.append(Spacer(1,12))

    # Weekly summary
    week_start = (datetime.utcnow() - timedelta(days=7)).isoformat()
    weekly_summary = risk_summary(week_start)
    weekly_gauge = calculate_secure_index(week_start)
    elements.append(Paragraph(f"Weekly SecureNation Index: {weekly_gauge} / 100", styles["Heading2"]))
    elements.append(Spacer(1,6))
    elements.append(Paragraph(f"Summary of past 7 days threats: {weekly_summary}", styles["Normal"]))
    rec_week = generate_recommendations(weekly_summary)
    elements.append(Paragraph("Recommendations:", styles["Heading3"]))
    for r in rec_week:
        elements.append(Paragraph(f"• {r}", styles["Normal"]))
    elements.append(PageBreak())

    # Charts
    trend_img, type_chart_img = generate_charts()
    if trend_img:
        img = io.BytesIO(base64.b64decode(trend_img))
        elements.append(Image(img, width=doc.width, height=220))
    if type_chart_img:
        elements.append(Spacer(1,12))
        img2 = io.BytesIO(base64.b64decode(type_chart_img))
        elements.append(Image(img2, width=doc.width, height=250))

    # Top 20 threats prioritized High->Medium->Low
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    high_rows = c.execute("SELECT id,indicator,type,classification,risk_score FROM threats WHERE classification='High' ORDER BY risk_score DESC").fetchall()
    medium_rows = c.execute("SELECT id,indicator,type,classification,risk_score FROM threats WHERE classification='Medium' ORDER BY risk_score DESC").fetchall()
        low_rows = c.execute(
        "SELECT id,indicator,type,classification,risk_score FROM threats WHERE classification='Low' ORDER BY risk_score DESC"
    ).fetchall()
    conn.close()

    # Combine top 20
    top_rows = high_rows + medium_rows + low_rows
    top_rows = top_rows[:20]

    wrap_style = ParagraphStyle(name="wrap", alignment=TA_LEFT, fontSize=8, leading=10)
    table_data = [["ID", "Indicator", "Type", "Class", "Risk"]]
    for r in top_rows:
        table_data.append([
            r["id"],
            Paragraph(r["indicator"], wrap_style),
            r["type"],
            r["classification"],
            r["risk_score"]
        ])

    col_widths = [doc.width*0.08, doc.width*0.45, doc.width*0.15, doc.width*0.17, doc.width*0.15]
    t = Table(table_data, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,0),colors.HexColor("#4B6C8A")),
        ('TEXTCOLOR',(0,0),(-1,0),colors.white),
        ('GRID',(0,0),(-1,-1),0.5,colors.black),
        ('VALIGN',(0,0),(-1,-1),'TOP'),
        ('ALIGN',(0,0),(-1,-1),'CENTER'),
        ('LEFTPADDING',(0,0),(-1,-1),2),
        ('RIGHTPADDING',(0,0),(-1,-1),2),
        ('TOPPADDING',(0,0),(-1,-1),2),
        ('BOTTOMPADDING',(0,0),(-1,-1),2)
    ]))
    elements.append(Spacer(1,12))
    elements.append(t)

    # Build PDF
    doc.build(elements)
    buffer.seek(0)
    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"RedShark_report_{filename_ts}.pdf",
        mimetype="application/pdf"
    )

# ---------------- REPORT CSV ----------------
@app.route("/report/csv")
def csv_report():
    filename_ts = datetime.now().strftime("%Y%m%d%H%M%S")
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    threats = c.execute("SELECT * FROM threats ORDER BY created_at DESC").fetchall()
    conn.close()
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(["ID","Pulse","Indicator","Type","Class","MITRE","Risk","Created"])
    cw.writerows(threats)
    output = io.BytesIO()
    output.write(si.getvalue().encode())
    output.seek(0)
    return send_file(
        output,
        as_attachment=True,
        download_name=f"RedShark_report_{filename_ts}.csv",
        mimetype="text/csv"
    )

# ---------------- REPORT JSON ----------------
@app.route("/report/json")
def json_report():
    filename_ts = datetime.now().strftime("%Y%m%d%H%M%S")
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    threats = c.execute("SELECT * FROM threats ORDER BY created_at DESC").fetchall()
    conn.close()
    data = [dict(x) for x in threats]
    output = io.BytesIO()
    output.write(str(data).encode())
    output.seek(0)
    return send_file(
        output,
        as_attachment=True,
        download_name=f"RedShark_report_{filename_ts}.json",
        mimetype="application/json"
    )

# ---------------- START ----------------
ensure_database()
fetch_otx_data()
cleanup_old_records()
if not os.getenv("RUN_MAIN"):
    threading.Thread(target=scheduler, daemon=True).start()

if __name__=="__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT",5000)))
