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
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle, PageBreak, ListFlowable, ListItem
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
        c.execute("""
        INSERT INTO threats (pulse, indicator, type, classification, mitre, risk_score, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            f"Dummy Pulse {i+1}",
            f"malicious{i+1}.com",
            "domain",
            "Medium",
            "OTX",
            random.randint(60, 95),
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

            created = datetime.utcnow().isoformat()
            c.execute("""
            INSERT INTO threats (pulse, indicator, type, classification, mitre, risk_score, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                name,
                val,
                typ,
                "Medium",
                "OTX",
                random.randint(60, 95),
                created
            ))

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

    # ---- Trend Last 7 Days ----
    if trend_rows:
        trend_dict = {row["date"]: row["cnt"] for row in trend_rows}
        today = datetime.utcnow() + timedelta(hours=8)
        dates, counts = [], []
        for i in range(6, -1, -1):
            d = (today - timedelta(days=i)).strftime("%Y-%m-%d")
            dates.append(d)
            counts.append(trend_dict.get(d, 0))

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

    # ---- Type Chart ----
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
    tz = timedelta(hours=8)
    timestamp = (datetime.utcnow() + tz).strftime("%Y-%m-%d %H:%M:%S GMT+8")
    m = folium.Map(location=[4.2105,101.9758], zoom_start=6, tiles="CartoDB dark_matter")
    folium.Marker([5.4164,100.3327], popup=f"Last update: {timestamp}").add_to(m)
    heat_data = []
    for coords in MALAYSIA_STATES.values():
        count = random.randint(1,10)
        heat_data.append([coords[0], coords[1], count])
    HeatMap(heat_data, radius=25).add_to(m)
    return m._repr_html_(), timestamp

# ---------------- SECURENATION INDEX ----------------
def calculate_secure_index():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT AVG(risk_score) as avg_risk FROM threats")
    avg_risk = c.fetchone()[0] or 0
    conn.close()
    return round(avg_risk,1)

# ---------------- SUMMARY & RECOMMENDATIONS ----------------
def generate_summary():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    now = datetime.utcnow()
    today_start = (now - timedelta(days=1)).isoformat()
    week_start = (now - timedelta(days=7)).isoformat()

    # ---- Daily ----
    daily_rows = c.execute(
        "SELECT type, COUNT(*) as cnt, MAX(risk_score) as max_risk FROM threats WHERE created_at >= ?",
        (today_start,)
    ).fetchall()
    daily_total = sum(r["cnt"] for r in daily_rows)
    daily_max_risk = max((r["max_risk"] for r in daily_rows), default=0)
    daily_types = {r["type"]: r["cnt"] for r in daily_rows}

    # ---- Weekly ----
    weekly_rows = c.execute(
        "SELECT type, COUNT(*) as cnt, MAX(risk_score) as max_risk FROM threats WHERE created_at >= ?",
        (week_start,)
    ).fetchall()
    weekly_total = sum(r["cnt"] for r in weekly_rows)
    weekly_max_risk = max((r["max_risk"] for r in weekly_rows), default=0)
    weekly_types = {r["type"]: r["cnt"] for r in weekly_rows}

    conn.close()

    # ---- Observations ----
    def summarize(total, max_risk, types):
        obs = f"Total new threats: {total}. "
        if max_risk >= 90:
            obs += "Critical/high risk indicators detected. "
        elif max_risk >= 70:
            obs += "Moderate risk indicators observed. "
        else:
            obs += "Mostly low to medium risk indicators. "

        top_types = sorted(types.items(), key=lambda x: x[1], reverse=True)
        if top_types:
            obs += "Top types: " + ", ".join(f"{t[0]} ({t[1]})" for t in top_types[:3]) + "."

        # ---- Recommendations ----
        recs = []
        if max_risk >= 90:
            recs.append("Immediate investigation of high-risk indicators.")
            recs.append("Apply strict firewall and IDS rules for top indicators.")
            recs.append("Alert SOC team for potential active threats.")
        elif max_risk >= 70:
            recs.append("Monitor indicators closely and review defenses.")
            recs.append("Update threat intelligence feeds and block top domains/IPs.")
        else:
            recs.append("Routine monitoring recommended.")
            recs.append("Ensure antivirus/endpoint solutions are up-to-date.")

        return obs, recs[:3]

    daily_obs, daily_recs = summarize(daily_total, daily_max_risk, daily_types)
    weekly_obs, weekly_recs = summarize(weekly_total, weekly_max_risk, weekly_types)

    return {
        "daily": {"observation": daily_obs, "recommendations": daily_recs},
        "weekly": {"observation": weekly_obs, "recommendations": weekly_recs}
    }

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

<h3>Summary & Recommendations</h3>
<h4>Daily</h4>
<p><strong>Observation:</strong> {{ summary.daily.observation }}</p>
<ul>
{% for rec in summary.daily.recommendations %}
<li>{{ rec }}</li>
{% endfor %}
</ul>

<h4>Weekly</h4>
<p><strong>Observation:</strong> {{ summary.weekly.observation }}</p>
<ul>
{% for rec in summary.weekly.recommendations %}
<li>{{ rec }}</li>
{% endfor %}
</ul>

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
    summary = generate_summary()

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
        top20=top20,
        summary=summary
    )

# ---------------- REPORTS ----------------
@app.route("/report/pdf")
def pdf_report():
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4,
                            leftMargin=36, rightMargin=36, topMargin=36, bottomMargin=36)
    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph("RedShark Threat Intelligence Report", styles["Title"]))
    elements.append(Spacer(1,12))

    # --- Add summary ---
    summary = generate_summary()
    elements.append(Paragraph("Daily Summary", styles["Heading2"]))
    elements.append(Paragraph(f"Observation: {summary['daily']['observation']}", styles["Normal"]))
    elements.append(ListFlowable(
        [ListItem(Paragraph(rec, styles["Normal"])) for rec in summary['daily']['recommendations']],
        bulletType='bullet'
    ))
    elements.append(Spacer(1,12))
    elements.append(Paragraph("Weekly Summary", styles["Heading2"]))
    elements.append(Paragraph(f"Observation: {summary['weekly']['observation']}", styles["Normal"]))
    elements.append(ListFlowable(
        [ListItem(Paragraph(rec, styles["Normal"])) for rec in summary['weekly']['recommendations']],
        bulletType='bullet'
    ))
       elements.append(Spacer(1,12))

    # ---- Add charts ----
    trend, type_chart = generate_charts()
    if trend:
        img = io.BytesIO(base64.b64decode(trend))
        elements.append(Paragraph("Threat Trend (Last 7 Days)", styles["Heading2"]))
        elements.append(Image(img,width=doc.width,height=220))
    if type_chart:
        elements.append(Spacer(1,12))
        img2 = io.BytesIO(base64.b64decode(type_chart))
        elements.append(Paragraph("Indicator Types", styles["Heading2"]))
        elements.append(Image(img2,width=doc.width,height=250))

    # ---- Top 20 threats table ----
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    rows = c.execute("SELECT id, indicator, type, classification, risk_score FROM threats ORDER BY risk_score DESC LIMIT 20").fetchall()
    conn.close()

    wrap_style = ParagraphStyle(name="wrap", alignment=TA_LEFT, fontSize=8, leading=10)
    table_data = [["ID","Indicator","Type","Class","Risk"]]
    for r in rows:
        table_data.append([r["id"], Paragraph(r["indicator"], wrap_style), r["type"], r["classification"], r["risk_score"]])

    col_widths = [doc.width*0.08, doc.width*0.45, doc.width*0.15, doc.width*0.17, doc.width*0.15]
    t = Table(table_data, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,0),colors.HexColor("#4B6C8A")),
        ('TEXTCOLOR',(0,0),(-1,0),colors.white),
        ('GRID',(0,0),(-1,-1),0.5,colors.black),
        ('VALIGN',(0,0),(-1,-1),'TOP')
    ]))
    elements.append(Spacer(1,12))
    elements.append(t)

    doc.build(elements)
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name=f"RedShark_report_{timestamp}.pdf", mimetype="application/pdf")


# ---------------- CSV & JSON REPORTS ----------------
@app.route("/report/csv")
def csv_report():
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    threats = c.execute("SELECT * FROM threats").fetchall()
    conn.close()
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(["ID","Pulse","Indicator","Type","Class","MITRE","Risk","Created"])
    cw.writerows(threats)
    output = io.BytesIO()
    output.write(si.getvalue().encode())
    output.seek(0)
    return send_file(output, as_attachment=True, download_name=f"RedShark_report_{timestamp}.csv", mimetype="text/csv")

@app.route("/report/json")
def json_report():
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    threats = c.execute("SELECT * FROM threats").fetchall()
    conn.close()
    data = [dict(x) for x in threats]
    output = io.BytesIO()
    output.write(str(data).encode())
    output.seek(0)
    return send_file(output, as_attachment=True, download_name=f"RedShark_report_{timestamp}.json", mimetype="application/json")


# ---------------- START ----------------
ensure_database()
fetch_otx_data()
cleanup_old_records()
if not os.getenv("RUN_MAIN"):
    threading.Thread(target=scheduler, daemon=True).start()

if __name__=="__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT",5000)))
