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

    # Malaysia timezone grouping
    trend_rows = c.execute("""
        SELECT DATE(created_at, '+8 hours') as date, COUNT(*) as cnt
        FROM threats
        GROUP BY DATE(created_at, '+8 hours')
    """).fetchall()

    type_rows = c.execute("""
        SELECT type, COUNT(*) as cnt
        FROM threats GROUP BY type
    """).fetchall()

    conn.close()

    trend_img = None
    type_img = None

    # ---------------- TREND CHART FIX ----------------
    trend_dict = {row["date"]: row["cnt"] for row in trend_rows}

    today = datetime.utcnow() + timedelta(hours=8)
    dates = []
    counts = []

    for i in range(6, -1, -1):
        d = (today - timedelta(days=i)).strftime("%Y-%m-%d")
        dates.append(d)
        counts.append(trend_dict.get(d, 0))

    plt.figure(figsize=(6,3))
    ax = plt.gca()
    plt.plot(dates, counts, marker="o", color="#d90429")
    plt.title("Threat Trend (Last 7 Days)", color="#d90429")
    ax.set_facecolor("#0d1b2a")
    plt.xticks(rotation=45)
    ax.tick_params(colors='white')
    plt.tight_layout()
    buf = io.BytesIO()
    plt.savefig(buf, format="png", facecolor="#0d1b2a")
    plt.close()
    trend_img = base64.b64encode(buf.getvalue()).decode()

    # ---------------- TYPE CHART ----------------
    if type_rows:
        labels = [x["type"] for x in type_rows]
        values = [x["cnt"] for x in type_rows]

        plt.figure(figsize=(6,4))
        ax = plt.gca()
        plt.bar(labels, values, color="#ff7f50")
        plt.title("Indicator Types", color="#d90429")
        ax.set_facecolor("#0d1b2a")
        ax.tick_params(colors='white')
        plt.xticks(rotation=30)
        plt.tight_layout()

        buf = io.BytesIO()
        plt.savefig(buf, format="png", facecolor="#0d1b2a")
        plt.close()
        type_img = base64.b64encode(buf.getvalue()).decode()

    return trend_img, type_img

# ---------------- SECURE INDEX ----------------
def calculate_secure_index():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT AVG(risk_score) FROM threats")
    avg = c.fetchone()[0] or 0
    conn.close()
    return round(avg, 1)

# ---------------- DASHBOARD TEMPLATE ----------------
TEMPLATE = """<html>
<head>
<title>RedShark Dashboard</title>
<style>
body {background:#0d1b2a;color:white;font-family:sans-serif;}
</style>
</head>
<body>
<h2>RedShark Threat Intelligence Dashboard</h2>
<p>SecureNation Index: {{ gauge }}/100</p>
<h3>Trend (Last 7 Days)</h3>
{% if trend %}<img src="data:image/png;base64,{{ trend }}">{% else %}<p>No trend data</p>{% endif %}
<h3>Indicator Types</h3>
{% if type_chart %}<img src="data:image/png;base64,{{ type_chart }}">{% else %}<p>No type data</p>{% endif %}
<p><a href='/report/pdf'>Download PDF</a> | <a href='/report/csv'>CSV</a> | <a href='/report/json'>JSON</a></p>
</body>
</html>
"""

# ---------------- DASHBOARD ----------------
@app.route("/")
def dashboard():
    trend, type_chart = generate_charts()
    gauge = calculate_secure_index()
    return render_template_string(
        TEMPLATE,
        trend=trend,
        type_chart=type_chart,
        gauge=gauge
    )

# ---------------- PDF REPORT ----------------
@app.route("/report/pdf")
def pdf_report():
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    buffer = io.BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=40,
        rightMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph("RedShark Threat Intelligence Report", styles["Title"]))
    elements.append(Spacer(1, 12))
    elements.append(Paragraph(f"SecureNation Index: {calculate_secure_index()}/100", styles["Normal"]))
    elements.append(PageBreak())

    trend, type_chart = generate_charts()

    if trend:
        img = io.BytesIO(base64.b64decode(trend))
        elements.append(Image(img, width=doc.width, height=220))

    if type_chart:
        elements.append(Spacer(1, 20))
        img2 = io.BytesIO(base64.b64decode(type_chart))
        elements.append(Image(img2, width=doc.width, height=250))

    # Table
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    rows = c.execute("""
        SELECT id, indicator, type, classification, risk_score
        FROM threats
        ORDER BY risk_score DESC LIMIT 20
    """).fetchall()

    conn.close()

    wrap_style = ParagraphStyle(
        name="wrap",
        alignment=TA_LEFT,
        fontSize=8,
        leading=10
    )

    data = [["ID", "Indicator", "Type", "Class", "Risk"]]

    for r in rows:
        data.append([
            r["id"],
            Paragraph(str(r["indicator"]), wrap_style),
            r["type"],
            r["classification"],
            r["risk_score"]
        ])

    col_widths = [
        doc.width * 0.08,
        doc.width * 0.45,
        doc.width * 0.15,
        doc.width * 0.17,
        doc.width * 0.15
    ]

    table = Table(data, colWidths=col_widths, repeatRows=1)

    table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#4B6C8A")),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
        ('VALIGN', (0,0), (-1,-1), 'TOP')
    ]))

    elements.append(Spacer(1, 20))
    elements.append(table)

    doc.build(elements)

    buffer.seek(0)
    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"RedShark_report_{timestamp}.pdf",
        mimetype="application/pdf"
    )

# ---------------- CSV REPORT ----------------
@app.route("/report/csv")
def csv_report():
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
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
        download_name=f"RedShark_report_{timestamp}.csv",
        mimetype="text/csv"
    )

# ---------------- JSON REPORT ----------------
@app.route("/report/json")
def json_report():
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
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
        download_name=f"RedShark_report_{timestamp}.json",
        mimetype="application/json"
    )

# ---------------- START ----------------
ensure_database()
fetch_otx_data()
cleanup_old_records()

if not os.getenv("RUN_MAIN"):
    threading.Thread(target=scheduler, daemon=True).start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)))
