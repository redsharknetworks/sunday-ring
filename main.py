import os
import io
import csv
import base64
import sqlite3
import threading
import time
import random
import json
from datetime import datetime, timedelta

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
RETENTION_DAYS = 60


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
    c.execute("CREATE INDEX IF NOT EXISTS idx_created_at ON threats(created_at)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_type ON threats(type)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_indicator ON threats(indicator)")
    conn.commit()
    conn.close()


def apply_retention_policy():
    cutoff = (datetime.utcnow() - timedelta(days=RETENTION_DAYS)).isoformat()
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("DELETE FROM threats WHERE created_at < ?", (cutoff,))
    conn.commit()
    conn.close()


# ---------------- DATA ----------------
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
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (pulse, indicator, "domain", "Medium", "OTX", score, created))
    conn.commit()
    conn.close()


def fetch_otx_data():
    ensure_database()
    apply_retention_policy()

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
        for ind in pulse.get("indicators", []):
            val = ind.get("indicator")
            typ = ind.get("type", "domain")
            if not val:
                continue
            score = random.randint(60, 95)
            created = datetime.utcnow().isoformat()
            c.execute("""
            INSERT INTO threats
            (pulse, indicator, type, classification, mitre, risk_score, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (name, val, typ, "Medium", "OTX", score, created))

    conn.commit()
    conn.close()


# ---------------- SCHEDULER ----------------
def scheduler():
    while True:
        fetch_otx_data()
        time.sleep(3600)


# ---------------- DASHBOARD ----------------
TEMPLATE = """
<html>
<head>
<title>RedShark Threat Intelligence Dashboard</title>
<style>
body {background:#0d1b2a;color:white;font-family:sans-serif;}
table {border-collapse: collapse;width:100%;}
th, td {padding:8px;text-align:left;}
th {background:crimson;color:white;}
tr:nth-child(even){background:#1b2a44;}
th:nth-child(2), td:nth-child(2) {min-width:500px;}
</style>
</head>
<body>

<h2>RedShark Threat Intelligence Dashboard</h2>

<h3>Latest Indicators</h3>
<table>
<tr>
<th>ID</th>
<th>Pulse</th>
<th>Indicator</th>
<th>Type</th>
<th>MITRE</th>
<th>Risk</th>
<th>Created</th>
</tr>

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
</table>

<h3>Top 20 Indicators</h3>
<table>
<tr><th>Indicator</th><th>Count</th></tr>
{% for row in top20 %}
<tr><td>{{ row['indicator'] }}</td><td>{{ row['count'] }}</td></tr>
{% endfor %}
</table>

<br>
<a href="/report/pdf">Download PDF</a> |
<a href="/report/csv">Download CSV</a> |
<a href="/report/json">Download JSON</a>

</body>
</html>
"""


@app.route("/")
def dashboard():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    table_data = c.execute("SELECT * FROM threats ORDER BY created_at DESC LIMIT 50").fetchall()
    top20 = c.execute("""
        SELECT indicator, COUNT(*) as count
        FROM threats
        GROUP BY indicator
        ORDER BY count DESC
        LIMIT 20
    """).fetchall()

    conn.close()

    return render_template_string(TEMPLATE,
                                  table_data=table_data,
                                  top20=top20)


# ---------------- PDF REPORT ----------------
@app.route("/report/pdf")
def pdf_report():
    timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    buffer = io.BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=60,
        rightMargin=60,
        topMargin=70,
        bottomMargin=70
    )

    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph("RedShark Threat Intelligence Report", styles["Title"]))
    elements.append(Spacer(1, 20))

    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    # Top 20 by Type with Avg Risk
    rows = c.execute("""
        SELECT type, indicator,
               COUNT(*) as count,
               AVG(risk_score) as avg_risk
        FROM threats
        GROUP BY type, indicator
        ORDER BY count DESC
        LIMIT 20
    """).fetchall()

    conn.close()

    table_data = [["Type","Indicator","Count","Avg Risk"]]

    for r in rows:
        table_data.append([
            r["type"],
            r["indicator"],
            r["count"],
            round(r["avg_risk"],1)
        ])

    t = Table(table_data, repeatRows=1)
    t.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,0),colors.HexColor("#4B6C8A")),
        ('TEXTCOLOR',(0,0),(-1,0),colors.white),
        ('GRID',(0,0),(-1,-1),0.5,colors.black)
    ]))

    elements.append(t)

    doc.build(elements)
    buffer.seek(0)

    return send_file(buffer,
                     as_attachment=True,
                     download_name=f"RedShark_report_{timestamp}.pdf",
                     mimetype='application/pdf')


# ---------------- CSV ----------------
@app.route("/report/csv")
def csv_report():
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

    return send_file(output,
                     as_attachment=True,
                     download_name="RedShark_report.csv",
                     mimetype="text/csv")


# ---------------- JSON ----------------
@app.route("/report/json")
def json_report():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    threats = c.execute("SELECT * FROM threats").fetchall()
    conn.close()

    data = [dict(x) for x in threats]

    output = io.BytesIO()
    output.write(json.dumps(data, indent=2).encode())
    output.seek(0)

    return send_file(output,
                     as_attachment=True,
                     download_name="RedShark_report.json",
                     mimetype="application/json")


# ---------------- START ----------------
ensure_database()
fetch_otx_data()

if not os.getenv("RUN_MAIN"):
    threading.Thread(target=scheduler, daemon=True).start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)))
