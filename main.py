import os
import io
import csv
import json
import base64
import sqlite3
import threading
import time
import random
from datetime import datetime, timedelta

import requests
from flask import Flask, render_template_string, send_file, jsonify, request, abort

from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle, PageBreak
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

import folium
from folium.plugins import HeatMap


# ================= CONFIG =================

app = Flask(__name__)

DB = os.getenv("DB_PATH", "threats.db")
OTX_KEY = os.getenv("OTX_KEY")
API_KEY = os.getenv("API_KEY", "redshark-secure")
OTX_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"
RETENTION_DAYS = int(os.getenv("RETENTION_DAYS", 30))


# ================= DATABASE =================

def get_conn():
    return sqlite3.connect(DB, timeout=30, check_same_thread=False)


def ensure_database():
    conn = get_conn()
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
        created_at TEXT,
        UNIQUE(signal, type)
    )
    """)
    conn.commit()
    conn.close()


# ================= DATA RETENTION =================

def cleanup_old():
    cutoff = datetime.utcnow() - timedelta(days=RETENTION_DAYS)
    conn = get_conn()
    conn.execute("DELETE FROM threats WHERE created_at < ?", (cutoff.isoformat(),))
    conn.commit()
    conn.close()


# ================= RISK ENGINE =================

def calculate_risk(indicator_type):
    base = {
        "domain": 70,
        "ip": 80,
        "url": 85,
        "file_hash": 90
    }.get(indicator_type, 65)

    return min(100, base + random.randint(0, 10))


def classify(score):
    if score >= 85:
        return "High"
    elif score >= 70:
        return "Medium"
    return "Low"


# ================= INSERT =================

def insert_threat(pulse, signal, typ):
    score = calculate_risk(typ)
    classification = classify(score)

    conn = get_conn()
    conn.execute("""
        INSERT OR IGNORE INTO threats
        (pulse, signal, type, classification, mitre, risk_score, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (pulse, signal, typ, classification, "OTX", score,
          datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()


# ================= DUMMY DATA =================

def insert_dummy_data():
    for i in range(10):
        insert_threat(f"Dummy Pulse {i+1}",
                      f"malicious{i+1}.com",
                      "domain")


# ================= OTX FETCH =================

def fetch_otx_data():
    ensure_database()

    if not OTX_KEY:
        insert_dummy_data()
        return

    headers = {"X-OTX-API-KEY": OTX_KEY}

    try:
        r = requests.get(OTX_URL, headers=headers, timeout=20)
        r.raise_for_status()
        pulses = r.json().get("results", [])
    except Exception:
        insert_dummy_data()
        return

    for pulse in pulses[:10]:
        name = pulse.get("name", "OTX Pulse")
        for ind in pulse.get("indicators", []):
            val = ind.get("indicator")
            typ = ind.get("type", "domain")
            if val:
                insert_threat(name, val, typ)

    cleanup_old()


# ================= SCHEDULER =================

def scheduler():
    while True:
        fetch_otx_data()
        time.sleep(3600)


# ================= SECURENATION INDEX =================

def calculate_secure_index():
    conn = get_conn()
    total = conn.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
    high = conn.execute("SELECT COUNT(*) FROM threats WHERE risk_score >= 85").fetchone()[0]
    conn.close()

    if total == 0:
        return 100

    exposure = high / total
    return max(0, 100 - int(exposure * 100))


def generate_gauge():
    index = calculate_secure_index()
    fig, ax = plt.subplots(figsize=(4, 2))
    ax.barh([0], [index], color="#d90429")
    ax.set_xlim(0, 100)
    ax.set_yticks([])
    ax.set_title(f"SecureNation Index: {index}", color="white")
    buf = io.BytesIO()
    plt.tight_layout()
    plt.savefig(buf, format="png", facecolor="#0d1b2a")
    plt.close()
    return base64.b64encode(buf.getvalue()).decode()


# ================= CHARTS =================

def generate_charts():
    conn = get_conn()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    trend = c.execute("""
    SELECT substr(created_at,1,10) as date, COUNT(*) as cnt
    FROM threats GROUP BY date ORDER BY date
    """).fetchall()

    types = c.execute("""
    SELECT type, COUNT(*) as cnt FROM threats GROUP BY type
    """).fetchall()

    conn.close()

    trend_img = None
    type_img = None

    if trend:
        dates = [x["date"] for x in trend]
        counts = [x["cnt"] for x in trend]
        plt.figure(figsize=(6,3))
        plt.plot(dates, counts, marker="o", color="#d90429")
        plt.xticks(rotation=45)
        buf = io.BytesIO()
        plt.tight_layout()
        plt.savefig(buf, format="png", facecolor="#0d1b2a")
        plt.close()
        trend_img = base64.b64encode(buf.getvalue()).decode()

    if types:
        labels = [x["type"] for x in types]
        values = [x["cnt"] for x in types]
        plt.figure(figsize=(4,3))
        plt.bar(labels, values, color="#ff7f50")
        buf = io.BytesIO()
        plt.tight_layout()
        plt.savefig(buf, format="png", facecolor="#0d1b2a")
        plt.close()
        type_img = base64.b64encode(buf.getvalue()).decode()

    return trend_img, type_img


# ================= MALAYSIA HEATMAP =================

MALAYSIA_STATES = {
    "Johor": [1.4927,103.7414],
    "Selangor": [3.1390,101.6869],
    "Penang": [5.4164,100.3327],
    "Sabah": [5.9804,116.0735],
    "Sarawak": [1.5533,110.3592]
}

def generate_heatmap():
    m = folium.Map(location=[4.2105,101.9758],
                   zoom_start=6,
                   tiles="CartoDB dark_matter")

    heat_data = []
    for coords in MALAYSIA_STATES.values():
        heat_data.append([coords[0], coords[1], random.randint(1,10)])

    HeatMap(heat_data, radius=25).add_to(m)
    return m._repr_html_()


# ================= TEMPLATE =================

TEMPLATE = """
<html>
<head>
<title>RedShark Threat Intelligence Dashboard</title>
<meta http-equiv="refresh" content="300">
<style>
body {background:#0d1b2a;color:white;font-family:sans-serif;}
table {border-collapse: collapse;width:100%;}
th,td {padding:6px;}
tr:nth-child(even){background:#1b2a44;}
th {background:#d90429;}
</style>
</head>
<body>
<h2>RedShark Threat Intelligence Dashboard</h2>
<h3>SecureNation Index</h3>
<img src="data:image/png;base64,{{ gauge }}">
<h3>Malaysia Heatmap</h3>
{{ heatmap | safe }}
<h3>Trend</h3>
{% if trend %}<img src="data:image/png;base64,{{ trend }}">{% endif %}
<h3>Signal Types</h3>
{% if type_chart %}<img src="data:image/png;base64,{{ type_chart }}">{% endif %}
<h3>Latest Signals</h3>
<table>
<tr><th>ID</th><th>Signal</th><th>Type</th><th>Risk</th><th>Created</th></tr>
{% for row in table_data %}
<tr>
<td>{{ row['id'] }}</td>
<td>{{ row['signal'] }}</td>
<td>{{ row['type'] }}</td>
<td>{{ row['risk_score'] }}</td>
<td>{{ row['created_at'] }}</td>
</tr>
{% endfor %}
</table>
</body>
</html>
"""


# ================= ROUTES =================

@app.route("/")
def dashboard():
    trend, type_chart = generate_charts()
    heatmap = generate_heatmap()
    gauge = generate_gauge()

    conn = get_conn()
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM threats ORDER BY created_at DESC LIMIT 50").fetchall()
    conn.close()

    return render_template_string(
        TEMPLATE,
        trend=trend,
        type_chart=type_chart,
        heatmap=heatmap,
        gauge=gauge,
        table_data=rows
    )


@app.route("/api/threats")
def api_threats():
    key = request.headers.get("X-API-KEY")
    if key != API_KEY:
        abort(401)

    conn = get_conn()
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM threats").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


# ================= START =================

ensure_database()
fetch_otx_data()

if os.environ.get("WERKZEUG_RUN_MAIN") == "true":
    threading.Thread(target=scheduler, daemon=True).start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
