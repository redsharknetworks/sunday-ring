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

from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image
from reportlab.lib.pagesizes import letter
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

# Railway-safe writable path
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
        indicator TEXT,
        type TEXT,
        classification TEXT,
        mitre TEXT,
        risk_score INTEGER,
        created_at TEXT
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS threat_hashes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pulse TEXT,
        hash TEXT,
        classification TEXT,
        mitre TEXT,
        risk_score INTEGER,
        created_at TEXT
    )
    """)

    conn.commit()
    conn.close()


# -------------------------------------------------
# DUMMY DATA (fallback)
# -------------------------------------------------

def insert_dummy_data():
    conn = sqlite3.connect(DB)
    c = conn.cursor()

    for i in range(5):
        pulse = f"Dummy Pulse {i+1}"
        indicator = f"malicious{i+1}.com"
        created = datetime.utcnow().isoformat()
        score = random.randint(60, 95)

        c.execute("""
        INSERT INTO threats
        (pulse, indicator, type, classification, mitre, risk_score, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (pulse, indicator, "domain", "Medium", "OTX", score, created))

    conn.commit()
    conn.close()
    print("Inserted dummy data")


# -------------------------------------------------
# OTX FETCH
# -------------------------------------------------

def fetch_otx_data():
    ensure_database()

    if not OTX_KEY:
        print("No OTX key found â using dummy data.")
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

            if typ.lower() in ["domain", "ipv4", "url"]:
                c.execute("""
                INSERT INTO threats
                (pulse, indicator, type, classification, mitre, risk_score, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (name, val, typ, "Medium", "OTX", score, created))

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

def generate_charts():
    ensure_database()

    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    trend = c.execute("""
    SELECT substr(created_at,1,10) as date, COUNT(*) as cnt
    FROM threats
    GROUP BY date ORDER BY date
    """).fetchall()

    types = c.execute("""
    SELECT type, COUNT(*) as cnt
    FROM threats
    GROUP BY type
    """).fetchall()

    conn.close()

    trend_img = None
    type_img = None

    if trend:
        dates = [x["date"] for x in trend]
        counts = [x["cnt"] for x in trend]

        plt.figure(figsize=(6,3))
        plt.plot(dates, counts, marker="o")
        plt.title("Threat Trend")
        plt.xticks(rotation=45)

        buf = io.BytesIO()
        plt.tight_layout()
        plt.savefig(buf, format="png")
        plt.close()

        trend_img = base64.b64encode(buf.getvalue()).decode()

    if types:
        labels = [x["type"] for x in types]
        values = [x["cnt"] for x in types]

        plt.figure(figsize=(4,3))
        plt.bar(labels, values)
        plt.title("Indicator Types")

        buf = io.BytesIO()
        plt.tight_layout()
        plt.savefig(buf, format="png")
        plt.close()

        type_img = base64.b64encode(buf.getvalue()).decode()

    return trend_img, type_img


# -------------------------------------------------
# HEATMAP
# -------------------------------------------------

def generate_heatmap():
    m = folium.Map(location=[4.2, 101.97], zoom_start=6)

    heat_data = [
        [3.1390,101.6869,5],   # KL
        [2.9264,101.6981,3],   # Putrajaya
        [2.9213,101.6500,3],   # Cyberjaya
        [1.5533,110.3592,2],   # Kuching
        [5.9804,116.0735,2],   # Kota Kinabalu
        [4.5929,101.0900,2],   # Ipoh
    ]

    HeatMap(heat_data, radius=25).add_to(m)
    return m._repr_html_()


# -------------------------------------------------
# DASHBOARD TEMPLATE
# -------------------------------------------------

TEMPLATE = """
<html>
<head>
<title>RedShark Threat Dashboard</title>
</head>
<body>
<h2>RedShark Threat Dashboard</h2>

<h3>Heatmap</h3>
{{ heatmap | safe }}

<h3>Trend</h3>
{% if trend %}
<img src="data:image/png;base64,{{ trend }}">
{% else %}
<p>No trend data</p>
{% endif %}

<h3>Indicator Types</h3>
{% if type_chart %}
<img src="data:image/png;base64,{{ type_chart }}">
{% else %}
<p>No type data</p>
{% endif %}

<h3>Latest Threats</h3>
<table border="1" cellpadding="5">
<tr>
<th>ID</th><th>Pulse</th><th>Indicator</th>
<th>Type</th><th>Risk</th><th>Created</th>
</tr>
{% for row in table_data %}
<tr>
<td>{{ row['id'] }}</td>
<td>{{ row['pulse'] }}</td>
<td>{{ row['indicator'] }}</td>
<td>{{ row['type'] }}</td>
<td>{{ row['risk_score'] }}</td>
<td>{{ row['created_at'] }}</td>
</tr>
{% endfor %}
</table>
</body>
</html>
"""


# -------------------------------------------------
# ROUTES
# -------------------------------------------------

@app.route("/")
def dashboard():
    trend, type_chart = generate_charts()
    heatmap = generate_heatmap()

    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    rows = c.execute("""
    SELECT * FROM threats
    ORDER BY created_at DESC
    LIMIT 20
    """).fetchall()
    conn.close()

    return render_template_string(
        TEMPLATE,
        trend=trend,
        type_chart=type_chart,
        heatmap=heatmap,
        table_data=rows
    )


# -------------------------------------------------
# INITIALIZE FOR GUNICORN (CRITICAL FIX)
# -------------------------------------------------

ensure_database()
fetch_otx_data()

# Prevent duplicate scheduler threads
if not os.getenv("RUN_MAIN"):
    threading.Thread(target=scheduler, daemon=True).start()


# -------------------------------------------------
# LOCAL RUN
# -------------------------------------------------

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)))
