import os
import io
import csv
import base64
import sqlite3
import threading
import time
import random
from datetime import datetime

from flask import Flask, render_template_string, send_file, jsonify
from OTXv2 import OTXv2

from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

import folium
from folium.plugins import HeatMap

# ---------------- CONFIG ----------------

app = Flask(__name__)

# Persistent DB if available
DB = "/data/threats.db" if os.path.exists("/data") else "threats.db"

OTX_KEY = os.getenv("OTX_KEY")
if OTX_KEY:
    otx = OTXv2(OTX_KEY)
else:
    otx = None
    print("⚠️ WARNING: OTX_KEY not set. Threats will not update.")

scheduler_started = False

# ---------------- DATABASE ----------------

def ensure_database():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS threats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pulse TEXT,
            indicator TEXT UNIQUE,
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
            hash TEXT UNIQUE,
            classification TEXT,
            mitre TEXT,
            risk_score INTEGER,
            created_at TEXT
        )
    """)
    conn.commit()
    conn.close()

# ---------------- OTX FETCH ----------------

def fetch_otx_data():
    if not otx:
        print("OTX key missing, skipping fetch.")
        return

    try:
        pulses = otx.getall(limit=10)  # Correct OTXv2 method
    except Exception as e:
        print("OTX fetch error:", e)
        return

    conn = sqlite3.connect(DB)
    c = conn.cursor()

    for pulse in pulses:
        name = pulse.get("name", "OTX")
        indicators = pulse.get("indicators", [])
        for ind in indicators:
            val = ind.get("indicator")
            typ = ind.get("type", "domain")
            if not val:
                continue
            created = datetime.utcnow().isoformat()
            score = random.randint(50, 95)
            try:
                if typ in ["IPv4", "domain", "URL"]:
                    c.execute("""
                        INSERT OR IGNORE INTO threats
                        (pulse, indicator, type, classification, mitre, risk_score, created_at)
                        VALUES (?,?,?,?,?,?,?)
                    """, (name, val, typ, "Medium", "OTX", score, created))
                if "Hash" in typ:
                    c.execute("""
                        INSERT OR IGNORE INTO threat_hashes
                        (pulse, hash, classification, mitre, risk_score, created_at)
                        VALUES (?,?,?,?,?,?)
                    """, (name, val, "Medium", "OTX", score, created))
            except Exception as e:
                print("Insert error:", e)

    conn.commit()
    conn.close()
    print("OTX Updated")

# ---------------- SCHEDULER ----------------

def scheduler():
    while True:
        try:
            fetch_otx_data()
        except Exception as e:
            print("Scheduler error:", e)
        time.sleep(3600)

def start_scheduler_once():
    global scheduler_started
    if not scheduler_started and otx:
        scheduler_started = True
        thread = threading.Thread(target=scheduler, daemon=True)
        thread.start()

# ---------------- CHARTS ----------------

def generate_charts():
    ensure_database()
    conn = sqlite3.connect(DB)
    c = conn.cursor()

    try:
        trend = c.execute("""
            SELECT date(created_at), COUNT(*)
            FROM threats
            GROUP BY date(created_at)
            ORDER BY date(created_at)
        """).fetchall()

        types = c.execute("""
            SELECT type, COUNT(*)
            FROM threats
            GROUP BY type
        """).fetchall()
    except:
        trend = []
        types = []

    conn.close()

    trend_img = None
    type_img = None

    if trend:
        dates = [x[0] for x in trend]
        counts = [x[1] for x in trend]

        plt.figure(figsize=(6,3))
        plt.plot(dates, counts, marker="o", color="crimson")
        plt.xticks(rotation=45)
        plt.title("Threat Trend")
        buf = io.BytesIO()
        plt.tight_layout()
        plt.savefig(buf, format="png")
        plt.close()
        trend_img = base64.b64encode(buf.getvalue()).decode()

    if types:
        labels = [x[0] for x in types]
        values = [x[1] for x in types]

        plt.figure(figsize=(4,3))
        plt.bar(labels, values, color="darkblue")
        plt.title("Indicator Types")
        buf = io.BytesIO()
        plt.tight_layout()
        plt.savefig(buf, format="png")
        plt.close()
        type_img = base64.b64encode(buf.getvalue()).decode()

    return trend_img, type_img

# ---------------- HEATMAP ----------------

def generate_heatmap():
    m = folium.Map(location=[4.2105, 101.9758], zoom_start=6)
    heat_data = [
        [3.1390,101.6869,5],  # KL
        [1.4927,103.7414,4],  # Johor
        [5.4164,100.3327,3],  # Penang
        [2.1896,102.2501,2],  # Melaka
        [6.1254,102.2381,2],  # Kelantan
    ]
    HeatMap(heat_data, radius=25).add_to(m)
    return m._repr_html_()

# ---------------- ROUTES ----------------

@app.route("/")
def dashboard():
    trend, type_chart = generate_charts()
    heatmap = generate_heatmap()
    return render_template_string(TEMPLATE,
                                  trend=trend,
                                  type_chart=type_chart,
                                  heatmap=heatmap)

@app.route("/report/json")
def json_report():
    ensure_database()
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    threats = c.execute("SELECT * FROM threats").fetchall()
    hashes = c.execute("""
        SELECT id, pulse, hash as indicator,
               'hash' as type, classification,
               mitre, risk_score, created_at
        FROM threat_hashes
    """).fetchall()
    conn.close()
    return jsonify([dict(x) for x in threats] + [dict(x) for x in hashes])

@app.route("/report/pdf")
def pdf_report():
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []
    elements.append(Paragraph("Threat Intelligence Report", styles["Title"]))
    elements.append(Spacer(1,12))

    trend, type_chart = generate_charts()
    if trend:
        img = io.BytesIO(base64.b64decode(trend))
        elements.append(Image(img, width=420, height=200))
    if type_chart:
        img2 = io.BytesIO(base64.b64decode(type_chart))
        elements.append(Spacer(1,12))
        elements.append(Image(img2, width=320, height=200))

    doc.build(elements)
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name="report.pdf")

# ---------------- TEMPLATE ----------------

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
<title>DarkGrid Dashboard</title>
<style>
body { background:#0f172a; color:white; font-family:Arial; text-align:center; max-width:1200px; margin:auto; }
.title { background: linear-gradient(90deg,#2f2f2f,#8b0000,#2f2f2f); padding:14px; border-radius:10px; margin-top:20px; }
.chart { margin:25px; }
a { color:orange; font-weight:bold; text-decoration:none; }
</style>
</head>
<body>

<h1 class="title">DARKGRID CYBER THREAT INTELLIGENCE</h1>

{% if heatmap %}
<div class="chart">
<h3>Malaysia Threat Heat Map</h3>
{{ heatmap|safe }}
</div>
{% endif %}

{% if trend %}
<div class="chart">
<h3>Threat Trend</h3>
<img src="data:image/png;base64,{{ trend }}" width="600">
</div>
{% endif %}

{% if type_chart %}
<div class="chart">
<h3>Indicator Types</h3>
<img src="data:image/png;base64,{{ type_chart }}" width="450">
</div>
{% endif %}

<br>
<a href="/report/pdf">PDF</a> |
<a href="/report/json">JSON</a>

</body>
</html>
"""

# ---------------- INITIALIZE ----------------

ensure_database()
start_scheduler_once()

try:
    fetch_otx_data()
except Exception as e:
    print("Initial fetch error:", e)

# ---------------- RUN LOCAL ----------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
