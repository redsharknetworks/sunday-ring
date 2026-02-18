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

from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

import folium
from folium.plugins import HeatMap

# ---------------- CONFIG ----------------
app = Flask(__name__)
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
        pulses = otx.getall(limit=10)
    except Exception as e:
        print("OTX fetch error:", e)
        return

    conn = sqlite3.connect(DB)
    c = conn.cursor()

    for pulse in pulses:
        name = pulse.get("name", "OTX")
        for ind in pulse.get("indicators", []):
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
        ax = plt.gca()
        if os.path.exists("boxing_ring.png"):
            bg = plt.imread("boxing_ring.png")
            ax.imshow(bg, extent=[0,len(dates)-1,0,max(counts)+5],
                      aspect='auto', alpha=0.2)

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

# ---------------- TOP 10 THREATS ----------------
def generate_top10_chart():
    ensure_database()
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    try:
        top10 = c.execute("""
            SELECT pulse, COUNT(*) as cnt, AVG(risk_score) as avg_risk
            FROM threats
            GROUP BY pulse
            ORDER BY cnt DESC
            LIMIT 10
        """).fetchall()
    except:
        top10 = []
    conn.close()

    top10_img = None
    if top10:
        pulses = [x[0] for x in top10]
        counts = [x[1] for x in top10]
        avg_risks = [x[2] for x in top10]

        colors_list = []
        for r in avg_risks[::-1]:
            if r >= 80:
                colors_list.append("red")
            elif r >= 60:
                colors_list.append("orange")
            else:
                colors_list.append("green")

        plt.figure(figsize=(6,3))
        plt.barh(pulses[::-1], counts[::-1], color=colors_list)
        plt.title("Top 10 Threat Pulses by Risk")
        plt.xlabel("Occurrences")
        plt.tight_layout()
        buf = io.BytesIO()
        plt.savefig(buf, format="png")
        plt.close()
        top10_img = base64.b64encode(buf.getvalue()).decode()
    return top10_img

# ---------------- HEATMAP ----------------
def generate_heatmap():
    m = folium.Map(location=[4.2105, 101.9758], zoom_start=6)
    heat_data = [
        [3.1390, 101.6869, 5], [1.4927, 103.7414, 4], [5.4164, 100.3327, 3],
        [2.1896, 102.2501, 2], [6.1254, 102.2381, 2], [2.9216, 101.6509, 3],
        [2.9264, 101.6998, 3], [1.5533, 110.3592, 2], [5.9804, 116.0735, 2],
        [6.1203, 100.3660, 2], [5.3289, 103.1403, 2], [4.5975, 101.0901, 2],
        [6.4383, 100.2002, 2], [3.8070, 103.3255, 2], [2.7295, 101.9385, 2],
    ]
    HeatMap(heat_data, radius=25).add_to(m)
    return m._repr_html_()

# ---------------- PDF ----------------
@app.route("/report/pdf")
def pdf_report():
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=landscape(A4),
                            rightMargin=20, leftMargin=20, topMargin=30, bottomMargin=20)
    styles = getSampleStyleSheet()
    elements = []

    # RedShark logo
    if os.path.exists("redshark.png"):
        elements.append(Image("redshark.png", width=120, height=40))
        elements.append(Spacer(1,12))

    elements.append(Paragraph("Threat Intelligence Report", styles["Title"]))
    elements.append(Spacer(1,12))

    trend_img, type_chart_img = generate_charts()
    top10_img = generate_top10_chart()

    if trend_img:
        elements.append(Image(io.BytesIO(base64.b64decode(trend_img)), width=500, height=200))
        elements.append(Spacer(1,12))
    if type_chart_img:
        elements.append(Image(io.BytesIO(base64.b64decode(type_chart_img)), width=400, height=200))
        elements.append(Spacer(1,12))
    if top10_img:
        elements.append(Image(io.BytesIO(base64.b64decode(top10_img)), width=500, height=200))
        elements.append(Spacer(1,12))

    # Fetch data
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
    rows = threats + hashes

    # Table
    data = [["ID","Pulse","Indicator","Type","Classification","MITRE","Risk","Created"]]
    for r in rows:
        pulse = Paragraph(str(r["pulse"]), ParagraphStyle(name='Normal', wordWrap='CJK'))
        indicator = Paragraph(str(r["indicator"]), ParagraphStyle(name='Normal', wordWrap='CJK'))
        data.append([r["id"], pulse, indicator, r["type"], r["classification"],
                     r["mitre"], r["risk_score"], r["created_at"]])

    table = Table(data, repeatRows=1, hAlign='LEFT')
    table.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,0),colors.darkblue),
        ('TEXTCOLOR',(0,0),(-1,0),colors.white),
        ('GRID',(0,0),(-1,-1),0.5,colors.grey),
        ('VALIGN',(0,0),(-1,-1),'TOP'),
        ('ALIGN',(0,0),(-1,-1),'CENTER'),
    ]))
    elements.append(table)

    doc.build(elements)
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name="report.pdf")

# ---------------- CSV ----------------
@app.route("/report/csv")
def csv_report():
    ensure_database()
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    threats = c.execute("SELECT * FROM threats").fetchall()
    hashes = c.execute("""
        SELECT id, pulse, hash as indicator, 'hash' as type,
               classification, mitre, risk_score, created_at
        FROM threat_hashes
    """).fetchall()
    conn.close()

    rows = threats + hashes
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(["ID","Pulse","Indicator","Type","Classification","MITRE","Risk","Created"])
    for r in rows:
        cw.writerow(r)
    output = io.BytesIO()
    output.write(si.getvalue().encode())
    output.seek(0)
    return send_file(output, as_attachment=True, download_name="report.csv")

# ---------------- JSON ----------------
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

# ---------------- DASHBOARD ----------------
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

{% if top10_chart %}
<div class="chart">
<h3>Top 10 Threat Pulses by Risk</h3>
<img src="data:image/png;base64,{{ top10_chart }}" width="600">
</div>
{% endif %}

<br>
<a href="/report/pdf">PDF</a> |
<a href="/report/csv">CSV</a> |
<a href="/report/json">JSON</a>

</body>
</html>
"""

@app.route("/")
def dashboard():
    trend, type_chart = generate_charts()
    top10_chart = generate_top10_chart()
    heatmap = generate_heatmap()
    return render_template_string(TEMPLATE, trend=trend, type_chart=type_chart,
                                  top10_chart=top10_chart, heatmap=heatmap)

# ---------------- INITIALIZE ----------------
ensure_database()
start_scheduler_once()
try:
    fetch_otx_data()
except Exception as e:
    print("Initial fetch error:", e)

# ---------------- RUN ----------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
