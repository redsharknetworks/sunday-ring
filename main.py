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

app = Flask(__name__)
DB = "threats.db"

# ---------------- OTX ----------------
OTX_KEY = os.getenv("OTX_KEY")
otx = OTXv2(OTX_KEY) if OTX_KEY else None

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

# ---------------- OTX FETCH ----------------
def fetch_otx_data():
    if not otx:
        print("OTX KEY missing")
        return
    try:
        pulses = otx.getsubscribed()
    except Exception as e:
        print("OTX ERROR:", e)
        return

    conn = sqlite3.connect(DB)
    c = conn.cursor()

    for pulse in pulses[:10]:
        name = pulse.get("name", "OTX")
        for ind in pulse.get("indicators", []):
            val = ind.get("indicator")
            typ = ind.get("type", "domain")
            if not val: continue
            created = datetime.utcnow().isoformat()
            score = random.randint(50,95)
            if typ in ["IPv4","domain","URL"]:
                c.execute("""
                INSERT INTO threats
                (pulse,indicator,type,classification,mitre,risk_score,created_at)
                VALUES (?,?,?,?,?,?,?)
                """,(name,val,typ,"Medium","OTX",score,created))
            if "Hash" in typ:
                c.execute("""
                INSERT INTO threat_hashes
                (pulse,hash,classification,mitre,risk_score,created_at)
                VALUES (?,?,?,?,?,?)
                """,(name,val,"Medium","OTX",score,created))
    conn.commit()
    conn.close()
    print("OTX Updated")

# ---------------- SCHEDULER ----------------
def scheduler():
    while True:
        fetch_otx_data()
        time.sleep(3600)  # every hour

# ---------------- CHARTS ----------------
def generate_charts():
    conn = sqlite3.connect(DB)
    c = conn.cursor()

    trend = c.execute("""
        SELECT substr(created_at,1,10), COUNT(*) FROM threats
        GROUP BY 1 ORDER BY 1
    """).fetchall()

    types = c.execute("""
        SELECT type, COUNT(*) FROM threats GROUP BY type
    """).fetchall()

    conn.close()

    trend_img = None
    type_img = None

    # Trend Chart with Boxing Ring
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
        plt.title("Threat Trend")
        plt.xticks(rotation=45)

        buf = io.BytesIO()
        plt.tight_layout()
        plt.savefig(buf, format="png")
        plt.close()
        trend_img = base64.b64encode(buf.getvalue()).decode()

    # Type Chart
    if types:
        labels = [x[0] for x in types]
        values = [x[1] for x in types]

        plt.figure(figsize=(4,3))
        plt.bar(labels, values)
        plt.title("Indicator Types")

        buf = io.BytesIO()
        plt.tight_layout()
        plt.savefig(buf, format="png")
        plt.close()
        type_img = base64.b64encode(buf.getvalue()).decode()

    return trend_img, type_img

# ---------------- MALAYSIA HEAT MAP ----------------
def generate_heatmap():
    m = folium.Map(location=[4.2105,101.9758], zoom_start=6)
    heat_data = [
        [3.1390,101.6869,5],   # Kuala Lumpur
        [1.4927,103.7414,4],   # Johor
        [5.4164,100.3327,3],   # Penang
        [2.1896,102.2501,2],   # Melaka
        [6.1254,102.2381,2],   # Kelantan
    ]
    HeatMap(heat_data,radius=25).add_to(m)
    return m._repr_html_()

# ---------------- DASHBOARD ----------------
@app.route("/")
def dashboard():
    trend,type_chart = generate_charts()
    heatmap = generate_heatmap()
    return render_template_string(TEMPLATE, trend=trend, type_chart=type_chart, heatmap=heatmap)

# ---------------- CSV ----------------
@app.route("/report/csv")
def csv_report():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    threats = c.execute("SELECT * FROM threats").fetchall()
    hashes = c.execute("""
        SELECT id,pulse,hash,'hash',classification,mitre,risk_score,created_at
        FROM threat_hashes
    """).fetchall()
    conn.close()
    rows = threats + hashes
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(["ID","Pulse","Indicator","Type","Class","MITRE","Risk","Created"])
    cw.writerows(rows)
    output = io.BytesIO()
    output.write(si.getvalue().encode())
    output.seek(0)
    return send_file(output, as_attachment=True, download_name="report.csv")

# ---------------- JSON ----------------
@app.route("/report/json")
def json_report():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    threats = c.execute("SELECT * FROM threats").fetchall()
    hashes = c.execute("""
        SELECT id,pulse,hash as indicator,'hash' as type,
        classification,mitre,risk_score,created_at
        FROM threat_hashes
    """).fetchall()
    conn.close()
    data = [dict(x) for x in threats] + [dict(x) for x in hashes]
    return jsonify(data)

# ---------------- PDF ----------------
@app.route("/report/pdf")
def pdf_report():
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer,pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []
    elements.append(Paragraph("Threat Intelligence Report",styles["Title"]))
    elements.append(Spacer(1,12))

    trend,type_chart = generate_charts()

    if trend:
        img = io.BytesIO(base64.b64decode(trend))
        elements.append(Image(img,width=420,height=200))
    if type_chart:
        img2 = io.BytesIO(base64.b64decode(type_chart))
        elements.append(Spacer(1,12))
        elements.append(Image(img2,width=320,height=200))

    doc.build(elements)
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name="report.pdf")

# ---------------- HTML TEMPLATE ----------------
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
<a href="/report/csv">CSV</a> |
<a href="/report/json">JSON</a>

</body>
</html>
"""

# ---------------- START ----------------
if __name__ == "__main__":
    ensure_database()
    fetch_otx_data()
    threading.Thread(target=scheduler,daemon=True).start()
    app.run(host="0.0.0.0", port=5000)
