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

from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, PageBreak
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

import folium
from folium.plugins import HeatMap

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
        entity TEXT,
        category TEXT,
        classification TEXT,
        mitre TEXT,
        risk_score INTEGER,
        created_at TEXT
    )
    """)
    conn.commit()
    conn.close()

# ---------------- DUMMY DATA ----------------
def insert_dummy_data():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    for i in range(10):
        pulse = f"Dummy Pulse {i+1}"
        entity = f"malicious{i+1}.com"
        created = datetime.utcnow().isoformat()
        score = random.randint(60, 95)
        c.execute("""
        INSERT INTO threats (pulse, entity, category, classification, mitre, risk_score, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,(pulse, entity, "Domain", "Medium", "OTX", score, created))
    conn.commit()
    conn.close()
    print("Inserted dummy data")

# ---------------- OTX FETCH ----------------
def fetch_otx_data():
    ensure_database()
    if not OTX_KEY:
        print("No OTX key, inserting dummy data...")
        insert_dummy_data()
        return

    headers = {"X-OTX-API-KEY": OTX_KEY}
    try:
        r = requests.get(OTX_URL, headers=headers, timeout=15)
        r.raise_for_status()
        pulses = r.json().get("results", [])
    except Exception as e:
        print("OTX fetch error:", e)
        insert_dummy_data()
        return

    conn = sqlite3.connect(DB)
    c = conn.cursor()
    for pulse in pulses[:10]:
        name = pulse.get("name","OTX Pulse")
        indicators = pulse.get("indicators",[])
        for ind in indicators:
            val = ind.get("indicator")
            typ = ind.get("type","Domain")
            if not val: continue
            created = datetime.utcnow().isoformat()
            score = random.randint(60,95)
            c.execute("""
            INSERT INTO threats (pulse, entity, category, classification, mitre, risk_score, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,(name,val,typ,"Medium","OTX",score,created))
    conn.commit()
    conn.close()
    print("OTX data updated")

# ---------------- SCHEDULER ----------------
def scheduler():
    while True:
        fetch_otx_data()
        time.sleep(3600)

# ---------------- CHARTS ----------------
def generate_trend_chart():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    trend = c.execute("""
        SELECT substr(created_at,1,10) as date, COUNT(*) as cnt
        FROM threats GROUP BY date ORDER BY date
    """).fetchall()
    conn.close()
    if not trend: return None

    dates = [x["date"] for x in trend]
    counts = [x["cnt"] for x in trend]

    plt.figure(figsize=(6,3))
    if os.path.exists("boxing_ring.png"):
        bg = plt.imread("boxing_ring.png")
        plt.imshow(bg, extent=[0,len(dates)-1,0,max(counts)+5], aspect='auto', alpha=0.2)
    plt.plot(dates, counts, marker="o", color="orange")
    plt.title("Threat Trend")
    plt.xticks(rotation=45)
    buf = io.BytesIO()
    plt.tight_layout()
    plt.savefig(buf, format="png", facecolor="#001f4d") # dark blue background
    plt.close()
    return base64.b64encode(buf.getvalue()).decode()

def generate_category_chart():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    categories = c.execute("""
        SELECT category, COUNT(*) as cnt FROM threats GROUP BY category
    """).fetchall()
    conn.close()
    if not categories: return None
    labels = [x["category"] for x in categories]
    values = [x["cnt"] for x in categories]
    plt.figure(figsize=(4,3))
    plt.bar(labels, values, color="orange")
    plt.title("Category Types")
    buf = io.BytesIO()
    plt.tight_layout()
    plt.savefig(buf, format="png", facecolor="#001f4d")
    plt.close()
    return base64.b64encode(buf.getvalue()).decode()

# ---------------- MALAYSIA HEATMAP ----------------
def generate_malaysia_heatmap():
    m = folium.Map(location=[4.2105,101.9758], zoom_start=6, tiles="cartodbpositron")
    # State-level sample coordinates (Lat, Lon, weight)
    heat_data = [
        [5.4164,100.3327,3],   # Penang
        [3.1390,101.6869,5],   # KL
        [1.4927,103.7414,4],   # Johor
        [2.1896,102.2501,2],   # Melaka
        [6.1254,102.2381,2],   # Kelantan
        [2.9213,101.6500,2],   # Cyberjaya
        [2.9264,101.6981,2],   # Putrajaya
        [1.5533,110.3592,2],   # Kuching
        [5.9804,116.0735,2],   # Kota Kinabalu
        [6.1164,100.3678,2],   # Alor Setar
        [5.3300,103.1400,2],   # Kuala Terengganu
        [4.5929,101.0900,2],   # Ipoh
        [6.4400,100.2000,2],   # Kangar
        [3.8167,103.3333,2],   # Kuantan
        [2.7290,101.9383,2],   # Seremban
    ]
    HeatMap(heat_data,radius=25).add_to(m)
    return m._repr_html_()

# ---------------- DASHBOARD TEMPLATE ----------------
TEMPLATE = """
<html>
<head>
<title>RedShark Threat Intelligence Dashboard</title>
</head>
<body style="background-color:#001f4d; color:white;">
<h2>RedShark Threat Intelligence Dashboard</h2>
<p>{{ summary }}</p>
<h3>SecureNation Index: {{ secure_index }}</h3>

<h3>Malaysia Threat Heatmap</h3>
{{ heatmap | safe }}

<h3>Trend</h3>
{% if trend %}
<img src="data:image/png;base64,{{ trend }}">
{% else %}<p>No trend data</p>{% endif %}

<h3>Category Chart</h3>
{% if category_chart %}
<img src="data:image/png;base64,{{ category_chart }}">
{% else %}<p>No category data</p>{% endif %}

<h3>Latest Threats (50 per page)</h3>
<table border="1" cellpadding="5">
<tr>
<th>ID</th><th>Pulse</th><th>Entity</th><th>Category</th><th>Risk</th><th>Created</th>
</tr>
{% for row in table_data %}
<tr>
<td>{{ row['id'] }}</td>
<td>{{ row['pulse'] }}</td>
<td>{{ row['entity'] }}</td>
<td>{{ row['category'] }}</td>
<td>{{ row['risk_score'] }}</td>
<td>{{ row['created_at'] }}</td>
</tr>
{% endfor %}
</table>

<h3>Top 10 by Entity</h3>
<table border="1" cellpadding="5">
<tr><th>Entity</th><th>Count</th></tr>
{% for row in top10 %}
<tr><td>{{ row['entity'] }}</td><td>{{ row['cnt'] }}</td></tr>
{% endfor %}
</table>

<p style="font-size:small;">Developed and analyzed by DarkGrid@redshark.my from publicly available sources.</p>
</body>
</html>
"""

# ---------------- DASHBOARD ROUTE ----------------
@app.route("/")
def dashboard():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    # Latest 50 threats
    rows = c.execute("SELECT * FROM threats ORDER BY created_at DESC LIMIT 50").fetchall()

    # Top 10
    top10 = c.execute("SELECT entity, COUNT(*) as cnt FROM threats GROUP BY entity ORDER BY cnt DESC LIMIT 10").fetchall()

    # Summary
    total_threats = c.execute("SELECT COUNT(*) as cnt FROM threats").fetchone()["cnt"]
    unique_pulses = c.execute("SELECT COUNT(DISTINCT pulse) as cnt FROM threats").fetchone()["cnt"]
    categories = c.execute("SELECT category, COUNT(*) as cnt FROM threats GROUP BY category").fetchall()
    avg_risk = c.execute("SELECT AVG(risk_score) as avg_score FROM threats").fetchone()["avg_score"]
    conn.close()

    category_summary = ", ".join([f"{x['cnt']} {x['category']}" for x in categories])
    summary = (f"RedShark has detected {total_threats} threats from {unique_pulses} pulses "
               f"covering categories: {category_summary}. SecureNation Index: {int(avg_risk)}. "
               f"Continuous monitoring recommended.")
    
    trend = generate_trend_chart()
    category_chart = generate_category_chart()
    heatmap = generate_malaysia_heatmap()
    secure_index = int(avg_risk)

    return render_template_string(
        TEMPLATE,
        table_data=rows,
        top10=top10,
        trend=trend,
        category_chart=category_chart,
        heatmap=heatmap,
        secure_index=secure_index,
        summary=summary
    )

# ---------------- CSV REPORT ----------------
@app.route("/report/csv")
def csv_report():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    rows = c.execute("SELECT * FROM threats").fetchall()
    conn.close()
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID","Pulse","Entity","Category","Risk","Created"])
    writer.writerows(rows)
    mem = io.BytesIO()
    mem.write(output.getvalue().encode())
    mem.seek(0)
    return send_file(mem, as_attachment=True, download_name=f"RedShark_DarkGrid_report_{timestamp}.csv")

# ---------------- JSON REPORT ----------------
@app.route("/report/json")
def json_report():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    rows = c = conn.cursor()
    data = c.execute("SELECT * FROM threats").fetchall()
    conn.close()
    json_data = [dict(x) for x in data]
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    return jsonify({"report_name":f"RedShark_DarkGrid_report_{timestamp}","data":json_data})

# ---------------- PDF REPORT ----------------
@app.route("/report/pdf")
def pdf_report():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    rows = c.execute("SELECT * FROM threats ORDER BY created_at DESC LIMIT 50").fetchall()
    conn.close()
    
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    # Executive Cover
    elements.append(Paragraph("RedShark DarkGrid Cyber Threat Intelligence Report", styles['Title']))
    elements.append(Spacer(1,12))
    elements.append(Paragraph(f"Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
    elements.append(Spacer(1,12))
    elements.append(Paragraph("Summary:", styles['Heading2']))
    
    total_threats = len(rows)
    unique_pulses = len(set([r['pulse'] for r in rows]))
    avg_risk = int(sum([r['risk_score'] for r in rows])/total_threats) if total_threats else 0
    summary = f"RedShark has detected {total_threats} threats from {unique_pulses} pulses. SecureNation Index: {avg_risk}."
    elements.append(Paragraph(summary, styles['Normal']))
    elements.append(Spacer(1,12))
    
    # Trend chart
    trend = generate_trend_chart()
    if trend:
        img = io.BytesIO(base64.b64decode(trend))
        elements.append(Image(img, width=420, height=200))
    
    # Category chart
    category_chart = generate_category_chart()
    if category_chart:
        img2 = io.BytesIO(base64.b64decode(category_chart))
        elements.append(Spacer(1,12))
        elements.append(Image(img2, width=320, height=200))

    doc.build(elements)
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name=f"RedShark_DarkGrid_report_{timestamp}.pdf")

# ---------------- START ----------------
ensure_database()
fetch_otx_data()
if not os.getenv("RUN_MAIN"):
    threading.Thread(target=scheduler, daemon=True).start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT",5000)))
