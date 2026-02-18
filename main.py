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

app = Flask(__name__)
DB = "threats.db"

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

# ---------------- DUMMY DATA ----------------
def insert_dummy_data():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    for i in range(10):
        pulse = f"Dummy Pulse {i+1}"
        indicator = f"malicious{i+1}.com"
        typ = "domain"
        created = datetime.utcnow().isoformat()
        score = random.randint(50,95)
        c.execute("""
        INSERT INTO threats (pulse, indicator, type, classification, mitre, risk_score, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,(pulse,indicator,typ,"Medium","OTX",score,created))
        hash_val = f"{random.randint(100000,999999)}abcd{i}"
        c.execute("""
        INSERT INTO threat_hashes (pulse, hash, classification, mitre, risk_score, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,(pulse,hash_val,"Medium","OTX",score,created))
    conn.commit()
    conn.close()
    print("Inserted dummy data")

# ---------------- OTX FETCH via requests ----------------
OTX_KEY = os.getenv("OTX_KEY")
OTX_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"

def fetch_otx_data():
    if not OTX_KEY:
        print("OTX key missing, inserting dummy data...")
        insert_dummy_data()
        return

    headers = {"X-OTX-API-KEY": OTX_KEY}
    try:
        response = requests.get(OTX_URL, headers=headers, timeout=15)
        response.raise_for_status()
        data = response.json()
        pulses = data.get("results", [])
    except Exception as e:
        print("OTX fetch error:", e)
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
            score = random.randint(50, 95)
            if typ.lower() in ["ipv4", "domain", "url"]:
                c.execute("""
                INSERT INTO threats (pulse, indicator, type, classification, mitre, risk_score, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,(name,val,typ,"Medium","OTX",score,created))
            if "hash" in typ.lower():
                c.execute("""
                INSERT INTO threat_hashes (pulse, hash, classification, mitre, risk_score, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,(name,val,"Medium","OTX",score,created))
    conn.commit()
    conn.close()
    print("OTX data updated via requests")

# ---------------- SCHEDULER ----------------
def scheduler():
    while True:
        fetch_otx_data()
        time.sleep(3600)  # fetch hourly

# ---------------- CHARTS ----------------
def generate_charts():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    trend = c.execute("SELECT substr(created_at,1,10) as date, COUNT(*) as cnt FROM threats GROUP BY date ORDER BY date").fetchall()
    types = c.execute("SELECT type, COUNT(*) as cnt FROM threats GROUP BY type").fetchall()
    conn.close()

    trend_img = None
    type_img = None

    # Trend chart with boxing_ring background
    if trend:
        dates = [x["date"] for x in trend]
        counts = [x["cnt"] for x in trend]

        plt.figure(figsize=(6,3))
        ax = plt.gca()
        plt.style.use('dark_background')
        if os.path.exists("boxing_ring.png"):
            bg = plt.imread("boxing_ring.png")
            ax.imshow(bg, extent=[0,len(dates)-1,0,max(counts)+5], aspect='auto', alpha=0.2)

        plt.plot(dates, counts, marker="o", color="crimson")
        plt.title("Threat Trend", color="white")
        plt.xticks(rotation=45, color="white")
        plt.yticks(color="white")
        plt.tight_layout()
        buf = io.BytesIO()
        plt.savefig(buf, format="png", facecolor='#0D1B2A')  # dark blue background
        plt.close()
        trend_img = base64.b64encode(buf.getvalue()).decode()

    # Type chart
    if types:
        labels = [x["type"] for x in types]
        values = [x["cnt"] for x in types]

        plt.figure(figsize=(4,3))
        plt.style.use('dark_background')
        plt.bar(labels, values, color="dodgerblue")
        plt.title("Indicator Types", color="white")
        plt.xticks(rotation=45, color="white")
        plt.yticks(color="white")
        buf = io.BytesIO()
        plt.tight_layout()
        plt.savefig(buf, format="png", facecolor='#0D1B2A')
        plt.close()
        type_img = base64.b64encode(buf.getvalue()).decode()

    return trend_img, type_img

# ---------------- MALAYSIA HEAT MAP ----------------
def generate_heatmap():
    m = folium.Map(location=[4.2105,101.9758], zoom_start=6, tiles="CartoDB dark_matter")
    heat_data = [
        [3.1390,101.6869,5],   # Kuala Lumpur
        [1.4927,103.7414,4],   # Johor
        [5.4164,100.3327,3],   # Penang
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
<title>RedShark Cyber Threat Intelligence Dashboard</title>
<style>
body { background-color:#0D1B2A; color:white; font-family:Arial, sans-serif;}
table { width:100%; border-collapse: collapse; margin-top:20px;}
th, td { border:1px solid #444; padding:8px; text-align:left;}
th { background-color:#1B3A57;}
tr:nth-child(even) { background-color:#112940;}
img { display:block; margin:auto;}
</style>
</head>
<body>
<h1>RedShark Cyber Threat Intelligence Dashboard</h1>

<!-- SecureNation Index + Summary -->
{{ summary_box|safe }}

<!-- Charts -->
{% if trend %}
<h2>Threat Trend</h2>
<img src="data:image/png;base64,{{ trend }}" width="600" height="300">
{% endif %}

{% if type_chart %}
<h2>Indicator Types</h2>
<img src="data:image/png;base64,{{ type_chart }}" width="400" height="300">
{% endif %}

<h2>Malaysia Threat Heatmap</h2>
{{ heatmap|safe }}

<h2>Latest Threats</h2>
<table>
<tr>
<th>ID</th><th>Pulse</th><th>Indicator</th><th>Type</th><th>Class</th><th>MITRE</th><th>Risk</th><th>Created</th>
</tr>
{% for row in table_data %}
<tr>
<td>{{ row['id'] }}</td><td>{{ row['pulse'] }}</td><td>{{ row['indicator'] }}</td><td>{{ row['type'] }}</td><td>{{ row['classification'] }}</td><td>{{ row['mitre'] }}</td><td>{{ row['risk_score'] }}</td><td>{{ row['created_at'] }}</td>
</tr>
{% endfor %}
</table>
</body>
</html>
"""

# ---------------- DASHBOARD ROUTE ----------------
@app.route("/")
def dashboard():
    trend,type_chart = generate_charts()
    heatmap = generate_heatmap()

    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    table_data = c.execute("SELECT * FROM threats ORDER BY created_at DESC LIMIT 20").fetchall()
    conn.close()

    # Example SecureNation Index
    secure_index = random.randint(45,95)

    # Summary box
    summary_box = render_template_string("""
    <div style="
        border-radius:10px;
        padding:20px;
        margin-bottom:20px;
        background-color:
        {% if secure_index >= 75 %}
            #e6f4ea
        {% elif secure_index >= 50 %}
            #fff4e5
        {% else %}
            #fdecea
        {% endif %};
        border: 2px solid
        {% if secure_index >= 75 %}
            #2e7d32
        {% elif secure_index >= 50 %}
            #f9a825
        {% else %}
            #c62828
        {% endif %};
    ">
    <h2 style="margin-top:0;">SecureNation Index: 
    <span style="font-size:28px; font-weight:bold; color:
        {% if secure_index >= 75 %}
            #2e7d32
        {% elif secure_index >= 50 %}
            #f9a825
        {% else %}
            #c62828
        {% endif %};
    ">{{ secure_index }} / 100</span></h2>
    <p style="font-size:16px; margin-top:10px;">
    <strong>Summary:</strong><br>
    RedShark has detected ongoing cyber threats that may pose risks to systems and data. Continued monitoring and proactive security actions are recommended.
    </p>
    </div>
    """, secure_index=secure_index)

    return render_template_string(TEMPLATE, trend=trend, type_chart=type_chart, heatmap=heatmap, table_data=table_data, summary_box=summary_box)

# ---------------- CSV ----------------
@app.route("/report/csv")
def csv_report():
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename = f"redshark_report_{timestamp}.csv"
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    threats = c.execute("SELECT * FROM threats").fetchall()
    hashes = c.execute("SELECT id,pulse,hash,'hash',classification,mitre,risk_score,created_at FROM threat_hashes").fetchall()
    conn.close()
    rows = threats + hashes
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(["ID","Pulse","Indicator","Type","Class","MITRE","Risk","Created"])
    cw.writerows(rows)
    output = io.BytesIO()
    output.write(si.getvalue().encode())
    output.seek(0)
    return send_file(output, as_attachment=True, download_name=filename)

# ---------------- JSON ----------------
@app.route("/report/json")
def json_report():
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename = f"redshark_report_{timestamp}.json"
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    threats = c.execute("SELECT * FROM threats").fetchall()
    hashes = c.execute("SELECT id,pulse,hash as indicator,'hash' as type,classification,mitre,risk_score,created_at FROM threat_hashes").fetchall()
    conn.close()
    data = [dict(x) for x in threats] + [dict(x) for x in hashes]
    return jsonify(data)

# ---------------- PDF ----------------
@app.route("/report/pdf")
def pdf_report():
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename = f"redshark_report_{timestamp}.pdf"
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer,pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []
    elements.append(Paragraph("RedShark Cyber Threat Intelligence Report",styles["Title"]))
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
    return send_file(buffer, as_attachment=True, download_name=filename)

# ---------------- START ----------------
if __name__ == "__main__":
    ensure_database()
    fetch_otx_data()
    threading.Thread(target=scheduler,daemon=True).start()
    app.run(host="0.0.0.0", port=int(os.getenv("PORT",5000)))
