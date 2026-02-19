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

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

import folium
from folium.plugins import HeatMap

from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors

# ---------------- CONFIG ----------------
app = Flask(__name__)
DB = os.getenv("DB_PATH", "/tmp/threats.db")
OTX_KEY = os.getenv("OTX_KEY")
OTX_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"
BOXING_RING = "boxing_ring.png"

# ---------------- MITRE MATRIX ----------------
MITRE_MATRIX = {
    "Initial Access": ["Phishing", "Drive-by Compromise", "Supply Chain Compromise"],
    "Execution": ["Command-Line Interface", "PowerShell", "Scripting"],
    "Persistence": ["Registry Run Keys", "Scheduled Task", "Boot or Logon Scripts"],
    "Privilege Escalation": ["Exploitation for Privilege Escalation", "Access Token Manipulation"],
    "Defense Evasion": ["Obfuscated Files", "Disabling Security Tools", "Code Signing"],
    "Credential Access": ["Credential Dumping", "Brute Force", "OS Credential Manager"],
    "Discovery": ["Network Scan", "File and Directory Discovery", "System Information Discovery"],
    "Lateral Movement": ["Pass the Hash", "Remote Services", "Windows Admin Shares"],
    "Collection": ["Screen Capture", "Data Staged", "Clipboard Data"],
    "Exfiltration": ["Exfiltration Over C2 Channel", "Automated Exfiltration", "Exfiltration Over Web Service"],
    "Impact": ["Data Destruction", "Data Encrypted for Impact", "Service Stop"]
}

# ---------------- DATABASE ----------------
def ensure_database():
    conn = sqlite3.connect(DB)
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
        created_at TEXT
    )""")
    conn.commit()
    conn.close()

# ---------------- DUMMY DATA ----------------
def insert_dummy_data():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    for i in range(10):
        pulse = f"Dummy Pulse {i+1}"
        signal = f"malicious{i+1}.com"
        score = random.randint(60, 95)
        mitre = random.choice([t for sub in MITRE_MATRIX.values() for t in sub])
        created = datetime.utcnow().isoformat()
        c.execute("""INSERT INTO threats
            (pulse, signal, type, classification, mitre, risk_score, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (pulse, signal, "domain", "Medium", mitre, score, created))
    conn.commit()
    conn.close()

# ---------------- OTX FETCH ----------------
def fetch_otx_data():
    ensure_database()
    if not OTX_KEY:
        print("No OTX key found — inserting dummy data")
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
            score = random.randint(60, 95)
            mitre = random.choice([t for sub in MITRE_MATRIX.values() for t in sub])
            created = datetime.utcnow().isoformat()
            c.execute("""INSERT INTO threats
                (pulse, signal, type, classification, mitre, risk_score, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (name, val, typ, "Medium", mitre, score, created))
    conn.commit()
    conn.close()
    print("OTX data updated")

# ---------------- SCHEDULER ----------------
def scheduler():
    while True:
        fetch_otx_data()
        time.sleep(3600)

# ---------------- CHARTS ----------------
def generate_charts():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    trend = c.execute("""
        SELECT substr(created_at,1,10) as date, COUNT(*) as cnt
        FROM threats GROUP BY date ORDER BY date
    """).fetchall()
    types = c.execute("""
        SELECT type, COUNT(*) as cnt
        FROM threats GROUP BY type
    """).fetchall()
    conn.close()

    trend_img = None
    type_img = None

    # Trend chart
    if trend:
        dates = [x["date"] for x in trend]
        counts = [x["cnt"] for x in trend]
        plt.figure(figsize=(6,3))
        ax = plt.gca()
        if os.path.exists(BOXING_RING):
            bg = plt.imread(BOXING_RING)
            ax.imshow(bg, extent=[0,len(dates)-1,0,max(counts)+5], aspect='auto', alpha=0.2)
        plt.plot(dates, counts, marker="o", color="#d90429")
        plt.title("Threat Trend", color="white")
        plt.xticks(rotation=45, color="white")
        plt.yticks(color="white")
        buf = io.BytesIO()
        plt.tight_layout()
        plt.savefig(buf, format="png", facecolor="#0d1b2a")
        plt.close()
        buf.seek(0)
        trend_img = base64.b64encode(buf.getvalue()).decode()

    # Type chart
    if types:
        labels = [x["type"] for x in types]
        values = [x["cnt"] for x in types]
        plt.figure(figsize=(4,3))
        plt.bar(labels, values, color="#ff7f50")
        plt.title("Signal Types", color="white")
        plt.xticks(color="white")
        plt.yticks(color="white")
        buf = io.BytesIO()
        plt.tight_layout()
        plt.savefig(buf, format="png", facecolor="#0d1b2a")
        plt.close()
        buf.seek(0)
        type_img = base64.b64encode(buf.getvalue()).decode()

    return trend_img, type_img

# ---------------- MALAYSIA HEATMAP ----------------
MALAYSIA_STATES = {
    "Johor": [1.4927,103.7414], "Kedah": [6.1164,100.3678], "Kelantan": [6.1254,102.2381],
    "Melaka": [2.1896,102.2501], "Negeri Sembilan": [2.7290,101.9383], "Pahang": [3.8167,103.3333],
    "Perak": [4.5929,101.0900], "Perlis": [6.4400,100.2000], "Penang": [5.4164,100.3327],
    "Sabah": [5.9804,116.0735], "Sarawak": [1.5533,110.3592], "Selangor": [3.1390,101.6869],
    "Terengganu": [5.3300,103.1400], "Kuala Lumpur": [3.1390,101.6869], "Putrajaya": [2.9264,101.6981],
    "Labuan": [5.2833,115.2333]
}

def generate_malaysia_heatmap():
    m = folium.Map(location=[4.2105,101.9758], zoom_start=6, tiles="CartoDB dark_matter")
    heat_data = [[coords[0], coords[1], random.randint(1,10)] for coords in MALAYSIA_STATES.values()]
    HeatMap(heat_data, radius=25).add_to(m)
    return m._repr_html_()

# ---------------- SECURENATION INDEX ----------------
def calculate_secure_index():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT AVG(risk_score) as avg_risk FROM threats")
    avg_risk = c.fetchone()[0] or 0
    conn.close()
    return round(avg_risk,1)

def generate_secure_gauge():
    index = calculate_secure_index()
    fig, ax = plt.subplots(figsize=(4,2))
    ax.barh([0],[index], color="#d90429")
    ax.set_xlim(0,100)
    ax.set_yticks([])
    ax.set_title(f"SecureNation Index: {index}", color="white")
    buf = io.BytesIO()
    plt.tight_layout()
    plt.savefig(buf, format="png", facecolor="#0d1b2a")
    plt.close()
    buf.seek(0)
    return base64.b64encode(buf.getvalue()).decode()

# ---------------- MITRE MATRIX GENERATOR ----------------
def generate_mitre_matrix():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    counts = {}
    rows = c.execute("SELECT mitre, risk_score FROM threats").fetchall()
    for r in rows:
        counts[r["mitre"]] = max(counts.get(r["mitre"], 0), r["risk_score"])
    conn.close()
    html = "<table border='1' style='border-collapse:collapse;width:100%;text-align:center;'>"
    html += "<tr><th>Tactic</th>"
    max_techs = max(len(t) for t in MITRE_MATRIX.values())
    for i in range(max_techs): html += f"<th>Technique {i+1}</th>"
    html += "</tr>"
    for tactic, techniques in MITRE_MATRIX.items():
        html += f"<tr><td style='background:#d90429;color:white;'>{tactic}</td>"
        for tech in techniques:
            score = counts.get(tech,0)
            color = f"#{255-int(score*2.55):02x}{int(score*2.55):02x}00" if score else "#555555"
            html += f"<td style='background:{color};color:white;' title='Risk: {score}'>{tech}</td>"
        for _ in range(max_techs - len(techniques)):
            html += "<td style='background:#555555;color:white;'></td>"
        html += "</tr>"
    html += "</table>"
    return html

# ---------------- DASHBOARD TEMPLATE ----------------
TEMPLATE = """
<html>
<head>
<title>RedShark Threat Dashboard</title>
<style>
body {background:#0d1b2a;color:white;font-family:sans-serif;}
table {border-collapse: collapse;width:100%;}
th,td {padding:6px;text-align:center;}
tr:nth-child(even){background:#1b2a44;}
tr:nth-child(odd){background:#0d1b2a;}
th {background:#d90429;color:white;}
</style>
</head>
<body>
<h2>RedShark Threat Intelligence Dashboard</h2>
<h3>SecureNation Index</h3>
<img src="data:image/png;base64,{{ gauge }}">
<h3>Malaysia Heatmap</h3>
{{ heatmap | safe }}
<h3>Trend Chart</h3>
{% if trend %}<img src="data:image/png;base64,{{ trend }}">{% endif %}
<h3>Signal Types</h3>
{% if type_chart %}<img src="data:image/png;base64,{{ type_chart }}">{% endif %}
<h3>MITRE ATT&CK Matrix</h3>
{{ mitre_matrix | safe }}
<h3>Latest Signals</h3>
<table>
<tr><th>ID</th><th>Pulse</th><th>Signal</th><th>Type</th><th>Risk</th><th>Created</th></tr>
{% for row in latest %}
<tr>
<td>{{ row['id'] }}</td>
<td>{{ row['pulse'] }}</td>
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

# ---------------- DASHBOARD ROUTE ----------------
@app.route("/")
def dashboard():
    trend, type_chart = generate_charts()
    heatmap = generate_malaysia_heatmap()
    gauge = generate_secure_gauge()
    mitre_matrix = generate_mitre_matrix()
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    latest = c.execute("SELECT * FROM threats ORDER BY created_at DESC LIMIT 20").fetchall()
    conn.close()
    return render_template_string(TEMPLATE,
                                  trend=trend,
                                  type_chart=type_chart,
                                  heatmap=heatmap,
                                  gauge=gauge,
                                  mitre_matrix=mitre_matrix,
                                  latest=latest)

# ---------------- REPORT ROUTES ----------------
@app.route("/report/csv")
def csv_report():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    rows = c.execute("SELECT * FROM threats ORDER BY created_at DESC").fetchall()
    conn.close()
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(["ID","Pulse","Signal","Type","Class","MITRE","Risk","Created"])
    cw.writerows(rows)
    output = io.BytesIO()
    output.write(si.getvalue().encode())
    output.seek(0)
    return send_file(output, as_attachment=True, download_name=f"RedShark_report_{datetime.now().strftime('%Y%m%d%H%M%S')}.csv")

@app.route("/report/json")
def json_report():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    rows = c.execute("SELECT * FROM threats ORDER BY created_at DESC").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/report/pdf")
def pdf_report():
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = [Paragraph("RedShark Threat Intelligence Report", styles["Title"]), Spacer(1,12)]
    trend, type_chart = generate_charts()
    if trend:
        img = io.BytesIO(base64.b64decode(trend))
        elements.append(Image(img, width=420,height=200))
    if type_chart:
        img = io.BytesIO(base64.b64decode(type_chart))
        elements.append(Image(img, width=320,height=200))
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    rows = c.execute("SELECT * FROM threats ORDER BY created_at DESC").fetchall()
    conn.close()
    table_data = [["ID","Pulse","Signal","Type","Class","MITRE","Risk","Created"]]
    for r in rows:
        table_data.append([r["id"], r["pulse"], r["signal"], r["type"], r["classification"], r["mitre"], r["risk_score"], r["created_at"]])
    t = Table(table_data, repeatRows=1)
    t.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,0),colors.darkblue),
        ('TEXTCOLOR',(0,0),(-1,0),colors.white),
        ('ALIGN',(0,0),(-1,-1),'CENTER'),
        ('GRID',(0,0),(-1,-1),0.5,colors.white),
        ('BACKGROUND',(0,1),(-1,-1),colors.HexColor("#1b2a44")),
    ]))
    elements.append(t)
    doc.build(elements)
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name=f"RedShark_report_{datetime.now().strftime('%Y%m%d%H%M%S')}.pdf")

# ---------------- START ----------------
ensure_database()
fetch_otx_data()
threading.Thread(target=scheduler, daemon=True).start()

if __name__=="__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT",5000)))
