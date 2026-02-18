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
from PIL import Image as PILImage

app = Flask(__name__)
DB = "/data/threats.db" if os.path.exists("/data") else "threats.db"

OTX_KEY = os.getenv("OTX_KEY")
otx = OTXv2(OTX_KEY) if OTX_KEY else None
if not OTX_KEY:
    print("⚠️ WARNING: OTX_KEY not set. Dummy threats will be generated.")

# ---------------- GLOBAL STORAGE ----------------
charts = {"trend": None, "type_chart": None, "top10": None}
heatmap_path = "heatmap.png"
report_pdf_path = "report.pdf"
report_csv_path = "report.csv"
report_json_path = "report.json"

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

# ---------------- FETCH DATA ----------------
def fetch_data():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    created = datetime.utcnow().isoformat()
    if otx:
        try:
            pulses = otx.getall(limit=10)
        except Exception as e:
            print("OTX fetch error:", e)
            pulses = []
        for pulse in pulses:
            name = pulse.get("name", "OTX")
            for ind in pulse.get("indicators", []):
                val = ind.get("indicator")
                typ = ind.get("type", "domain")
                if not val: continue
                score = random.randint(50,95)
                try:
                    if typ in ["IPv4","domain","URL"]:
                        c.execute("INSERT OR IGNORE INTO threats (pulse,indicator,type,classification,mitre,risk_score,created_at) VALUES (?,?,?,?,?,?,?)",
                                  (name,val,typ,"Medium","OTX",score,created))
                    if "Hash" in typ:
                        c.execute("INSERT OR IGNORE INTO threat_hashes (pulse,hash,classification,mitre,risk_score,created_at) VALUES (?,?,?,?,?,?)",
                                  (name,val,"Medium","OTX",score,created))
                except: pass
    else:
        # Dummy data
        dummy_pulses = ["Red Shark Attack","Silent Hunter","Ghost Spider","Dark Wave","Cyber Kraken","Phantom Tiger"]
        dummy_types = ["IPv4","domain","URL","FileHash-MD5","FileHash-SHA256"]
        for _ in range(30):
            pulse = random.choice(dummy_pulses)
            indicator = f"dummy-{random.randint(1000,9999)}.com"
            typ = random.choice(dummy_types)
            score = random.randint(50,95)
            try:
                if typ in ["IPv4","domain","URL"]:
                    c.execute("INSERT OR IGNORE INTO threats (pulse,indicator,type,classification,mitre,risk_score,created_at) VALUES (?,?,?,?,?,?,?)",
                              (pulse,indicator,typ,random.choice(["Low","Medium","High"]),"N/A",score,created))
                if "Hash" in typ:
                    c.execute("INSERT OR IGNORE INTO threat_hashes (pulse,hash,classification,mitre,risk_score,created_at) VALUES (?,?,?,?,?,?)",
                              (pulse,indicator,random.choice(["Low","Medium","High"]),"N/A",score,created))
            except: pass
    conn.commit()
    conn.close()

# ---------------- BACKGROUND TASKS ----------------
def generate_charts_pdf_csv_json():
    global charts
    while True:
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        # Trend chart
        trend = c.execute("SELECT date(created_at), COUNT(*) FROM threats GROUP BY date(created_at) ORDER BY date(created_at)").fetchall()
        if trend:
            dates = [x[0] for x in trend]
            counts = [x[1] for x in trend]
            plt.figure(figsize=(6,3))
            ax = plt.gca()
            if os.path.exists("boxing_ring.png"):
                bg = plt.imread("boxing_ring.png")
                ax.imshow(bg, extent=[0,len(dates)-1,0,max(counts)+5], aspect='auto', alpha=0.2)
            plt.plot(dates, counts, marker="o", color="crimson")
            plt.xticks(rotation=45)
            plt.title("Threat Trend")
            buf = io.BytesIO()
            plt.tight_layout()
            plt.savefig(buf, format="png")
            plt.close()
            charts["trend"] = base64.b64encode(buf.getvalue()).decode()
        # Type chart
        types = c.execute("SELECT type, COUNT(*) FROM threats GROUP BY type").fetchall()
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
            charts["type_chart"] = base64.b64encode(buf.getvalue()).decode()
        # Top10 chart
        top10 = c.execute("SELECT pulse, COUNT(*) as cnt, AVG(risk_score) as avg_risk FROM threats GROUP BY pulse ORDER BY cnt DESC LIMIT 10").fetchall()
        if top10:
            pulses = [x[0] for x in top10]
            counts = [x[1] for x in top10]
            avg_risks = [x[2] for x in top10]
            colors_list = []
            for r in avg_risks[::-1]:
                if r>=80: colors_list.append("red")
                elif r>=60: colors_list.append("orange")
                else: colors_list.append("green")
            plt.figure(figsize=(6,3))
            plt.barh(pulses[::-1], counts[::-1], color=colors_list)
            plt.title("Top 10 Threat Pulses by Risk")
            plt.xlabel("Occurrences")
            plt.tight_layout()
            buf = io.BytesIO()
            plt.savefig(buf, format="png")
            plt.close()
            charts["top10"] = base64.b64encode(buf.getvalue()).decode()
        # Heatmap as image
        if True:
            from folium import Map
            from folium.plugins import HeatMap
            m = Map(location=[4.2105,101.9758], zoom_start=6)
            heat_data = [
                [3.1390,101.6869,5],[1.4927,103.7414,4],[5.4164,100.3327,3],[2.1896,102.2501,2],
                [6.1254,102.2381,2],[2.9216,101.6509,3],[2.9264,101.6998,3],[1.5533,110.3592,2],
                [5.9804,116.0735,2],[6.1203,100.3660,2],[5.3289,103.1403,2],[4.5975,101.0901,2],
                [6.4383,100.2002,2],[3.8070,103.3255,2],[2.7295,101.9385,2]
            ]
            HeatMap(heat_data,radius=25).add_to(m)
            m.save("heatmap.html")
            # Convert to PNG image
            os.system("chromium --headless --disable-gpu --screenshot={} heatmap.html".format(heatmap_path))
        # Generate PDF
        conn.row_factory = sqlite3.Row
        threats = c.execute("SELECT * FROM threats ORDER BY created_at DESC LIMIT 50").fetchall()
        hashes = c.execute("SELECT id,pulse,hash as indicator,'hash' as type,classification,mitre,risk_score,created_at FROM threat_hashes ORDER BY created_at DESC LIMIT 50").fetchall()
        conn.close()
        doc = SimpleDocTemplate(report_pdf_path,pagesize=landscape(A4),rightMargin=20,leftMargin=20,topMargin=30,bottomMargin=20)
        styles = getSampleStyleSheet()
        elements = []
        if os.path.exists("redshark.png"):
            elements.append(Image("redshark.png", width=120,height=40))
            elements.append(Spacer(1,12))
        elements.append(Paragraph("Threat Intelligence Report",styles["Title"]))
        elements.append(Spacer(1,12))
        for key in ["trend","type_chart","top10"]:
            img_data = charts.get(key)
            if img_data:
                elements.append(Image(io.BytesIO(base64.b64decode(img_data)), width=500,height=200))
                elements.append(Spacer(1,12))
        # Table
        data = [["ID","Pulse","Indicator","Type","Classification","MITRE","Risk","Created"]]
        for r in threats+hashes:
            data.append([r["id"],r["pulse"],r["indicator"],r["type"],r["classification"],r["mitre"],r["risk_score"],r["created_at"]])
        table = Table(data,repeatRows=1)
        table.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.darkblue),
                                   ('TEXTCOLOR',(0,0),(-1,0),colors.white),
                                   ('GRID',(0,0),(-1,-1),0.5,colors.grey),
                                   ('VALIGN',(0,0),(-1,-1),'TOP'),
                                   ('ALIGN',(0,0),(-1,-1),'CENTER')]))
        elements.append(table)
        doc.build(elements)
        # Generate CSV
        si = io.StringIO()
        cw = csv.writer(si)
        cw.writerow(["ID","Pulse","Indicator","Type","Classification","MITRE","Risk","Created"])
        for r in threats+hashes:
            cw.writerow([r["id"],r["pulse"],r["indicator"],r["type"],r["classification"],r["mitre"],r["risk_score"],r["created_at"]])
        with open(report_csv_path,"w",encoding="utf-8") as f:
            f.write(si.getvalue())
        # Generate JSON
        import json
        with open(report_json_path,"w",encoding="utf-8") as f:
            json.dump([dict(x) for x in threats+hashes],f,indent=2)
        time.sleep(600) # regenerate every 10 min

def start_background_tasks():
    t = threading.Thread(target=generate_charts_pdf_csv_json,daemon=True)
    t.start()

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
<img src="/heatmap.png" width="600">
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

{% if top10 %}
<div class="chart">
<h3>Top 10 Threat Pulses by Risk</h3>
<img src="data:image/png;base64,{{ top10 }}" width="600">
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
    return render_template_string(TEMPLATE, trend=charts.get("trend"), type_chart=charts.get("type_chart"),
                                  top10=charts.get("top10"), heatmap=True)

@app.route("/heatmap.png")
def heatmap_image():
    if os.path.exists(heatmap_path):
        return send_file(heatmap_path, mimetype="image/png")
    return "",404

@app.route("/report/pdf")
def pdf_report():
    if os.path.exists(report_pdf_path):
        return send_file(report_pdf_path, as_attachment=True, download_name="report.pdf")
    return "PDF not ready", 503

@app.route("/report/csv")
def csv_report():
    if os.path.exists(report_csv_path):
        return send_file(report_csv_path, as_attachment=True, download_name="report.csv")
    return "CSV not ready", 503

@app.route("/report/json")
def json_report():
    if os.path.exists(report_json_path):
        return send_file(report_json_path, as_attachment=True, download_name="report.json")
    return "JSON not ready", 503

# ---------------- INIT ----------------
ensure_database()
fetch_data()
start_background_tasks()

if __name__ == "__main__":
    port = int(os.environ.get("PORT",5000))
    app.run(host="0.0.0.0", port=port)
