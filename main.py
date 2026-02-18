import os
import io
import csv
import sqlite3
import threading
import time
import random
from datetime import datetime
from flask import Flask, render_template_string, send_file, jsonify
from OTXv2 import OTXv2
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import base64
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle
from reportlab.lib.pagesizes import landscape, A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet

app = Flask(__name__)
DB = "threats.db"

OTX_KEY = os.getenv("OTX_KEY")
otx = OTXv2(OTX_KEY) if OTX_KEY else None
if not OTX_KEY:
    print("⚠️ WARNING: OTX_KEY not set. Dummy data will be generated.")

# ---------------- GLOBAL STORAGE ----------------
charts = {"trend": None, "type_chart": None, "top10": None, "heatmap": None}
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
def fetch_otx_data():
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
            name = pulse.get("name","OTX")
            for ind in pulse.get("indicators", []):
                val = ind.get("indicator")
                typ = ind.get("type","domain")
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

# ---------------- BACKGROUND CHARTS ----------------
def generate_charts_bg():
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
        top10 = c.execute("SELECT pulse, COUNT(*) as cnt FROM threats GROUP BY pulse ORDER BY cnt DESC LIMIT 10").fetchall()
        if top10:
            pulses = [x[0] for x in top10]
            counts = [x[1] for x in top10]
            plt.figure(figsize=(6,3))
            plt.barh(pulses[::-1], counts[::-1], color="red")
            plt.title("Top 10 Threat Pulses")
            plt.tight_layout()
            buf = io.BytesIO()
            plt.savefig(buf, format="png")
            plt.close()
            charts["top10"] = base64.b64encode(buf.getvalue()).decode()
        # Malaysia heatmap
        cities = [
            (3.1390,101.6869), # KL
            (1.4927,103.7414), # Johor
            (5.4164,100.3327), # Penang
            (2.1896,102.2501), # Melaka
            (6.1254,102.2381), # Kelantan
            (2.9216,101.6509), # Cyberjaya
            (2.9264,101.6998), # Putrajaya
            (1.5533,110.3592), # Kuching
            (5.9804,116.0735), # Kota Kinabalu
            (6.1203,100.3660), # Alor Setar
            (5.3289,103.1403), # Kuala Terengganu
            (4.5975,101.0901), # Ipoh
            (6.4383,100.2002), # Kangar
            (3.8070,103.3255), # Kuantan
            (2.7295,101.9385), # Seremban
        ]
        lats,lons = zip(*cities)
        plt.figure(figsize=(6,6))
        plt.scatter(lons,lats,s=100,c="red",alpha=0.6)
        plt.title("Malaysia Threat Heatmap")
        buf = io.BytesIO()
        plt.tight_layout()
        plt.savefig(buf,format="png")
        plt.close()
        charts["heatmap"] = base64.b64encode(buf.getvalue()).decode()
        conn.close()
        time.sleep(600)  # regenerate every 10 min

def start_background():
    t = threading.Thread(target=generate_charts_bg, daemon=True)
    t.start()

# ---------------- DASHBOARD ----------------
TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>DarkGrid Dashboard</title></head>
<body>
<h1>DarkGrid Threat Dashboard</h1>
{% if charts.trend %}<img src="data:image/png;base64,{{ charts.trend }}"><br>{% endif %}
{% if charts.type_chart %}<img src="data:image/png;base64,{{ charts.type_chart }}"><br>{% endif %}
{% if charts.top10 %}<img src="data:image/png;base64,{{ charts.top10 }}"><br>{% endif %}
{% if charts.heatmap %}<img src="data:image/png;base64,{{ charts.heatmap }}"><br>{% endif %}
<br>
<a href="/report/pdf">PDF</a> |
<a href="/report/csv">CSV</a> |
<a href="/report/json">JSON</a>
</body>
</html>
"""

@app.route("/")
def dashboard():
    return render_template_string(TEMPLATE, charts=charts)

# ---------------- REPORTS ----------------
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
fetch_otx_data()
start_background()

if __name__ == "__main__":
    port = int(os.environ.get("PORT",5000))
    app.run(host="0.0.0.0", port=port, threaded=True)
