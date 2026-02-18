import os
import io
import sqlite3
import threading
import time
import random
from datetime import datetime
from flask import Flask, render_template_string, send_file, jsonify
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import base64
import csv
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle
from reportlab.lib.pagesizes import landscape, A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet

app = Flask(__name__)
DB = "threats.db"  # Use relative path

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
    conn.commit()
    conn.close()

# ---------------- DUMMY DATA ----------------
def fetch_dummy_data():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    dummy_pulses = ["Red Shark Attack","Silent Hunter","Ghost Spider","Dark Wave","Cyber Kraken","Phantom Tiger"]
    dummy_types = ["IPv4","domain","URL","FileHash-MD5","FileHash-SHA256"]
    for _ in range(30):
        pulse = random.choice(dummy_pulses)
        indicator = f"dummy-{random.randint(1000,9999)}.com"
        typ = random.choice(dummy_types)
        score = random.randint(50,95)
        created = datetime.utcnow().isoformat()
        try:
            c.execute("INSERT OR IGNORE INTO threats (pulse,indicator,type,classification,mitre,risk_score,created_at) VALUES (?,?,?,?,?,?,?)",
                      (pulse,indicator,typ,random.choice(["Low","Medium","High"]),"N/A",score,created))
        except: pass
    conn.commit()
    conn.close()

# ---------------- BACKGROUND CHARTS ----------------
charts = {"trend": None, "type_chart": None, "top10": None, "heatmap": None}

def generate_charts_bg():
    while True:
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        # Trend chart
        trend = c.execute("SELECT date(created_at), COUNT(*) FROM threats GROUP BY date(created_at) ORDER BY date(created_at)").fetchall()
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
        # Malaysia heatmap (scatter plot)
        cities = [
            (3.1390,101.6869), (1.4927,103.7414), (5.4164,100.3327), (2.1896,102.2501),
            (6.1254,102.2381), (2.9216,101.6509), (2.9264,101.6998), (1.5533,110.3592),
            (5.9804,116.0735), (6.1203,100.3660), (5.3289,103.1403), (4.5975,101.0901),
            (6.4383,100.2002), (3.8070,103.3255), (2.7295,101.9385)
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
        time.sleep(600)

def start_background():
    t = threading.Thread(target=generate_charts_bg, daemon=True)
    t.start()

# ---------------- DASHBOARD ----------------
TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>Dashboard</title></head>
<body>
<h1>DarkGrid Threat Dashboard</h1>
{% if charts.trend %}<img src="data:image/png;base64,{{ charts.trend }}"><br>{% endif %}
{% if charts.type_chart %}<img src="data:image/png;base64,{{ charts.type_chart }}"><br>{% endif %}
{% if charts.top10 %}<img src="data:image/png;base64,{{ charts.top10 }}"><br>{% endif %}
{% if charts.heatmap %}<img src="data:image/png;base64,{{ charts.heatmap }}"><br>{% endif %}
</body>
</html>
"""

@app.route("/")
def dashboard():
    return render_template_string(TEMPLATE, charts=charts)

# ---------------- INIT ----------------
ensure_database()
fetch_dummy_data()
start_background()

if __name__ == "__main__":
    port = int(os.environ.get("PORT",5000))
    app.run(host="0.0.0.0", port=port)
