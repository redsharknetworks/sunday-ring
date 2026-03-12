import os
import io
import csv
import sqlite3
import threading
import time
import random
from datetime import datetime, timedelta
from flask import Flask, render_template_string, send_file
import plotly
import plotly.graph_objs as go
import json
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from plotly.utils import PlotlyJSONEncoder

app = Flask(__name__)
DB = "/tmp/threats.db"

# Malaysia states coordinates
MALAYSIA_STATES = {
    "Johor":[1.4927,103.7414],"Kedah":[6.1164,100.3678],"Kelantan":[6.1254,102.2381],
    "Melaka":[2.1896,102.2501],"Negeri Sembilan":[2.7290,101.9383],"Pahang":[3.8167,103.3333],
    "Perak":[4.5929,101.0900],"Perlis":[6.4400,100.2000],"Penang":[5.4164,100.3327],
    "Sabah":[5.9804,116.0735],"Sarawak":[1.5533,110.3592],"Selangor":[3.1390,101.6869],
    "Terengganu":[5.3300,103.1400],"Kuala Lumpur":[3.1390,101.6869],
    "Putrajaya":[2.9264,101.6981],"Labuan":[5.2833,115.2333]
}

ASSETS = ["Server-1","Server-2","Firewall-1","DB-Prod","Laptop-1"]
EVENT_TYPES = ["Malware","Phishing","Port Scan","Data Exfiltration","Suspicious Login"]

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
        source TEXT,
        city TEXT,
        severity TEXT,
        created_at TEXT
    )
    """)
    conn.commit()
    conn.close()

def cleanup_old_records():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    cutoff = (datetime.utcnow() - timedelta(days=60)).isoformat()
    c.execute("DELETE FROM threats WHERE created_at < ?", (cutoff,))
    conn.commit()
    conn.close()

# ---------------- INSERT THREAT ----------------
def insert_threat(pulse, indicator, typ, severity, score, source, city):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("""INSERT INTO threats (pulse, indicator, type, classification, mitre, risk_score, source, city, severity, created_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
              (pulse, indicator, typ, severity, "MITRE-T", score, source, city, severity, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()

# ---------------- DUMMY DATA ----------------
def insert_dummy_data(n=20):
    for _ in range(n):
        score = random.randint(10,95)
        severity = "Critical" if score >= 70 else "High" if score>=40 else "Medium"
        city = random.choice(list(MALAYSIA_STATES.keys()))
        insert_threat(f"Pulse {random.randint(1,20)}", f"malicious{random.randint(1,50)}.com",
                      random.choice(EVENT_TYPES), severity, score, "dummy", city)

# ---------------- SCHEDULER ----------------
def scheduler():
    while True:
        insert_dummy_data()
        cleanup_old_records()
        time.sleep(3600)

# ---------------- CHARTS ----------------
def generate_trend_chart():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT substr(created_at,1,10) as d, COUNT(*) as cnt FROM threats GROUP BY d").fetchall()
    conn.close()
    x = [r["d"] for r in rows] if rows else [datetime.utcnow().strftime("%Y-%m-%d")]
    y = [r["cnt"] for r in rows] if rows else [0]
    fig = go.Figure(data=[go.Scatter(x=x,y=y,mode="lines+markers",line=dict(color="#00e6ff"))])
    fig.update_layout(title="Threat Timeline",
                      paper_bgcolor="#0b1b2a",plot_bgcolor="#0b1b2a",font_color="#00e6ff")
    return json.dumps(fig,cls=PlotlyJSONEncoder)

def generate_type_chart():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT type, COUNT(*) as cnt FROM threats GROUP BY type").fetchall()
    conn.close()
    labels = [r["type"] for r in rows] if rows else ["No Data"]
    values = [r["cnt"] for r in rows] if rows else [0]
    fig = go.Figure(data=[go.Pie(labels=labels, values=values, hole=0.3)])
    fig.update_layout(title="Threat Type Distribution",
                      paper_bgcolor="#0b1b2a",plot_bgcolor="#0b1b2a",font_color="#00e6ff")
    return json.dumps(fig,cls=PlotlyJSONEncoder)

def generate_heatmap_cities():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT city FROM threats WHERE severity='Critical'").fetchall()
    conn.close()
    return [r["city"] for r in rows]

# ---------------- DASHBOARD ROUTE ----------------
@app.route("/")
def dashboard():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    table_data = [dict(r) for r in conn.execute("SELECT * FROM threats ORDER BY created_at DESC LIMIT 50").fetchall()]
    conn.close()
    trend = generate_trend_chart()
    type_chart = generate_type_chart()
    critical_cities = generate_heatmap_cities()
    gauge = 50  # placeholder
    return render_template_string(open("template.html").read(),
                                  table_data=table_data,
                                  trend=trend,
                                  type_chart=type_chart,
                                  critical_cities=critical_cities,
                                  positions=MALAYSIA_STATES,
                                  gauge=gauge)

# ---------------- START ----------------
ensure_database()
insert_dummy_data()
threading.Thread(target=scheduler,daemon=True).start()

if __name__=="__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT",5000)))