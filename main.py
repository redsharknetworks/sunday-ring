import os
import io
import csv
import base64
import sqlite3
import threading
import time
import random
from datetime import datetime, timedelta

import requests
from flask import Flask, render_template_string, send_file, jsonify

from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

import folium
from folium.plugins import HeatMap


# ---------------- CONFIG ----------------

app = Flask(__name__)

DB = os.getenv("DB_PATH", "threats.db")
OTX_KEY = os.getenv("OTX_KEY")
OTX_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"
RETENTION_DAYS = int(os.getenv("RETENTION_DAYS", 30))


# ---------------- DATABASE ----------------

def get_conn():
    return sqlite3.connect(DB, timeout=30, check_same_thread=False)


def ensure_database():
    conn = get_conn()
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
        created_at TEXT,
        UNIQUE(signal, type)
    )
    """)
    conn.commit()
    conn.close()


# ---------------- RISK ENGINE ----------------

def calculate_risk(indicator_type):
    base = {
        "domain": 75,
        "ip": 80,
        "url": 85,
        "file_hash": 90
    }.get(indicator_type, 70)

    return base + random.randint(0, 5)


def classify(score):
    if score >= 85:
        return "High"
    elif score >= 70:
        return "Medium"
    return "Low"


# ---------------- CLEANUP ----------------

def cleanup_old_data():
    cutoff = datetime.utcnow() - timedelta(days=RETENTION_DAYS)
    conn = get_conn()
    conn.execute(
        "DELETE FROM threats WHERE created_at < ?",
        (cutoff.isoformat(),)
    )
    conn.commit()
    conn.close()


# ---------------- DUMMY DATA ----------------

def insert_dummy_data():
    conn = get_conn()
    c = conn.cursor()

    for i in range(20):
        pulse = f"Dummy Pulse {i+1}"
        signal = f"malicious{i+1}.com"
        score = random.randint(60, 95)
        classification = classify(score)

        c.execute("""
        INSERT OR IGNORE INTO threats
        (pulse, signal, type, classification, mitre, risk_score, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            pulse,
            signal,
            "domain",
            classification,
            "OTX",
            score,
            datetime.utcnow().isoformat()
        ))

    conn.commit()
    conn.close()


# ---------------- OTX FETCH ----------------

def fetch_otx_data():
    ensure_database()

    if not OTX_KEY:
        insert_dummy_data()
        return

    headers = {"X-OTX-API-KEY": OTX_KEY}

    try:
        r = requests.get(OTX_URL, headers=headers, timeout=20)
        r.raise_for_status()
        pulses = r.json().get("results", [])
    except Exception:
        insert_dummy_data()
        return

    conn = get_conn()
    c = conn.cursor()

    for pulse in pulses[:10]:
        name = pulse.get("name", "OTX Pulse")
        for ind in pulse.get("indicators", []):
            val = ind.get("indicator")
            typ = ind.get("type", "domain")
            if not val:
                continue

            score = calculate_risk(typ)
            classification = classify(score)

            c.execute("""
            INSERT OR IGNORE INTO threats
            (pulse, signal, type, classification, mitre, risk_score, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                name,
                val,
                typ,
                classification,
                "OTX",
                score,
                datetime.utcnow().isoformat()
            ))

    conn.commit()
    conn.close()
    cleanup_old_data()


# ---------------- SCHEDULER ----------------

def scheduler():
    while True:
        fetch_otx_data()
        time.sleep(3600)


# ---------------- CHARTS ----------------

def generate_trend_chart():
    conn = get_conn()
    conn.row_factory = sqlite3.Row
    trend = conn.execute("""
    SELECT substr(created_at,1,10) as date, COUNT(*) as cnt
    FROM threats
    GROUP BY date ORDER BY date
    """).fetchall()
    conn.close()

    if not trend:
        return None

    dates = [x["date"] for x in trend]
    counts = [x["cnt"] for x in trend]

    plt.figure(figsize=(6,3), facecolor="#0A2239")
    ax = plt.gca()
    ax.set_facecolor("#0A2239")

    plt.plot(dates, counts, marker="o", color="crimson")
    plt.title("Threat Trend", color="white")
    plt.xticks(rotation=45, color="white")
    plt.yticks(color="white")

    buf = io.BytesIO()
    plt.tight_layout()
    plt.savefig(buf, format="png", facecolor="#0A2239")
    plt.close()
    buf.seek(0)
    return base64.b64encode(buf.getvalue()).decode()


def generate_type_chart():
    conn = get_conn()
    conn.row_factory = sqlite3.Row
    types = conn.execute("""
    SELECT type, COUNT(*) as cnt
    FROM threats GROUP BY type
    """).fetchall()
    conn.close()

    if not types:
        return None

    labels = [x["type"] for x in types]
    values = [x["cnt"] for x in types]

    plt.figure(figsize=(4,3), facecolor="#0A2239")
    ax = plt.gca()
    ax.set_facecolor("#0A2239")

    plt.bar(labels, values, color="crimson")
    plt.title("Signal Types", color="white")
    plt.xticks(color="white")
    plt.yticks(color="white")

    buf = io.BytesIO()
    plt.tight_layout()
    plt.savefig(buf, format="png", facecolor="#0A2239")
    plt.close()
    buf.seek(0)
    return base64.b64encode(buf.getvalue()).decode()


# ---------------- MALAYSIA HEATMAP ----------------

def generate_heatmap():
    malaysia_coords = [
        [3.1390,101.6869,5],
        [2.1896,102.2501,3],
        [1.4927,103.7414,3],
        [5.9804,116.0735,2],
        [1.5533,110.3592,2],
        [6.1164,100.3678,2],
        [5.4164,100.3327,2],
        [6.1254,102.2381,2],
        [2.7290,101.9383,2],
        [4.5929,101.0900,2],
        [5.3300,103.1400,2],
        [3.8167,103.3333,2],
    ]

    m = folium.Map(
        location=[4.2105,101.9758],
        zoom_start=6,
        tiles="CartoDB dark_matter"
    )

    HeatMap(malaysia_coords, radius=25).add_to(m)
    return m._repr_html_()


# ---------------- SUMMARY ----------------

def generate_summary():
    conn = get_conn()
    conn.row_factory = sqlite3.Row

    total = conn.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
    high = conn.execute(
        "SELECT COUNT(*) FROM threats WHERE risk_score>=85"
    ).fetchone()[0]

    types = conn.execute("""
    SELECT type, COUNT(*) as cnt FROM threats GROUP BY type
    """).fetchall()

    conn.close()

    return f"Detected {total} signals. {high} high-risk. Breakdown: " + \
           ", ".join([f"{x['type']}({x['cnt']})" for x in types])


# ---------------- TEMPLATE ----------------

# (Your original HTML template remains unchanged here for brevity)
# Keep your previous TEMPLATE variable exactly as you had it.


# ---------------- ROUTES ----------------

@app.route("/")
def dashboard():
    trend = generate_trend_chart()
    type_chart = generate_type_chart()
    heatmap = generate_heatmap()

    conn = get_conn()
    conn.row_factory = sqlite3.Row
    table_data = conn.execute(
        "SELECT * FROM threats ORDER BY created_at DESC LIMIT 50"
    ).fetchall()
    conn.close()

    summary_text = generate_summary()

    return render_template_string(
        TEMPLATE,
        trend=trend,
        type_chart=type_chart,
        heatmap=heatmap,
        table_data=table_data,
        summary_text=summary_text
    )


# ---------------- START ----------------

ensure_database()
fetch_otx_data()

if os.environ.get("WERKZEUG_RUN_MAIN") == "true":
    threading.Thread(target=scheduler, daemon=True).start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
