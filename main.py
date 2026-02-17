from flask import Flask, render_template, send_file, jsonify
import requests
import pandas as pd
import sqlite3
import os
from datetime import datetime, timedelta, timezone
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from reportlab.pdfgen import canvas
import csv
import json
import pytz

app = Flask(__name__)

DB = "threats.db"

# ---------------- DB INIT ----------------
def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS indicators(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            risk INTEGER,
            mitre TEXT,
            created_at TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

# ---------------- OTX FETCH (LIMITED) ----------------
def fetch_otx():
    try:
        url = "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=3"
        r = requests.get(url, timeout=10)
        data = r.json()

        conn = sqlite3.connect(DB)
        c = conn.cursor()

        for pulse in data.get("results", []):
            for ind in pulse.get("indicators", [])[:3]:
                ip = ind.get("indicator", "")
                risk = 50
                mitre = "T1046"

                c.execute("""
                    INSERT INTO indicators(ip,risk,mitre,created_at)
                    VALUES (?,?,?,?)
                """, (
                    ip,
                    risk,
                    mitre,
                    datetime.utcnow().isoformat()
                ))

        conn.commit()
        conn.close()
        return "OK"
    except:
        return "FAILED"

@app.route("/fetch_otx")
def manual_otx():
    return fetch_otx()

# ---------------- TREND CHART ----------------
def generate_trend():
    conn = sqlite3.connect(DB)
    df = pd.read_sql_query("""
        SELECT DATE(created_at) d, AVG(risk) r
        FROM indicators
        GROUP BY d
    """, conn)
    conn.close()

    if df.empty:
        return None

    plt.figure(figsize=(6,3))
    plt.plot(df["d"], df["r"], color="orange", linewidth=3)
    plt.title("Risk Trend")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig("static/trend.png")
    plt.close()

    return "trend.png"

# ---------------- EXPORT REPORT ----------------
@app.route("/generate_report")
def export_report():
    conn = sqlite3.connect(DB)
    df = pd.read_sql_query("SELECT * FROM indicators", conn)
    conn.close()

    ts = datetime.utcnow().strftime("%Y%m%d_%H%M")
    base = f"darkgrid_redshark_{ts}"

    # CSV
    df.to_csv(f"{base}.csv", index=False)

    # JSON
    df.to_json(f"{base}.json", orient="records")

    # PDF
    c = canvas.Canvas(f"{base}.pdf")
    c.drawString(50, 800, "Threat Report")
    c.drawString(50, 780, f"Records: {len(df)}")
    c.save()

    return jsonify({"status": "generated", "file": base})

# ---------------- DASHBOARD ----------------
@app.route("/")
def dashboard():
    trend_img = generate_trend()

    conn = sqlite3.connect(DB)
    df = pd.read_sql_query("""
        SELECT ip,risk,mitre,created_at
        FROM indicators
        ORDER BY created_at DESC
        LIMIT 200
    """, conn)
    conn.close()

    malaysia_time = (
        datetime.utcnow().replace(tzinfo=timezone.utc)
        + timedelta(hours=8)
    ).strftime("%Y-%m-%d %H:%M:%S")

    return render_template(
        "dashboard.html",
        table=df.to_dict(orient="records"),
        trend=trend_img,
        malaysia_time=malaysia_time
    )

if __name__ == "__main__":
    app.run()
