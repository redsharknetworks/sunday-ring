import os
import sqlite3
import requests
from datetime import datetime, timezone, timedelta

from flask import Flask, render_template
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

app = Flask(__name__)

DB_PATH = "data.db"
OTX_API_KEY = os.getenv("OTX_API_KEY")

# =========================
# INIT DB
# =========================
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS indicators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            country TEXT,
            risk_score INTEGER,
            created_at TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

# =========================
# INSERT DATA
# =========================
def insert_indicator(ip, country, risk):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        INSERT INTO indicators (ip, country, risk_score, created_at)
        VALUES (?, ?, ?, ?)
    """, (ip, country, risk, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()

# =========================
# FETCH OTX
# =========================
def fetch_otx_data():
    if not OTX_API_KEY:
        return 0

    url = "https://otx.alienvault.com/api/v1/indicators/IPv4/reputation"
    headers = {"X-OTX-API-KEY": OTX_API_KEY}

    inserted = 0

    try:
        # simple demo IP list to avoid heavy memory
        test_ips = ["8.8.8.8", "1.1.1.1", "8.8.4.4"]

        for ip in test_ips:
            r = requests.get(f"{url}?ip={ip}", headers=headers, timeout=10)
            if r.status_code != 200:
                continue

            data = r.json()
            risk = data.get("reputation", 10)

            insert_indicator(ip, "Unknown", risk)
            inserted += 1

    except Exception as e:
        print("OTX ERROR:", e)

    return inserted

# =========================
# TREND CHART
# =========================
def generate_trend_chart():
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query(
        "SELECT created_at, risk_score FROM indicators ORDER BY created_at ASC",
        conn
    )
    conn.close()

    if df.empty:
        return None

    df["created_at"] = pd.to_datetime(df["created_at"])

    plt.figure(figsize=(6,3))
    plt.plot(df["created_at"], df["risk_score"], color="orange", linewidth=3)
    plt.title("Risk Trend")
    plt.xticks(rotation=45)
    plt.tight_layout()

    path = "static/trend.png"
    os.makedirs("static", exist_ok=True)
    plt.savefig(path)
    plt.close()

    return path

# =========================
# ROUTES
# =========================
@app.route("/")
def dashboard():
    trend_image = generate_trend_chart()

    tz = timezone(timedelta(hours=8))
    now = datetime.now(tz).strftime("%Y-%m-%d %H:%M:%S GMT+8")

    return render_template(
        "dashboard.html",
        trend_image=trend_image,
        timestamp=now
    )

@app.route("/fetch_otx")
def fetch_otx_route():
    try:
        rows = fetch_otx_data()
        return f"FETCH OK - {rows} rows inserted"
    except Exception as e:
        return f"ERROR: {str(e)}"

@app.route("/count")
def count():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM indicators")
    total = c.fetchone()[0]
    conn.close()
    return str(total)

# =========================
# RUN
# =========================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
