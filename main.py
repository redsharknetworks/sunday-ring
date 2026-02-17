import os
import sqlite3
from datetime import datetime, timedelta
from flask import Flask, render_template, jsonify
import pandas as pd
import matplotlib.pyplot as plt
import io
import base64
from OTXv2 import OTXv2

# -----------------------------
# Configuration
# -----------------------------
DB_FILE = "indicators.db"
OTX_API_KEY = os.getenv("OTX_API_KEY")  # Make sure this is set
COUNTRY_FILTER = "MY"  # Malaysia

app = Flask(__name__)

# -----------------------------
# Initialize Database
# -----------------------------
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS indicators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            country TEXT,
            risk_score INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# -----------------------------
# Insert Indicator
# -----------------------------
def insert_indicator(ip, country, risk_score):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO indicators (ip, country, risk_score, created_at) VALUES (?, ?, ?, ?)",
        (ip, country, risk_score, datetime.utcnow())
    )
    conn.commit()
    conn.close()

# -----------------------------
# Fetch OTX Pulses
# -----------------------------
@app.route("/fetch_otx")
def fetch_otx():
    try:
        otx = OTXv2(OTX_API_KEY)

        # Get all pulses (limit for demo)
        pulses = otx.getall(indicator_type="IPv4", limit=50)  

        inserted = 0
        for pulse in pulses:
            for ind in pulse.get("indicators", []):
                ip = ind.get("indicator")
                country = ind.get("geo", {}).get("country")  # Some pulses include country
                if country != COUNTRY_FILTER:
                    continue  # Only Malaysia
                risk_score = pulse.get("threat_score", 50)  # Approximation
                insert_indicator(ip, country, risk_score)
                inserted += 1

        return jsonify({"status": "ok", "inserted": inserted})

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

# -----------------------------
# Generate Trend Chart
# -----------------------------
def generate_trend_chart():
    conn = sqlite3.connect(DB_FILE)
    df = pd.read_sql_query(
        "SELECT created_at, risk_score FROM indicators ORDER BY created_at ASC",
        conn
    )
    conn.close()

    if df.empty:
        return None

    plt.figure(figsize=(10,4))
    plt.plot(pd.to_datetime(df["created_at"]), df["risk_score"], marker='o')
    plt.title("Risk Score Trend")
    plt.xlabel("Time")
    plt.ylabel("Risk Score")
    plt.tight_layout()

    buf = io.BytesIO()
    plt.savefig(buf, format='png', bbox_inches='tight')
    buf.seek(0)
    encoded = base64.b64encode(buf.read()).decode("utf-8")
    plt.close()
    return encoded

# -----------------------------
# Dashboard
# -----------------------------
@app.route("/")
def dashboard():
    trend_image = generate_trend_chart()
    timestamp = (datetime.utcnow() + timedelta(hours=8)).strftime("%Y-%m-%d %H:%M:%S")
    return render_template("dashboard.html", trend_image=trend_image, timestamp=timestamp)

# -----------------------------
# Run Flask
# -----------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)))
