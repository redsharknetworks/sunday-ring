import os
import sqlite3
import pandas as pd
from flask import Flask, render_template, jsonify
from datetime import datetime, timedelta
from matplotlib import pyplot as plt
from OTXv2 import OTXv2
import pdfkit
import folium

# ===== CONFIG =====
DB_FILE = os.path.join(os.getcwd(), "indicators.db")  # Absolute path
OTX_API_KEY = os.environ.get("OTX_API_KEY")
COUNTRY_FILTER = "MY"
ROWS_PER_PAGE = 20

app = Flask(__name__)

# ===== DATABASE =====
def init_db():
    """Ensure DB and table exist."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS indicators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT UNIQUE,
            country TEXT,
            risk_score INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

def insert_indicator(ip, country, risk_score):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    try:
        c.execute('''
            INSERT OR IGNORE INTO indicators (ip, country, risk_score) 
            VALUES (?, ?, ?)
        ''', (ip, country, risk_score))
        conn.commit()
    except Exception as e:
        print("DB insert error:", e)
    finally:
        conn.close()

# ===== OTX FETCH =====
@app.route("/fetch_otx")
def fetch_otx():
    try:
        init_db()  # Ensure table exists before fetch
        otx = OTXv2(OTX_API_KEY)
        pulses = otx.getall(limit=50)
        inserted = 0

        for pulse in pulses:
            indicators = pulse.get("indicators", [])
            for ind in indicators:
                ip = ind.get("indicator")
                if not ip or len(ip.split(".")) != 4:
                    continue
                geo = ind.get("geo", {})
                country = geo.get("country")
                if country != COUNTRY_FILTER:
                    continue
                risk_score = pulse.get("threat_score", 50)
                insert_indicator(ip, country, risk_score)
                inserted += 1

        return jsonify({"status": "ok", "inserted": inserted})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

# ===== TREND CHART =====
def generate_trend_chart():
    init_db()  # ensure table exists
    conn = sqlite3.connect(DB_FILE)
    df = pd.read_sql_query(
        "SELECT created_at, risk_score FROM indicators ORDER BY created_at ASC", conn
    )
    conn.close()
    if df.empty:
        return None
    plt.figure(figsize=(10,5))
    plt.plot(pd.to_datetime(df['created_at']), df['risk_score'], marker='o')
    plt.title("Risk Score Trend")
    plt.xlabel("Time")
    plt.ylabel("Risk Score")
    plt.grid(True)
    plt.tight_layout()
    img_path = os.path.join("static", "trend_chart.png")
    plt.savefig(img_path)
    plt.close()
    return img_path

# ===== DASHBOARD =====
@app.route("/")
def dashboard():
    init_db()
    conn = sqlite3.connect(DB_FILE)
    df = pd.read_sql_query(
        "SELECT ip, country, risk_score, created_at FROM indicators ORDER BY created_at DESC", conn
    )
    conn.close()
    trend_image = generate_trend_chart()
    malaysia_time = (datetime.utcnow() + timedelta(hours=8)).strftime("%Y-%m-%d %H:%M:%S")
    return render_template("dashboard.html",
                           indicators=df.to_dict(orient="records"),
                           trend_image=trend_image,
                           timestamp=malaysia_time)

# ===== MAIN =====
if __name__ == "__main__":
    init_db()  # Ensure DB ready before first request
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
