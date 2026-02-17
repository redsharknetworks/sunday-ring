import os
import json
import sqlite3
import pandas as pd
from flask import Flask, render_template, jsonify
from OTXv2 import OTXv2

app = Flask(__name__)

# --- Config ---
DB_FILE = "ioc.db"
SEED_FILE = "seed.json"
OTX_API_KEY = os.getenv("OTX_API_KEY")  # Ensure you set this in Render env

# --- Initialize Database ---
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS indicators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT,
            indicator TEXT,
            country TEXT,
            risk_score INTEGER,
            created_at TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

# --- Load Seed JSON if exists ---
def load_seed():
    if os.path.exists(SEED_FILE):
        with open(SEED_FILE, "r") as f:
            data = json.load(f)
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        for i in data:
            cursor.execute("""
                INSERT INTO indicators (type, indicator, country, risk_score, created_at)
                VALUES (?, ?, ?, ?, ?)
            """, (
                i.get("type"),
                i.get("indicator"),
                i.get("country"),
                i.get("risk_score"),
                i.get("created_at")
            ))
        conn.commit()
        conn.close()

# Uncomment to load seed once
# load_seed()

# --- Dashboard ---
@app.route("/")
def dashboard():
    conn = sqlite3.connect(DB_FILE)
    try:
        df = pd.read_sql_query(
            "SELECT type, indicator, country, risk_score, created_at FROM indicators ORDER BY created_at DESC",
            conn
        )
        chart_data = df.to_dict(orient="records") if not df.empty else []
    except Exception as e:
        print(f"Dashboard read failed: {e}")
        chart_data = []
    finally:
        conn.close()
    return render_template("dashboard.html", chart_data=chart_data)

# --- Fetch OTX manually ---
@app.route("/fetch_otx")
def fetch_otx():
    if not OTX_API_KEY:
        return jsonify({"status": "error", "message": "OTX_API_KEY not set"}), 400

    try:
        otx = OTXv2(OTX_API_KEY)
        pulses = otx.getall(limit=50)  # adjust limit
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    rows_inserted = 0

    for pulse in pulses:
        for ioc in pulse.get("indicators", []):
            cursor.execute("""
                INSERT INTO indicators (type, indicator, country, risk_score, created_at)
                VALUES (?, ?, ?, ?, ?)
            """, (
                ioc.get("type"),
                ioc.get("indicator"),
                ioc.get("country", ""),
                ioc.get("risk_score", 0),
                ioc.get("created_at")
            ))
            rows_inserted += 1
    conn.commit()
    conn.close()

    return jsonify({"status": "ok", "rows_inserted": rows_inserted})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
