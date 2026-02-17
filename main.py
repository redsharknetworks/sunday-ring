import os
import json
import sqlite3
from flask import Flask, render_template, jsonify
from OTXv2 import OTXv2
import pandas as pd

# ----------------------------
# Configuration
# ----------------------------
OTX_API_KEY = os.getenv("OTX_API_KEY", "")
SEED_FILE = "otx_seed.json"  # stored in root of repo
DB_FILE = "indicators.db"

app = Flask(__name__)

# ----------------------------
# Database helpers
# ----------------------------
def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    return conn

def create_table_if_not_exists():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS indicators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT,
            indicator TEXT,
            country TEXT,
            risk_score REAL,
            created_at TEXT
        )
    """)
    conn.commit()
    conn.close()

# Initialize DB at startup
create_table_if_not_exists()

# ----------------------------
# Helper to insert indicators
# ----------------------------
def insert_indicators(indicators):
    if not indicators:
        return 0
    conn = get_db_connection()
    cursor = conn.cursor()
    rows = 0
    for ind in indicators:
        cursor.execute("""
            INSERT INTO indicators (type, indicator, country, risk_score, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (
            ind.get("type"),
            ind.get("indicator"),
            ind.get("country"),
            ind.get("risk_score"),
            ind.get("created_at")
        ))
        rows += 1
    conn.commit()
    conn.close()
    return rows

# ----------------------------
# Load manual seed file
# ----------------------------
def load_seed_file():
    if os.path.exists(SEED_FILE):
        with open(SEED_FILE, "r") as f:
            data = json.load(f)
        inserted = insert_indicators(data)
        return inserted
    return 0

# ----------------------------
# Fetch from OTX
# ----------------------------
def fetch_otx(limit=50):
    if not OTX_API_KEY:
        return {"message": "OTX API key not set", "status": "error"}

    otx = OTXv2(OTX_API_KEY)
    try:
        pulses = otx.getall(limit=limit)
    except Exception as e:
        return {"message": str(e), "status": "error"}

    indicators = []
    for pulse in pulses:
        for ind in pulse.get("indicators", []):
            indicators.append({
                "type": ind.get("type"),
                "indicator": ind.get("indicator"),
                "country": ind.get("country"),
                "risk_score": ind.get("risk_score"),
                "created_at": ind.get("created_at")
            })
    rows = insert_indicators(indicators)
    return {"message": f"{rows} rows inserted", "status": "ok"}

# ----------------------------
# Routes
# ----------------------------
@app.route("/")
def dashboard():
    try:
        conn = get_db_connection()
        df = pd.read_sql_query(
            "SELECT type, indicator, country, risk_score, created_at FROM indicators ORDER BY created_at DESC",
            conn
        )
        conn.close()
        return render_template("dashboard.html", data=df.to_dict(orient="records"))
    except Exception as e:
        return f"Dashboard read failed: {str(e)}"

@app.route("/fetch_otx")
def fetch_otx_route():
    # First, load manual seed file if exists
    seed_rows = load_seed_file()

    # Then fetch latest OTX
    result = fetch_otx(limit=50)
    result["seed_rows"] = seed_rows
    return jsonify(result)

# ----------------------------
# Run app
# ----------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=True)
