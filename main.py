import os
import json
import sqlite3
import pandas as pd
from flask import Flask, jsonify, render_template
from OTXv2 import OTXv2

DB_PATH = "threat_intel.db"
SEED_FILE = "otx_seed.json"
OTX_API_KEY = os.environ.get("OTX_API_KEY")

app = Flask(__name__)

# Initialize DB
def init_db():
    conn = sqlite3.connect(DB_PATH)
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

# Load seed JSON if exists
def load_seed():
    if os.path.exists(SEED_FILE):
        with open(SEED_FILE, "r") as f:
            data = json.load(f)
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        for entry in data.get("indicators", []):
            cursor.execute("""
                INSERT INTO indicators (type, indicator, country, risk_score, created_at)
                VALUES (?, ?, ?, ?, ?)
            """, (
                entry.get("type"),
                entry.get("indicator"),
                entry.get("country"),
                entry.get("risk_score"),
                entry.get("created_at")
            ))
        conn.commit()
        conn.close()
        print(f"Loaded {len(data.get('indicators', []))} rows from seed JSON.")
    else:
        print("No seed JSON found, skipping.")

# Fetch from OTX if key exists
def fetch_otx(limit=50):
    if not OTX_API_KEY:
        print("OTX_API_KEY not set, skipping OTX fetch.")
        return {"status": "skipped", "message": "OTX key not set"}
    otx = OTXv2(OTX_API_KEY)
    try:
        pulses = otx.getall(limit=limit)
    except Exception as e:
        print("OTX fetch failed:", e)
        return {"status": "error", "message": str(e)}
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    count = 0
    for pulse in pulses:
        for ind in pulse.get("indicators", []):
            cursor.execute("""
                INSERT INTO indicators (type, indicator, country, risk_score, created_at)
                VALUES (?, ?, ?, ?, ?)
            """, (
                ind.get("type"),
                ind.get("indicator"),
                ind.get("country", ""),
                ind.get("risk_score", 0),
                ind.get("created_at")
            ))
            count += 1
    conn.commit()
    conn.close()
    print(f"Inserted {count} indicators from OTX.")
    return {"status": "ok", "inserted": count}

@app.route("/fetch_otx")
def fetch_route():
    result = fetch_otx()
    return jsonify(result)

@app.route("/")
def dashboard():
    conn = sqlite3.connect(DB_PATH)
    try:
        df = pd.read_sql_query("SELECT type, indicator, country, risk_score, created_at FROM indicators ORDER BY created_at DESC", conn)
        data = df.to_dict(orient="records")
    except Exception as e:
        data = {"error": str(e)}
    conn.close()
    return render_template("dashboard.html", indicators=data)

if __name__ == "__main__":
    init_db()
    load_seed()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
