import os
import json
import sqlite3
from datetime import datetime
from flask import Flask, render_template, jsonify
from OTXv2 import OTXv2
import pandas as pd

# -------------------------
# Config
# -------------------------
DB_FILE = os.path.join(os.path.dirname(__file__), "indicators.db")
SEED_FILE = os.path.join(os.path.dirname(__file__), "otx_seed.json")
OTX_API_KEY = os.environ.get("OTX_API_KEY", "")

app = Flask(__name__)

# -------------------------
# Initialize DB with seed
# -------------------------
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # Create table if not exists
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

    # Seed DB if empty
    cursor.execute("SELECT COUNT(*) FROM indicators")
    count = cursor.fetchone()[0]

    if count == 0 and os.path.exists(SEED_FILE):
        with open(SEED_FILE, "r") as f:
            seeds = json.load(f)
            total = 0
            for seed in seeds:
                for ind in seed["indicators"]:
                    cursor.execute("""
                    INSERT INTO indicators (type, indicator, country, risk_score, created_at)
                    VALUES (?, ?, ?, ?, ?)
                    """, (
                        ind["type"],
                        ind["indicator"],
                        ind.get("country", ""),
                        ind.get("risk_score", 50),
                        ind.get("created", datetime.utcnow().isoformat())
                    ))
                    total += 1
            print(f"[INIT] Seeded {total} indicators into DB")
        conn.commit()
    conn.close()


# -------------------------
# Routes
# -------------------------
@app.route("/")
def dashboard():
    conn = sqlite3.connect(DB_FILE)
    try:
        df = pd.read_sql_query(
            "SELECT type, indicator, country, risk_score, created_at FROM indicators ORDER BY created_at DESC",
            conn
        )
        data = df.to_dict(orient="records")
    except Exception as e:
        print(f"[ERROR] Dashboard read failed: {e}")
        data = []
    conn.close()
    return render_template("dashboard.html", indicators=data)


@app.route("/fetch_otx")
def fetch_otx():
    if not OTX_API_KEY:
        return jsonify({"status": "error", "message": "OTX_API_KEY not set"}), 400

    otx = OTXv2(OTX_API_KEY)
    try:
        pulses = otx.getall(limit=50)  # Fetch latest 50 pulses
    except Exception as e:
        print(f"[ERROR] OTX fetch failed: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

    inserted = 0
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    for pulse in pulses:
        for ind in pulse.get("indicators", []):
            try:
                cursor.execute("""
                INSERT INTO indicators (type, indicator, country, risk_score, created_at)
                VALUES (?, ?, ?, ?, ?)
                """, (
                    ind["type"],
                    ind["indicator"],
                    ind.get("country", ""),
                    ind.get("risk_score", 50),
                    ind.get("created", datetime.utcnow().isoformat())
                ))
                inserted += 1
            except Exception as e:
                print(f"[WARN] Insert failed for {ind}: {e}")
                continue
    conn.commit()
    conn.close()
    return jsonify({"status": "ok", "inserted": inserted})


# -------------------------
# Main
# -------------------------
if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
