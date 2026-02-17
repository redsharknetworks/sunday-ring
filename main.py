import os
import json
import sqlite3
from datetime import datetime
from flask import Flask, render_template, jsonify
from OTXv2 import OTXv2  # make sure OTXv2.py is in your project
import pandas as pd
import matplotlib.pyplot as plt
import io
import base64

# ---------- CONFIG ----------
OTX_API_KEY = os.getenv("OTX_API_KEY")
DB_FILE = "otx.db"
SEED_FILE = "otx_seed.json"  # optional manual seed JSON
# ----------------------------

app = Flask(__name__)

# ---------- DATABASE ----------
def init_db():
    """Create indicators table if not exists"""
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

def insert_indicator(ind_type, indicator, country, risk_score, created_at):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO indicators (type, indicator, country, risk_score, created_at)
        VALUES (?, ?, ?, ?, ?)
    """, (ind_type, indicator, country, risk_score, created_at))
    conn.commit()
    conn.close()

# ---------- MANUAL SEED ----------
def populate_from_seed():
    if os.path.exists(SEED_FILE):
        with open(SEED_FILE, "r") as f:
            data = json.load(f)
        inserted = 0
        for ioc in data.get("indicators", []):
            insert_indicator(
                ioc.get("type", ""),
                ioc.get("indicator", ""),
                ioc.get("country", ""),
                ioc.get("risk_score", 0),
                ioc.get("created_at", datetime.utcnow().isoformat())
            )
            inserted += 1
        return inserted
    return 0

# ---------- FETCH FROM OTX ----------
@app.route("/fetch_otx")
def fetch_otx():
    if not OTX_API_KEY:
        return jsonify({"status": "error", "message": "OTX_API_KEY not set"}), 400

    try:
        otx = OTXv2(OTX_API_KEY)
        # Example: get last 50 pulses
        pulses = otx.getall(limit=50)
        count = 0
        for pulse in pulses:
            for ind in pulse.get("indicators", []):
                insert_indicator(
                    ind.get("type", ""),
                    ind.get("indicator", ""),
                    ind.get("country", ""),
                    ind.get("risk_score", 0),
                    ind.get("created_at", datetime.utcnow().isoformat())
                )
                count += 1
        return jsonify({"status": "ok", "inserted": count})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

# ---------- DASHBOARD ----------
@app.route("/")
def dashboard():
    try:
        conn = sqlite3.connect(DB_FILE)
        df = pd.read_sql_query(
            "SELECT type, indicator, country, risk_score, created_at FROM indicators ORDER BY created_at DESC",
            conn
        )
        conn.close()

        # Generate chart
        if not df.empty:
            plt.figure(figsize=(6,4))
            df_group = df.groupby("type").size()
            df_group.plot(kind="bar")
            plt.title("Indicators by Type")
            plt.xlabel("Type")
            plt.ylabel("Count")
            img = io.BytesIO()
            plt.tight_layout()
            plt.savefig(img, format='png')
            img.seek(0)
            chart_url = base64.b64encode(img.getvalue()).decode()
            plt.close()
        else:
            chart_url = None

        return render_template("dashboard.html", data=df.to_dict(orient="records"), chart_url=chart_url)
    except Exception as e:
        return f"Dashboard read failed: {e}"

# ---------- POPULATE SEED ON STARTUP ----------
@app.before_first_request
def startup_seed():
    inserted = populate_from_seed()
    if inserted:
        print(f"Seeded {inserted} indicators from {SEED_FILE}")

# ---------- RUN ----------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=True)
