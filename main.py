import os
import sqlite3
from flask import Flask, render_template, jsonify
from OTXv2 import OTXv2
import pandas as pd

app = Flask(__name__)

# Database file
DB_FILE = "indicators.db"

# Get OTX API key from environment
OTX_API_KEY = os.environ.get("OTX_API_KEY")
if not OTX_API_KEY:
    raise ValueError("OTX_API_KEY not set in environment variables")

# Initialize OTX
otx = OTXv2(OTX_API_KEY)

# Ensure the indicators table exists
def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS indicators (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT,
                country TEXT,
                risk_score INTEGER,
                created_at TEXT
            )
        """)
        conn.commit()

init_db()

@app.route("/")
def dashboard():
    try:
        with sqlite3.connect(DB_FILE) as conn:
            df = pd.read_sql_query(
                "SELECT ip, country, risk_score, created_at FROM indicators ORDER BY created_at DESC",
                conn
            )
        # Convert to dict for charts in dashboard.html
        data = df.to_dict(orient="records")
        return render_template("dashboard.html", data=data)
    except Exception as e:
        return f"Error loading dashboard: {str(e)}", 500

@app.route("/fetch_otx")
def fetch_otx():
    try:
        # Fetch latest pulses (low limit to prevent memory crash)
        pulses = otx.getall(limit=10)
        if not pulses:
            return jsonify({"status": "ok", "message": "No new pulses found"})

        inserted = 0
        with sqlite3.connect(DB_FILE) as conn:
            for pulse in pulses:
                for indicator in pulse.get("indicators", []):
                    ip = indicator.get("indicator")
                    country = indicator.get("country") or "Unknown"
                    risk_score = indicator.get("risk_score") or 0
                    created_at = indicator.get("created") or pulse.get("created") or ""
                    conn.execute(
                        "INSERT INTO indicators (ip, country, risk_score, created_at) VALUES (?, ?, ?, ?)",
                        (ip, country, risk_score, created_at)
                    )
                    inserted += 1
            conn.commit()

        return jsonify({"status": "ok", "message": f"{inserted} rows inserted"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
