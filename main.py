import os
import json
from datetime import datetime
from flask import Flask, jsonify
from OTXv2 import OTXv2
import sqlite3
from sqlite3 import Error

# -------------------------------
# Configuration
# -------------------------------
OTX_KEY = os.environ.get("OTX_API_KEY")  # Reuse your existing OTX key
DB_FILE = "threat_intel.db"  # SQLite file in project root

# -------------------------------
# Flask App
# -------------------------------
app = Flask(__name__)

# -------------------------------
# SQLite Utility Functions
# -------------------------------
def get_conn():
    """Connect to SQLite DB"""
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row  # for dict-like row access
        return conn
    except Error as e:
        print(f"SQLite connection error: {e}")
        return None

def create_table():
    """Create table if it doesn't exist"""
    conn = get_conn()
    if conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS threat_intel (
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

# Call table creation at startup
create_table()

# -------------------------------
# OTX Fetch Function
# -------------------------------
def fetch_otx_pulses(limit=50):
    otx = OTXv2(OTX_KEY)
    try:
        pulses = otx.getall(limit=limit)
    except Exception as e:
        print(f"Error fetching OTX: {e}")
        return []

    # Store in SQLite
    conn = get_conn()
    if not conn:
        return []

    cursor = conn.cursor()
    for pulse in pulses:
        # Some pulses might not have all fields
        for indicator in pulse.get("indicators", []):
            cursor.execute("""
                INSERT INTO threat_intel (type, indicator, country, risk_score, created_at)
                VALUES (?, ?, ?, ?, ?)
            """, (
                indicator.get("type", "unknown"),
                indicator.get("indicator", "unknown"),
                indicator.get("country", ""),
                indicator.get("risk_score", 0),
                indicator.get("created_at", datetime.utcnow().isoformat())
            ))
    conn.commit()
    conn.close()
    return pulses

# -------------------------------
# Flask Routes
# -------------------------------
@app.route("/fetch_otx")
def fetch_otx():
    pulses = fetch_otx_pulses()
    return jsonify({"status": "success", "count": len(pulses)})

@app.route("/dashboard")
def dashboard():
    """Return JSON of all threat intel"""
    conn = get_conn()
    if not conn:
        return jsonify({"error": "DB connection failed"}), 500

    cursor = conn.cursor()
    cursor.execute("""
        SELECT type, indicator, country, risk_score, created_at
        FROM threat_intel
        ORDER BY created_at DESC
    """)
    rows = cursor.fetchall()
    conn.close()

    # Convert sqlite3.Row to dict
    result = [dict(row) for row in rows]
    return jsonify(result)

# -------------------------------
# Main Entry
# -------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
