import os
import io
import json
import time
import threading
import logging
from datetime import datetime

import sqlite3
import requests
from flask import Flask, jsonify, send_file

app = Flask(__name__)
DB_FILE = "redshark.db"

OTX_KEY = os.environ.get("OTX_KEY", "aa94a69a780ed789016bb72d51d9b58b823eb1e6173f6fffc34530693dacb03b")
ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_KEY", "08cf00dc25d22cbd0f45ec5ebb87cb61e93c22349a6eb14544a100")

logging.basicConfig(level=logging.INFO)

# ---------------- DB ---------------- #
def get_db():
    return sqlite3.connect(DB_FILE, check_same_thread=False, timeout=10)

def init_db():
    with get_db() as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS indicators(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator TEXT UNIQUE,
            source TEXT,
            severity TEXT,
            last_seen TEXT
        )
        """)
init_db()

# ---------------- FETCH ---------------- #
def fetch_data():
    data = []

    # OTX
    try:
        r = requests.get(
            "https://otx.alienvault.com/api/v1/pulses/subscribed",
            headers={"X-OTX-API-KEY": OTX_KEY},
            timeout=10
        )
        if r.status_code == 200:
            j = r.json()
            for p in j.get("results", []):
                for i in p.get("indicators", []):
                    data.append((i["indicator"], "OTX", "High"))
    except Exception as e:
        logging.error(f"OTX error: {e}")

    # AbuseIPDB
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/blacklist?limit=50",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            timeout=10
        )
        if r.status_code == 200:
            j = r.json()
            for i in j.get("data", []):
                data.append((i["ipAddress"], "AbuseIPDB", "Critical"))
    except Exception as e:
        logging.error(f"Abuse error: {e}")

    return data

# ---------------- ENGINE ---------------- #
def engine():
    while True:
        try:
            rows = fetch_data()
            with get_db() as conn:
                for ind, src, sev in rows:
                    conn.execute("""
                    INSERT OR IGNORE INTO indicators
                    (indicator, source, severity, last_seen)
                    VALUES (?,?,?,?)
                    """, (ind, src, sev, datetime.utcnow().isoformat()))
            logging.info(f"Saved {len(rows)}")
        except Exception as e:
            logging.error(f"Engine crash: {e}")

        time.sleep(600)

def start_engine():
    if not hasattr(start_engine, "started"):
        threading.Thread(target=engine, daemon=True).start()
        start_engine.started = True

# Render-safe
if os.environ.get("RENDER") and os.environ.get("RENDER_INSTANCE_ID"):
    start_engine()

# ---------------- ROUTES ---------------- #
@app.route("/")
def home():
    return "✅ RedShark running on Render"

@app.route("/api")
def api():
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM indicators ORDER BY id DESC LIMIT 100").fetchall()
    return jsonify([list(r) for r in rows])

# ---------------- RUN ---------------- #
if __name__ == "__main__":
    start_engine()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)