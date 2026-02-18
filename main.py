import os
import json
import threading
import pandas as pd
import psycopg2
from flask import Flask, jsonify, render_template
from OTXv2 import OTXv2

# -----------------------------
# Configuration
# -----------------------------
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user:pass@host:5432/threat_intel")
OTX_API_KEY = os.getenv("OTX_API_KEY")
OTX_SEED_FILE = os.path.join(os.path.dirname(__file__), "otx_seed.json")
OTX_FETCH_LIMIT = 20  # small batches for memory safety

# -----------------------------
# Initialize Flask
# -----------------------------
app = Flask(__name__)

# -----------------------------
# DB connection
# -----------------------------
def get_db_connection():
    conn = psycopg2.connect(DATABASE_URL)
    return conn

# -----------------------------
# Load seed file
# -----------------------------
def load_seed():
    if os.path.exists(OTX_SEED_FILE):
        with open(OTX_SEED_FILE, "r") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return []
    return []

# -----------------------------
# Fetch OTX pulses (background)
# -----------------------------
def fetch_otx_background():
    if not OTX_API_KEY:
        print("OTX API key not set, skipping live fetch.")
        return

    otx = OTXv2(OTX_API_KEY)
    try:
        pulses = otx.getall(limit=OTX_FETCH_LIMIT)
        conn = get_db_connection()
        cur = conn.cursor()
        for pulse in pulses:
            for indicator in pulse.get("indicators", []):
                cur.execute("""
                    INSERT INTO threat_intel (type, indicator, country, risk_score, created_at)
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT DO NOTHING
                """, (
                    indicator.get("type"),
                    indicator.get("indicator"),
                    indicator.get("country", None),
                    indicator.get("risk_score", None),
                    indicator.get("created_at", None)
                ))
        conn.commit()
        cur.close()
        conn.close()
        print(f"Fetched {len(pulses)} OTX pulses.")
    except Exception as e:
        print(f"Error fetching OTX: {e}")

# -----------------------------
# Routes
# -----------------------------
@app.route("/")
def dashboard():
    conn = get_db_connection()
    try:
        df = pd.read_sql_query(
            "SELECT type, indicator, country, risk_score, created_at "
            "FROM threat_intel ORDER BY created_at DESC LIMIT 100",
            conn
        )
        data = df.to_dict(orient="records")
    except Exception as e:
        print(f"Dashboard read failed: {e}")
        data = load_seed()  # fallback to seed
    finally:
        conn.close()
    return jsonify(data)

@app.route("/fetch_otx")
def fetch_otx():
    thread = threading.Thread(target=fetch_otx_background)
    thread.start()
    return jsonify({"status": "OTX fetch started in background"})


# -----------------------------
# Start background fetch on first request
# -----------------------------
@app.before_request
def start_background_fetch():
    if not hasattr(app, "otx_thread_started"):
        app.otx_thread_started = True
        threading.Thread(target=fetch_otx_background).start()

# -----------------------------
# Run
# -----------------------------
if __name__ == "__main__":
    port = int(os.getenv("PORT", 33212))
    app.run(host="0.0.0.0", port=port)
