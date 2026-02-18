import os
import json
import pandas as pd
import matplotlib.pyplot as plt
from flask import Flask, jsonify, render_template
from datetime import datetime
from OTXv2 import OTXv2
import psycopg2
from psycopg2.extras import RealDictCursor

# ----------------------------
# Config
# ----------------------------
DATABASE_URL = os.getenv("DATABASE_URL")
OTX_API_KEY = os.getenv("OTX_API_KEY")
SEED_FILE = "otx_seed.json"  # optional seed JSON in repo

app = Flask(__name__)

# ----------------------------
# Database setup
# ----------------------------
def get_conn():
    return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)

def init_db():
    with get_conn() as conn:
        with conn.cursor() as cur:
            # Create database table if it does not exist
            cur.execute("""
                CREATE TABLE IF NOT EXISTS threat_intel (
                    id SERIAL PRIMARY KEY,
                    type TEXT,
                    indicator TEXT UNIQUE,
                    country TEXT,
                    risk_score REAL,
                    created_at TIMESTAMP
                )
            """)
        conn.commit()

# Initialize DB and table
init_db()

# ----------------------------
# OTX fetch
# ----------------------------
otx = OTXv2(OTX_API_KEY)

def fetch_otx(limit=50):
    pulses = []
    try:
        pulses = otx.getall(limit=limit)
    except Exception as e:
        print("OTX fetch failed:", e)
        if os.path.exists(SEED_FILE):
            with open(SEED_FILE, "r") as f:
                pulses = json.load(f)
    
    inserted = 0
    with get_conn() as conn:
        with conn.cursor() as cur:
            for pulse in pulses:
                for ioc in pulse.get("indicators", []):
                    try:
                        cur.execute("""
                            INSERT INTO threat_intel (type, indicator, country, risk_score, created_at)
                            VALUES (%s, %s, %s, %s, %s)
                            ON CONFLICT (indicator) DO NOTHING
                        """, (
                            ioc.get("type"),
                            ioc.get("indicator"),
                            ioc.get("country", None),
                            ioc.get("risk_score", None),
                            datetime.utcnow()
                        ))
                        inserted += cur.rowcount
                    except Exception as e:
                        print("Insert error:", e)
        conn.commit()
    return {"inserted": inserted, "total": len(pulses)}

# ----------------------------
# Dashboard
# ----------------------------
@app.route("/")
def dashboard():
    try:
        with get_conn() as conn:
            df = pd.read_sql("SELECT type, indicator, country, risk_score, created_at FROM threat_intel ORDER BY created_at DESC", conn)
        
        chart_path = None
        if not df.empty:
            chart_path = "static/top10.png"
            top10 = df.sort_values("risk_score", ascending=False).head(10)
            plt.figure(figsize=(10,6))
            plt.barh(top10["indicator"], top10["risk_score"], color="red")
            plt.xlabel("Risk Score")
            plt.title("Top 10 Threat Indicators")
            plt.tight_layout()
            plt.savefig(chart_path)
            plt.close()

        return render_template("dashboard.html", table=df.to_dict(orient="records"), chart=chart_path)
    except Exception as e:
        print("Dashboard read failed:", e)
        return "Dashboard read failed: " + str(e), 500

# ----------------------------
# Fetch OTX route
# ----------------------------
@app.route("/fetch_otx")
def fetch_route():
    result = fetch_otx()
    return jsonify(result)

# ----------------------------
# Run
# ----------------------------
if __name__ == "__main__":
    port = int(os.getenv("PORT", 33212))
    app.run(host="0.0.0.0", port=port)
