import os
import json
import pandas as pd
from flask import Flask, render_template, jsonify
from sqlalchemy import create_engine, text
from OTXv2 import OTXv2

app = Flask(__name__)

# PostgreSQL connection string from environment variable
DB_URL = os.environ.get("DATABASE_URL") or "postgresql://threat_intel_user:jf0cGhfYYeCmTc9fpakD9xMpIz0Joma1@dpg-d6afq1rnv86c739lsmr0-a:5432/threat_intel"
engine = create_engine(DB_URL)

# OTX API key from env
OTX_API_KEY = os.environ.get("OTX_API_KEY")
otx = OTXv2(OTX_API_KEY)

# Create table if not exists
with engine.connect() as conn:
    conn.execute(text("""
    CREATE TABLE IF NOT EXISTS indicators (
        id SERIAL PRIMARY KEY,
        type VARCHAR(50),
        indicator VARCHAR(255),
        country VARCHAR(100),
        risk_score FLOAT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """))
    conn.commit()


@app.route("/")
def dashboard():
    try:
        with engine.connect() as conn:
            df = pd.read_sql_query(
                "SELECT type, indicator, country, risk_score, created_at FROM indicators ORDER BY created_at DESC",
                conn
            )
        data = df.to_dict(orient="records")
        return render_template("dashboard.html", data=data)
    except Exception as e:
        print("Dashboard read failed:", e)
        return "Dashboard read failed", 500


@app.route("/fetch_otx")
def fetch_otx():
    try:
        pulses = otx.getall(limit=50)  # fetch latest pulses
        rows_inserted = 0

        with engine.begin() as conn:
            for pulse in pulses:
                for ioc in pulse.get("indicators", []):
                    if ioc.get("type") not in ["IPv4", "domain", "hash"]:
                        continue

                    conn.execute(
                        text("""
                        INSERT INTO indicators (type, indicator, country, risk_score)
                        VALUES (:type, :indicator, :country, :risk_score)
                        ON CONFLICT DO NOTHING
                        """),
                        {
                            "type": ioc.get("type"),
                            "indicator": ioc.get("indicator"),
                            "country": ioc.get("country", "Unknown"),
                            "risk_score": float(ioc.get("risk_score", 0))
                        }
                    )
                    rows_inserted += 1

        return jsonify({"message": f"{rows_inserted} rows inserted"}), 200
    except Exception as e:
        print("Fetch OTX failed:", e)
        return jsonify({"status": "error", "message": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
