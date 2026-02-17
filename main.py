import os
import sqlite3
import pandas as pd
from flask import Flask, render_template, jsonify
from datetime import datetime, timedelta
from matplotlib import pyplot as plt
from matplotlib.dates import DateFormatter
from OTXv2 import OTXv2
import pdfkit
import json
import csv
import folium

# ===== CONFIG =====
DB_FILE = "indicators.db"
OTX_API_KEY = os.environ.get("OTX_API_KEY")
COUNTRY_FILTER = "MY"  # Malaysia
ROWS_PER_PAGE = 20

app = Flask(__name__)

# ===== DATABASE =====
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS indicators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT UNIQUE,
            country TEXT,
            risk_score INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

def insert_indicator(ip, country, risk_score):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    try:
        c.execute('''
            INSERT OR IGNORE INTO indicators (ip, country, risk_score) 
            VALUES (?, ?, ?)
        ''', (ip, country, risk_score))
        conn.commit()
    except Exception as e:
        print("DB insert error:", e)
    finally:
        conn.close()

# ===== OTX FETCH =====
@app.route("/fetch_otx")
def fetch_otx():
    try:
        otx = OTXv2(OTX_API_KEY)
        pulses = otx.getall(limit=50)  # fetch recent pulses
        inserted = 0

        for pulse in pulses:
            indicators = pulse.get("indicators", [])
            for ind in indicators:
                ip = ind.get("indicator")
                if not ip or len(ip.split(".")) != 4:
                    continue  # only IPv4

                geo = ind.get("geo", {})
                country = geo.get("country")
                if country != COUNTRY_FILTER:
                    continue  # only Malaysia

                risk_score = pulse.get("threat_score", 50)
                insert_indicator(ip, country, risk_score)
                inserted += 1

        return jsonify({"status": "ok", "inserted": inserted})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

# ===== TREND CHART =====
def generate_trend_chart():
    conn = sqlite3.connect(DB_FILE)
    df = pd.read_sql_query(
        "SELECT created_at, risk_score FROM indicators ORDER BY created_at ASC", conn
    )
    conn.close()

    if df.empty:
        return None

    plt.figure(figsize=(10,5))
    plt.plot(pd.to_datetime(df['created_at']), df['risk_score'], marker='o')
    plt.title("Risk Score Trend")
    plt.xlabel("Time")
    plt.ylabel("Risk Score")
    plt.grid(True)
    plt.tight_layout()

    img_path = "static/trend_chart.png"
    plt.savefig(img_path)
    plt.close()
    return img_path

# ===== DASHBOARD =====
@app.route("/")
def dashboard():
    conn = sqlite3.connect(DB_FILE)
    df = pd.read_sql_query(
        "SELECT ip, country, risk_score, created_at FROM indicators ORDER BY created_at DESC", conn
    )
    conn.close()

    trend_image = generate_trend_chart()

    malaysia_time = (datetime.utcnow() + timedelta(hours=8)).strftime("%Y-%m-%d %H:%M:%S")
    return render_template("dashboard.html", indicators=df.to_dict(orient="records"),
                           trend_image=trend_image,
                           timestamp=malaysia_time)

# ===== EXPORT REPORTS =====
@app.route("/export_reports")
def export_reports():
    conn = sqlite3.connect(DB_FILE)
    df = pd.read_sql_query(
        "SELECT ip, country, risk_score, created_at FROM indicators ORDER BY created_at DESC", conn
    )
    conn.close()

    ts = (datetime.utcnow() + timedelta(hours=8)).strftime("%Y%m%d%H%M%S")
    base_filename = f"dsrkgrid_redshark_{ts}"

    # CSV
    csv_file = f"{base_filename}.csv"
    df.to_csv(csv_file, index=False)

    # JSON
    json_file = f"{base_filename}.json"
    df.to_json(json_file, orient="records", indent=2)

    # PDF
    pdf_file = f"{base_filename}.pdf"
    html_content = render_template("dashboard.html", indicators=df.to_dict(orient="records"),
                                   trend_image=None, timestamp=ts)
    pdfkit.from_string(html_content, pdf_file)

    return jsonify({"status": "ok", "csv": csv_file, "json": json_file, "pdf": pdf_file})

# ===== HEAT MAP =====
@app.route("/malaysia_heatmap")
def malaysia_heatmap():
    conn = sqlite3.connect(DB_FILE)
    df = pd.read_sql_query("SELECT ip, country FROM indicators WHERE country='MY'", conn)
    conn.close()

    m = folium.Map(location=[4.2105, 101.9758], zoom_start=6)  # Center Malaysia
    for _, row in df.iterrows():
        folium.CircleMarker(
            location=[4.2105, 101.9758],  # Placeholder, real geo can be added
            radius=5,
            color="red",
            fill=True
        ).add_to(m)

    heatmap_file = "static/malaysia_heatmap.html"
    m.save(heatmap_file)
    return render_template("malaysia_heatmap.html", map_file=heatmap_file)

# ===== MAIN =====
if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
