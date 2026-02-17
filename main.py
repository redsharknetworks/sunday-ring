import os
import sqlite3
import json
from datetime import datetime, timezone, timedelta
from flask import Flask, render_template, send_file
import pandas as pd
import requests
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import base64
from io import BytesIO
import folium
from reportlab.pdfgen import canvas
from OTXv2 import OTXv2

app = Flask(__name__)

# =========================
# DATABASE INIT
# =========================
conn = sqlite3.connect("threats.db", check_same_thread=False)
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS indicators (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    indicator TEXT,
    type TEXT,
    country TEXT,
    city TEXT,
    risk_score INTEGER,
    mitre TEXT,
    created_at TEXT
)
""")
conn.commit()

# =========================
# OTX INIT
# =========================
OTX_API_KEY = os.getenv("OTX_API_KEY", "")
otx = OTXv2(OTX_API_KEY) if OTX_API_KEY else None

def fetch_otx():
    if not otx:
        return
    try:
        pulses = otx.getall()
        for pulse in pulses.get("results", [])[:5]:
            for ind in pulse.get("indicators", [])[:5]:
                value = ind.get("indicator")
                if not value:
                    continue

                now = datetime.utcnow().isoformat()
                cursor.execute("""
                INSERT INTO indicators
                (indicator, type, country, city, risk_score, mitre, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    value,
                    ind.get("type", "IP"),
                    "Malaysia",
                    "Kuala Lumpur",
                    50,
                    "T1059",
                    now
                ))
        conn.commit()
    except Exception as e:
        print("OTX fetch error:", e)

# =========================
# TREND CHART
# =========================
def generate_trend_chart():
    try:
        df = pd.read_sql_query(
            "SELECT created_at, risk_score FROM indicators ORDER BY created_at ASC",
            conn
        )
        if df.empty:
            return ""

        plt.figure(figsize=(6, 3))
        plt.plot(df["risk_score"], color="orange", linewidth=3)
        plt.title("Risk Trend")
        plt.tight_layout()

        img = BytesIO()
        plt.savefig(img, format="png")
        img.seek(0)
        return base64.b64encode(img.getvalue()).decode()
    except:
        return ""

# =========================
# HEAT MAP
# =========================
def generate_heatmap():
    m = folium.Map(location=[4.21, 101.97], zoom_start=6)
    folium.CircleMarker([3.14, 101.69], radius=20, color="red").add_to(m)
    file_name = "templates/heatmap.html"
    m.save(file_name)
    return "heatmap.html"

# =========================
# EXPORT REPORTS
# =========================
def export_reports():
    df = pd.read_sql_query("SELECT * FROM indicators", conn)
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M")

    csv_name = f"darkgrid_redshark_{ts}.csv"
    json_name = f"darkgrid_redshark_{ts}.json"
    pdf_name = f"darkgrid_redshark_{ts}.pdf"

    df.to_csv(csv_name, index=False)
    df.to_json(json_name, orient="records")

    c = canvas.Canvas(pdf_name)
    c.drawString(100, 800, "RedShark Threat Report")
    c.drawString(100, 780, f"Records: {len(df)}")
    c.save()

    return {
        "csv": csv_name,
        "json": json_name,
        "pdf": pdf_name
    }

# =========================
# DASHBOARD ROUTE
# =========================
@app.route("/")
def dashboard():
    fetch_otx()

    trend_image = generate_trend_chart()
    heatmap_file = generate_heatmap()
    exports = export_reports()

    df = pd.read_sql_query(
        "SELECT * FROM indicators ORDER BY created_at DESC LIMIT 200",
        conn
    )
    table_html = df.to_html(classes="table table-striped", index=False)

    malaysia_time = (
        datetime.utcnow().replace(tzinfo=timezone.utc)
        + timedelta(hours=8)
    ).strftime("%Y-%m-%d %H:%M:%S")

    return render_template(
        "dashboard.html",
        trend_image=trend_image,
        heatmap_file=heatmap_file,
        table_html=table_html,
        export_files=exports,
        malaysia_time=malaysia_time
    )

# =========================
# DOWNLOAD ROUTE
# =========================
@app.route("/download/<path:filename>")
def download(filename):
    return send_file(filename, as_attachment=True)

# =========================
# RUN
# =========================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
