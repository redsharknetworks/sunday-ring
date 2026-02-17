import os
import sqlite3
import pandas as pd
import matplotlib.pyplot as plt
from flask import Flask, render_template, send_file, jsonify
from datetime import datetime, timedelta
import requests
from ipwhois import IPWhois
import geopandas as gpd
import folium
from apscheduler.schedulers.background import BackgroundScheduler

app = Flask(__name__)
DB_FILE = "indicators.db"

# ----------------- Helper Functions -----------------

def fetch_otx_data():
    """Fetch latest indicators from AlienVault OTX and store into DB."""
    url = "https://otx.alienvault.com/api/v1/indicators/export"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            store_indicators(data)
    except Exception as e:
        print(f"OTX fetch error: {e}")

def store_indicators(data):
    """Store fetched indicators into SQLite DB."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS indicators (
            indicator TEXT,
            type TEXT,
            risk_score INTEGER,
            mitre TEXT,
            created_at TEXT,
            latitude REAL,
            longitude REAL
        )
    """)
    for item in data:
        # Example: mapping fields from OTX JSON to DB columns
        indicator = item.get('indicator', '')
        i_type = item.get('type', '')
        risk_score = int(item.get('risk', 0))
        mitre = item.get('mitre', '')
        created_at = item.get('created_at', datetime.utcnow().isoformat())
        lat = item.get('latitude', None)
        lon = item.get('longitude', None)
        cursor.execute("""
            INSERT INTO indicators (indicator, type, risk_score, mitre, created_at, latitude, longitude)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (indicator, i_type, risk_score, mitre, created_at, lat, lon))
    conn.commit()
    conn.close()

def generate_trend_chart():
    conn = sqlite3.connect(DB_FILE)
    df = pd.read_sql_query("SELECT created_at, risk_score FROM indicators ORDER BY created_at ASC", conn)
    conn.close()
    if not df.empty:
        df['created_at'] = pd.to_datetime(df['created_at'])
        plt.figure(figsize=(10, 4))
        plt.plot(df['created_at'], df['risk_score'], color='orange', linewidth=2, marker='o')
        plt.title("Threat Trend")
        plt.xlabel("Date")
        plt.ylabel("Risk Score")
        plt.grid(True)
        plt.tight_layout()
        trend_path = os.path.join("static", "trend.png")
        plt.savefig(trend_path)
        plt.close()
        return trend_path
    return None

def generate_heatmap():
    conn = sqlite3.connect(DB_FILE)
    df = pd.read_sql_query("SELECT latitude, longitude, risk_score FROM indicators WHERE latitude IS NOT NULL AND longitude IS NOT NULL", conn)
    conn.close()
    if df.empty:
        return None

    map_center = [df['latitude'].mean(), df['longitude'].mean()]
    fmap = folium.Map(location=map_center, zoom_start=4)
    for _, row in df.iterrows():
        folium.CircleMarker(
            location=[row['latitude'], row['longitude']],
            radius=5,
            color='red' if row['risk_score']>5 else 'orange',
            fill=True
        ).add_to(fmap)

    heatmap_path = os.path.join("templates", "heatmap.html")
    fmap.save(heatmap_path)
    return heatmap_path

# ----------------- Routes -----------------

@app.route("/")
def dashboard():
    trend_image = generate_trend_chart()
    generate_heatmap()

    conn = sqlite3.connect(DB_FILE)
    df = pd.read_sql_query("SELECT indicator, type, risk_score, mitre, created_at FROM indicators ORDER BY created_at DESC LIMIT 50", conn)
    conn.close()
    indicators = df.to_dict(orient="records")
    return render_template("dashboard.html", trend_image=trend_image, indicators=indicators)

@app.route("/report/json")
def json_report():
    conn = sqlite3.connect(DB_FILE)
    df = pd.read_sql_query("SELECT * FROM indicators", conn)
    conn.close()
    return jsonify(df.to_dict(orient="records"))

@app.route("/report/csv")
def csv_report():
    conn = sqlite3.connect(DB_FILE)
    df = pd.read_sql_query("SELECT * FROM indicators", conn)
    conn.close()
    csv_path = os.path.join("static", "report.csv")
    df.to_csv(csv_path, index=False)
    return send_file(csv_path, mimetype="text/csv", as_attachment=True)

@app.route("/report/pdf")
def pdf_report():
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle
    from reportlab.lib import colors
    conn = sqlite3.connect(DB_FILE)
    df = pd.read_sql_query("SELECT indicator, type, risk_score, mitre, created_at FROM indicators ORDER BY created_at DESC LIMIT 50", conn)
    conn.close()
    pdf_path = os.path.join("static", "report.pdf")
    doc = SimpleDocTemplate(pdf_path)
    data = [df.columns.tolist()] + df.values.tolist()
    table = Table(data)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.grey),
        ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
        ('ALIGN',(0,0),(-1,-1),'LEFT'),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('GRID', (0,0), (-1,-1), 0.5, colors.black)
    ]))
    doc.build([table])
    return send_file(pdf_path, mimetype="application/pdf", as_attachment=True)

# ----------------- Scheduler -----------------

scheduler = BackgroundScheduler()
scheduler.add_job(fetch_otx_data, 'interval', hours=1)
scheduler.start()

# ----------------- Run -----------------

if __name__ == "__main__":
    # Initial fetch on start
    fetch_otx_data()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)), debug=True)
