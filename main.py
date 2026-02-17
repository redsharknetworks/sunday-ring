import os
import sqlite3
from datetime import datetime, timezone, timedelta
import io
import base64
import requests
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.offsetbox import OffsetImage, AnnotationBbox
from flask import Flask, render_template, send_file
from ipwhois import IPWhois
from OTXv2 import OTXv2
import folium
from folium.plugins import HeatMap
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import json

# Flask app
app = Flask(__name__)

# Database
DB_FILE = "indicators.db"
conn = sqlite3.connect(DB_FILE, check_same_thread=False)

# OTX API key
OTX_API_KEY = os.getenv("OTX_API_KEY")
otx = OTXv2(OTX_API_KEY)

# Malaysia cities coordinates (sample)
MALAYSIA_CITIES = {
    "Kuala Lumpur": [3.1390, 101.6869],
    "Penang": [5.4164, 100.3327],
    "Johor Bahru": [1.4927, 103.7414],
    "Kota Kinabalu": [5.9804, 116.0735],
    "Kuching": [1.5533, 110.3593],
}

def fetch_otx_malaysia():
    """Fetch latest OTX indicators targeting Malaysia"""
    try:
        pulses = otx.getall(indicator_type="IPv4", limit=50)
        for pulse in pulses:
            for indicator in pulse.get("indicators", []):
                ip = indicator.get("indicator")
                source = indicator.get("source", "OTX")
                risk = indicator.get("risk", 5)
                created_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
                conn.execute(
                    "INSERT OR IGNORE INTO indicators (ip, source, risk_score, created_at) VALUES (?, ?, ?, ?)",
                    (ip, source, risk, created_at),
                )
        conn.commit()
    except Exception as e:
        print("OTX fetch error:", e)

def generate_trend_chart():
    """Generate trend chart with boxing_ring.png background"""
    df = pd.read_sql_query("SELECT created_at, risk_score FROM indicators ORDER BY created_at ASC", conn)
    plt.figure(figsize=(10,5))
    img = plt.imread("boxing_ring.png")
    plt.imshow(img, extent=[0, len(df), 0, df['risk_score'].max()], aspect='auto', alpha=0.2)
    plt.plot(df['risk_score'], color='red', marker='o')
    plt.xticks(range(len(df)), df['created_at'], rotation=45)
    plt.ylabel("Risk Score")
    plt.tight_layout()
    buf = io.BytesIO()
    plt.savefig(buf, format="png")
    plt.close()
    buf.seek(0)
    return base64.b64encode(buf.read()).decode("utf-8")

def generate_malaysia_heatmap():
    """Generate Malaysia heatmap for attack locations"""
    df = pd.read_sql_query("SELECT ip FROM indicators", conn)
    coords = []
    for ip in df['ip']:
        try:
            obj = IPWhois(ip).lookup_rdap()
            country = obj.get("network", {}).get("country", "")
            if country.upper() == "MY":
                lat, lon = MALAYSIA_CITIES.get("Kuala Lumpur", [3.1390, 101.6869])
                coords.append([lat, lon])
        except:
            continue
    m = folium.Map(location=[4.2105, 101.9758], zoom_start=6)
    HeatMap(coords).add_to(m)
    heatmap_file = "static/malaysia_heatmap.html"
    m.save(heatmap_file)
    return heatmap_file

def export_reports():
    """Export CSV, JSON, PDF with Malaysia timestamp"""
    df = pd.read_sql_query("SELECT * FROM indicators", conn)
    malaysia_time = datetime.utcnow().replace(tzinfo=timezone.utc) + timedelta(hours=8)
    timestamp = malaysia_time.strftime("%Y%m%d_%H%M%S")
    csv_file = f"dsrkgrid_redshark_{timestamp}.csv"
    json_file = f"dsrkgrid_redshark_{timestamp}.json"
    pdf_file = f"dsrkgrid_redshark_{timestamp}.pdf"
    df.to_csv(csv_file, index=False)
    df.to_json(json_file, orient="records")
    
    # PDF
    c = canvas.Canvas(pdf_file, pagesize=letter)
    c.drawString(100, 750, f"RedShark Threat Indicators - Malaysia {malaysia_time}")
    for i, row in df.iterrows():
        c.drawString(50, 700 - i*15, f"{row['created_at']} | {row['ip']} | {row['risk_score']}")
        if i >= 40:
            break  # Limit rows per page
    c.save()
    return {"csv": csv_file, "json": json_file, "pdf": pdf_file}

@app.route("/")
def dashboard():
    fetch_otx_malaysia()
    trend_image = generate_trend_chart()
    heatmap_file = generate_malaysia_heatmap()
    df_table = pd.read_sql_query("SELECT * FROM indicators ORDER BY created_at DESC LIMIT 100", conn)
    table_html = df_table.to_html(classes="table table-striped table-bordered", index=False)
    
    malaysia_time = datetime.utcnow().replace(tzinfo=timezone.utc) + timedelta(hours=8)
    malaysia_time_str = malaysia_time.strftime("%Y-%m-%d %H:%M:%S %Z+8")
    
    export_files = export_reports()
    
    return render_template("dashboard.html", trend_image=trend_image,
                           heatmap_file=heatmap_file,
                           table_html=table_html,
                           export_files=export_files,
                           malaysia_time=malaysia_time_str)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
