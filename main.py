import os
import sqlite3
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime
from flask import Flask, render_template, send_file
from io import BytesIO
from OTXv2 import OTXv2
import geopandas as gpd
import folium
from folium.plugins import MarkerCluster
from fpdf import FPDF
import json

# ---------------------------
# Configuration
# ---------------------------
DB_PATH = "indicators.db"
BOXING_RING_IMG = "static/boxing_ring.png"
OTX_API_KEY = os.getenv("OTX_API_KEY")  # set in environment
COUNTRY = "MY"

app = Flask(__name__)
otx = OTXv2(OTX_API_KEY)

# ---------------------------
# Helper Functions
# ---------------------------
def fetch_otx_indicators(country="MY"):
    """
    Fetch recent malicious IPs from OTX targeting Malaysia.
    Returns a DataFrame.
    """
    records = []
    pulses = otx.getall()
    for pulse in pulses:
        for indicator in pulse['indicators']:
            if indicator['type'] == 'IPv4':
                records.append({
                    "created_at": pulse['modified'],
                    "source_ip": indicator['indicator'],
                    "source_country": indicator.get('country', 'Other'),
                    "target_city": "Unknown",
                    "target_country": "Malaysia",
                    "risk_score": pulse.get('threat_level', 3)
                })
    return pd.DataFrame(records)

def fetch_local_indicators():
    """Fetch indicators from local SQLite DB."""
    if not os.path.exists(DB_PATH):
        return pd.DataFrame(columns=['created_at', 'source_ip', 'source_country', 'target_city', 'target_country', 'risk_score'])
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query("SELECT * FROM indicators ORDER BY created_at DESC", conn)
    conn.close()
    return df

def generate_trend_chart(df):
    """Generate trend chart of risk_score over time with boxing_ring background."""
    plt.figure(figsize=(10,6))
    if os.path.exists(BOXING_RING_IMG):
        img = plt.imread(BOXING_RING_IMG)
        plt.imshow(img, extent=[0, len(df), df['risk_score'].min(), df['risk_score'].max()], aspect='auto', alpha=0.3)
    plt.plot(range(len(df)), df['risk_score'], marker='o', color='red', linewidth=2)
    plt.title("Threat Risk Trend")
    plt.xlabel("Indicators")
    plt.ylabel("Risk Score")
    plt.tight_layout()
    buf = BytesIO()
    plt.savefig(buf, format='png')
    buf.seek(0)
    plt.close()
    return buf

def generate_geo_map(df):
    """Generate Malaysia-focused map with source to city lines."""
    malaysia_coords = [4.2105, 101.9758]  # center
    m = folium.Map(location=malaysia_coords, zoom_start=5)
    cluster = MarkerCluster().add_to(m)
    for _, row in df.iterrows():
        if row['target_country'] == "Malaysia":
            folium.Marker(
                location=malaysia_coords,
                popup=f"{row['source_ip']} ({row['source_country']}) Risk: {row['risk_score']}"
            ).add_to(cluster)
    return m._repr_html_()

def save_reports(df):
    """Save CSV, JSON, PDF with timestamp."""
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    base_filename = f"dsrkgrid_redshark_{timestamp}"

    # CSV
    df.to_csv(f"static/{base_filename}.csv", index=False)

    # JSON
    df.to_json(f"static/{base_filename}.json", orient='records', indent=2)

    # PDF
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="DarkGrid RedShark Threat Report", ln=True, align="C")
    pdf.cell(200, 10, txt=f"Generated: {datetime.now()}", ln=True, align="C")
    pdf.ln(10)
    for _, row in df.iterrows():
        pdf.multi_cell(0, 8, txt=f"{row['created_at']} | {row['source_ip']} | {row['source_country']} | {row['risk_score']}")
    pdf.output(f"static/{base_filename}.pdf")

    return base_filename

# ---------------------------
# Routes
# ---------------------------
@app.route("/")
def dashboard():
    # Fetch local + OTX
    df_local = fetch_local_indicators()
    df_otx = fetch_otx_indicators(COUNTRY)
    df = pd.concat([df_local, df_otx], ignore_index=True)
    df['created_at'] = pd.to_datetime(df['created_at'])
    df = df.sort_values(by='created_at', ascending=False)

    # Generate chart and map
    trend_buf = generate_trend_chart(df)
    geo_map = generate_geo_map(df)

    # Save reports
    report_base = save_reports(df)

    # Executive summary
    exec_summary = {
        "total_indicators": len(df),
        "average_risk": df['risk_score'].mean(),
        "high_risk_count": len(df[df['risk_score']>=4]),
    }

    return render_template(
        "dashboard.html",
        table_data=df.to_dict(orient='records'),
        trend_chart=trend_buf.getvalue(),
        geo_map=geo_map,
        report_base=report_base,
        exec_summary=exec_summary
    )

# ---------------------------
# Run App
# ---------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=True)
