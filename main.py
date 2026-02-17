import os
import sqlite3
from datetime import datetime, timedelta
from flask import Flask, render_template, jsonify, send_file
import requests
import pandas as pd
import matplotlib.pyplot as plt
import geopandas as gpd
import folium
from ipwhois import IPWhois

app = Flask(__name__)

DB_FILE = "threats.db"
OTX_API_KEY = os.getenv("OTX_API_KEY")  # set your OTX API key in environment

# ----------------------
# DATABASE INIT
# ----------------------
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS indicators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator TEXT,
            type TEXT,
            risk_score INTEGER,
            mitre TEXT,
            created_at TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# ----------------------
# OTX FETCH
# ----------------------
def fetch_otx_indicators():
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    types = ["IPv4", "domain", "file_hash"]
    conn = sqlite3.connect(DB_FILE)
    for t in types:
        url = f"https://otx.alienvault.com/api/v1/indicators/{t}/reputation"
        params = {"limit": 50}  # adjust as needed
        try:
            resp = requests.get(url, headers=headers, params=params, timeout=10)
            resp.raise_for_status()
            data = resp.json().get("results", [])
            for item in data:
                indicator = item.get("indicator")
                risk = item.get("reputation", 0)
                mitre = ",".join(item.get("mitre", []))
                created_at = datetime.utcnow().isoformat()
                # Insert into DB if not exist
                conn.execute(
                    "INSERT OR IGNORE INTO indicators (indicator, type, risk_score, mitre, created_at) VALUES (?,?,?,?,?)",
                    (indicator, t, risk, mitre, created_at)
                )
            conn.commit()
        except Exception as e:
            print(f"OTX fetch error for {t}: {e}")
    conn.close()

# ----------------------
# ROUTES
# ----------------------
@app.route("/")
def dashboard():
    # Fetch latest OTX data first
    fetch_otx_indicators()

    conn = sqlite3.connect(DB_FILE)
    df = pd.read_sql_query("SELECT * FROM indicators ORDER BY created_at DESC LIMIT 1000", conn)
    conn.close()

    # Trend chart
    trend = df.groupby([pd.to_datetime(df["created_at"]).dt.date, "type"])["indicator"].count().unstack(fill_value=0)
    plt.figure(figsize=(8,4))
    for col in trend.columns:
        plt.plot(trend.index, trend[col], label=col, color='orange', linewidth=2)  # orange bold line
    plt.legend()
    plt.title("Indicators Trend")
    plt.tight_layout()
    plt.savefig("static/trend.png")
    plt.close()

    # Heat map
    geo_map = folium.Map(location=[3.139, 101.6869], zoom_start=6)  # Malaysia center
    for ip in df[df["type"]=="IPv4"]["indicator"]:
        try:
            obj = IPWhois(ip)
            res = obj.lookup_rdap(asn_methods=["whois"])
            lat = res.get("network", {}).get("latitude")
            lon = res.get("network", {}).get("longitude")
            if lat and lon:
                folium.CircleMarker(location=[lat, lon], radius=5, color='red').add_to(geo_map)
        except:
            continue
    geo_map.save("templates/heatmap.html")

    return render_template("dashboard.html", trend_image="static/trend.png")

@app.route("/report/json")
def report_json():
    conn = sqlite3.connect(DB_FILE)
    df = pd.read_sql_query("SELECT * FROM indicators ORDER BY created_at DESC", conn)
    conn.close()
    return jsonify(df.to_dict(orient="records"))

@app.route("/report/csv")
def report_csv():
    conn = sqlite3.connect(DB_FILE)
    df = pd.read_sql_query("SELECT * FROM indicators ORDER BY created_at DESC", conn)
    conn.close()
    csv_file = "report.csv"
    df.to_csv(csv_file, index=False)
    return send_file(csv_file, as_attachment=True)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 10000)))
