# main.py

from flask import Flask, render_template, send_file, jsonify
import sqlite3
import pandas as pd
import matplotlib.pyplot as plt
from io import BytesIO
from datetime import datetime, timedelta
from ipwhois import IPWhois
import requests

app = Flask(__name__)

DB_FILE = "indicators.db"

# ----------------------------
# 1️⃣ Database Initialization
# ----------------------------
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS indicators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator TEXT NOT NULL,
            type TEXT,
            risk_score INTEGER,
            mitre TEXT,
            created_at TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

init_db()  # Ensure DB/table exists on startup

# ----------------------------
# 2️⃣ Fetch Data Placeholder
# ----------------------------
def fetch_otx_data():
    # Example: insert sample data (replace with real OTX fetch logic)
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    now = datetime.utcnow().isoformat()
    cursor.execute("""
        INSERT INTO indicators (indicator, type, risk_score, mitre, created_at)
        VALUES (?, ?, ?, ?, ?)
    """, ("8.8.8.8", "ip", 5, "T1071", now))
    conn.commit()
    conn.close()

# ----------------------------
# 3️⃣ Trend Chart Generation
# ----------------------------
def generate_trend_chart():
    conn = sqlite3.connect(DB_FILE)
    df = pd.read_sql_query("SELECT created_at, risk_score FROM indicators ORDER BY created_at ASC", conn)
    conn.close()

    plt.figure(figsize=(8,4))
    if not df.empty:
        df['created_at'] = pd.to_datetime(df['created_at'])
        plt.plot(df['created_at'], df['risk_score'], color='orange', linewidth=2, marker='o')
        plt.title("Risk Score Trend")
        plt.xlabel("Date")
        plt.ylabel("Risk Score")
        plt.grid(True)
    else:
        plt.text(0.5, 0.5, "No data available", ha='center', va='center', fontsize=12)
        plt.axis('off')

    img = BytesIO()
    plt.tight_layout()
    plt.savefig(img, format='png')
    img.seek(0)
    plt.close()
    return img

# ----------------------------
# 4️⃣ Flask Routes
# ----------------------------
@app.route("/")
def dashboard():
    # Optional: fetch new data here
    fetch_otx_data()  # For demo
    trend_image = generate_trend_chart()
    return render_template("dashboard.html", trend_chart=trend_image)

@app.route("/trend.png")
def trend_png():
    img = generate_trend_chart()
    return send_file(img, mimetype='image/png')

@app.route("/report/json")
def report_json():
    conn = sqlite3.connect(DB_FILE)
    df = pd.read_sql_query("SELECT * FROM indicators ORDER BY created_at DESC", conn)
    conn.close()
    return df.to_json(orient='records')

@app.route("/report/csv")
def report_csv():
    conn = sqlite3.connect(DB_FILE)
    df = pd.read_sql_query("SELECT * FROM indicators ORDER BY created_at DESC", conn)
    conn.close()
    csv_data = df.to_csv(index=False)
    return csv_data, 200, {'Content-Type':'text/csv'}

# ----------------------------
# 5️⃣ Run App
# ----------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000, debug=True)
