import os
import io
import csv
import json
import time
import threading
import sqlite3
from datetime import datetime
from zipfile import ZipFile

import requests
from flask import Flask, render_template_string, send_file

app = Flask(__name__)

# ==============================
# Configuration
# ==============================
DB_DIR = "data"
DB_PATH = os.path.join(DB_DIR, "database.db")
OTX_URL = "https://otx.alienvault.com/api/v1/indicators"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
ABUSEIPDB_KEY = "08cf00dc25d22cbd0f45ec5ebb87cb61e289533bd33bceb9b93c22349a6eb8674d52aaf14544a100"
REFRESH_INTERVAL = 3600  # seconds

# ==============================
# Ensure DB folder exists
# ==============================
if not os.path.exists(DB_DIR):
    os.makedirs(DB_DIR)

# ==============================
# Database helper functions
# ==============================
def init_db():
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ip_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                source TEXT,
                severity TEXT,
                description TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[DB] Error initializing database: {e}")

def insert_event(ip, source, severity, description):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO ip_events (ip, source, severity, description)
            VALUES (?, ?, ?, ?)
        """, (ip, source, severity, description))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[DB] Error inserting event: {e}")

def fetch_recent_events(limit=100):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT ip, source, severity, description, timestamp
            FROM ip_events
            ORDER BY timestamp DESC
            LIMIT ?
        """, (limit,))
        rows = cursor.fetchall()
        conn.close()
        return rows
    except Exception as e:
        print(f"[DB] Error fetching events: {e}")
        return []

init_db()

# ==============================
# API Fetching
# ==============================
def fetch_otx_data(indicator_type="IPv4", limit=50):
    try:
        url = f"{OTX_URL}/{indicator_type}/recent"
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json().get("results", [])
        for item in data[:limit]:
            ip = item.get("indicator")
            desc = item.get("description", "")
            severity = item.get("threat_level", "Medium")
            insert_event(ip, "OTX", severity, desc)
    except Exception as e:
        print(f"[OTX] Error fetching data: {e}")

def fetch_abuseipdb_data(ip_list):
    headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
    for ip in ip_list:
        try:
            response = requests.get(ABUSEIPDB_URL, headers=headers, params={"ipAddress": ip, "maxAgeInDays": 90}, timeout=10)
            response.raise_for_status()
            data = response.json().get("data", {})
            score = data.get("abuseConfidenceScore", 0)
            if score > 50:
                insert_event(ip, "AbuseIPDB", "High", f"Abuse confidence score: {score}")
        except Exception as e:
            print(f"[AbuseIPDB] Error fetching {ip}: {e}")

# ==============================
# Background Refresh Thread
# ==============================
def refresh_data_loop():
    while True:
        try:
            print("[INFO] Refreshing data from OTX and AbuseIPDB...")
            fetch_otx_data()
            recent_ips = [row[0] for row in fetch_recent_events(limit=50)]
            fetch_abuseipdb_data(recent_ips)
            print("[INFO] Data refresh complete. Sleeping...")
        except Exception as e:
            print(f"[Refresh Thread] Unexpected error: {e}")
        time.sleep(REFRESH_INTERVAL)

threading.Thread(target=refresh_data_loop, daemon=True).start()

# ==============================
# Flask Routes
# ==============================
@app.route("/")
def index():
    try:
        events = fetch_recent_events(limit=50) or []
        return render_template_string("""
        <html>
        <head>
            <title>CTI HIGHLIGHT AT {{timestamp}}</title>
            <style>
                body { font-family: Arial, sans-serif; background: #121212; color: #EEE; }
                table { width: 100%; border-collapse: collapse; margin-top: 20px; }
                th, td { border: 1px solid #444; padding: 8px; text-align: left; }
                th { background-color: #222; }
                tr.critical { background-color: #8B0000; animation: blink 1s infinite; }
                @keyframes blink { 50% { opacity: 0; } }
            </style>
        </head>
        <body>
            <h1>CTI HIGHLIGHT AT {{timestamp}}</h1>
            <table>
                <tr>
                    <th>IP</th>
                    <th>Source</th>
                    <th>Severity</th>
                    <th>Description</th>
                    <th>Timestamp</th>
                </tr>
                {% for ip, source, severity, desc, ts in events %}
                <tr class="{{'critical' if severity=='High' else ''}}">
                    <td>{{ip}}</td>
                    <td>{{source}}</td>
                    <td>{{severity}}</td>
                    <td>{{desc}}</td>
                    <td>{{ts}}</td>
                </tr>
                {% endfor %}
            </table>
            <p style="margin-top:20px; font-size:12px; color:#888;">Developed and analysed by darkgrid@redshark.my using publicly available sources.</p>
        </body>
        </html>
        """, events=events, timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    except Exception as e:
        return f"Error rendering page: {e}", 500

@app.route("/export_pdf")
def export_pdf():
    try:
        events = fetch_recent_events(limit=100) or []
        buffer = io.BytesIO()
        from reportlab.platypus import SimpleDocTemplate, Table
        from reportlab.lib.pagesizes import letter
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        data = [["IP", "Source", "Severity", "Description", "Timestamp"]] + list(events)
        table = Table(data)
        doc.build([table])
        buffer.seek(0)
        return send_file(buffer, as_attachment=True, download_name="cti_highlight.pdf", mimetype="application/pdf")
    except Exception as e:
        return f"Error generating PDF: {e}", 500

@app.route("/export_csv")
def export_csv():
    try:
        events = fetch_recent_events(limit=100) or []
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(["IP", "Source", "Severity", "Description", "Timestamp"])
        writer.writerows(events)
        buffer.seek(0)
        return send_file(io.BytesIO(buffer.getvalue().encode()), as_attachment=True, download_name="cti_highlight.csv", mimetype="text/csv")
    except Exception as e:
        return f"Error generating CSV: {e}", 500

# ==============================
# Run Flask App
# ==============================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)