import os
import io
import csv
import base64
import sqlite3
import threading
import time
from datetime import datetime, timedelta

import requests
from flask import (
    Flask, render_template_string, send_file,
    jsonify, request, abort
)

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

import folium
from folium.plugins import HeatMap

# ---------------- CONFIG ----------------

app = Flask(__name__)

DB = os.getenv("DB_PATH", "threats.db")
OTX_KEY = os.getenv("OTX_KEY")
API_KEY = os.getenv("API_KEY", "secure123")
OTX_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"
RETENTION_DAYS = int(os.getenv("RETENTION_DAYS", 30))


# ---------------- DATABASE ----------------

def get_conn():
    return sqlite3.connect(DB, timeout=30, check_same_thread=False)


def ensure_database():
    conn = get_conn()
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS threats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pulse TEXT,
        signal TEXT,
        type TEXT,
        classification TEXT,
        mitre TEXT,
        risk_score INTEGER,
        created_at TEXT,
        UNIQUE(signal, type)
    )
    """)
    conn.commit()
    conn.close()


# ---------------- RISK ENGINE ----------------

def calculate_risk(indicator_type):
    base = {
        "domain": 75,
        "ip": 80,
        "url": 85,
        "file_hash": 90
    }.get(indicator_type, 70)

    return base


def classify(score):
    if score >= 85:
        return "High"
    elif score >= 70:
        return "Medium"
    return "Low"


# ---------------- DATA RETENTION ----------------

def cleanup_old_data():
    cutoff = datetime.utcnow() - timedelta(days=RETENTION_DAYS)
    conn = get_conn()
    conn.execute(
        "DELETE FROM threats WHERE created_at < ?",
        (cutoff.isoformat(),)
    )
    conn.commit()
    conn.close()


# ---------------- OTX FETCH ----------------

def fetch_otx_data():
    ensure_database()

    if not OTX_KEY:
        print("No OTX key — skipping fetch.")
        return

    headers = {"X-OTX-API-KEY": OTX_KEY}
    next_url = OTX_URL

    conn = get_conn()
    c = conn.cursor()

    while next_url:
        try:
            r = requests.get(next_url, headers=headers, timeout=20)
            r.raise_for_status()
            data = r.json()
        except Exception as e:
            print("OTX error:", e)
            break

        for pulse in data.get("results", []):
            name = pulse.get("name", "OTX Pulse")
            for ind in pulse.get("indicators", []):
                val = ind.get("indicator")
                typ = ind.get("type", "domain")
                if not val:
                    continue

                score = calculate_risk(typ)
                classification = classify(score)

                c.execute("""
                INSERT OR IGNORE INTO threats
                (pulse, signal, type, classification, mitre, risk_score, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    name,
                    val,
                    typ,
                    classification,
                    "OTX",
                    score,
                    datetime.utcnow().isoformat()
                ))

        next_url = data.get("next")

    conn.commit()
    conn.close()
    cleanup_old_data()
    print("OTX updated.")


# ---------------- SCHEDULER ----------------

def scheduler():
    while True:
        fetch_otx_data()
        time.sleep(3600)


# ---------------- SECURENATION INDEX ----------------

def securenation_index():
    conn = get_conn()
    total = conn.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
    high = conn.execute(
        "SELECT COUNT(*) FROM threats WHERE risk_score >= 85"
    ).fetchone()[0]
    conn.close()

    if total == 0:
        return 100

    exposure_ratio = high / total
    index = max(0, 100 - int(exposure_ratio * 100))
    return index


# ---------------- API PROTECTION ----------------

def require_api_key():
    key = request.headers.get("X-API-KEY")
    if key != API_KEY:
        abort(401)


# ---------------- DASHBOARD ----------------

TEMPLATE = """
<html>
<head>
<title>SecureNation Index Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
body { background:#0A2239; color:white; font-family:Arial; }
.card { padding:20px; background:#1C3C6B; margin:15px; border-radius:8px; }
button { padding:8px 15px; background:crimson; color:white; border:none; }
</style>
</head>
<body>

<h2>SecureNation Index</h2>

<div class="card">
<h1 id="index">{{ index }}</h1>
<p>National Cyber Exposure Score (0 = critical, 100 = secure)</p>
<button onclick="refreshIndex()">Refresh</button>
</div>

<div class="card">
<h3>Threat Overview</h3>
<p>Total Signals: {{ total }}</p>
<p>High Risk: {{ high }}</p>
</div>

<script>
function refreshIndex(){
 fetch('/api/index')
  .then(r=>r.json())
  .then(d=>{
    document.getElementById("index").innerText = d.index;
  });
}

setInterval(refreshIndex, 60000);
</script>

</body>
</html>
"""


@app.route("/")
def dashboard():
    conn = get_conn()
    total = conn.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
    high = conn.execute(
        "SELECT COUNT(*) FROM threats WHERE risk_score>=85"
    ).fetchone()[0]
    conn.close()

    return render_template_string(
        TEMPLATE,
        index=securenation_index(),
        total=total,
        high=high
    )


# ---------------- REST API ----------------

@app.route("/api/index")
def api_index():
    return jsonify({"index": securenation_index()})


@app.route("/api/threats")
def api_threats():
    require_api_key()

    t = request.args.get("type")
    conn = get_conn()

    if t:
        rows = conn.execute(
            "SELECT * FROM threats WHERE type=? ORDER BY created_at DESC",
            (t,)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM threats ORDER BY created_at DESC"
        ).fetchall()

    conn.close()

    return jsonify([dict(zip(
        ["id","pulse","signal","type","classification","mitre","risk_score","created_at"],
        r
    )) for r in rows])


# ---------------- EXPORT ----------------

@app.route("/report/csv")
def export_csv():
    require_api_key()

    conn = get_conn()
    rows = conn.execute("SELECT * FROM threats").fetchall()
    conn.close()

    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(["ID","Pulse","Signal","Type","Class","MITRE","Risk","Created"])
    for r in rows:
        cw.writerow(r)

    buf = io.BytesIO()
    buf.write(si.getvalue().encode())
    buf.seek(0)

    return send_file(
        buf,
        as_attachment=True,
        download_name="SecureNation_Report.csv"
    )


# ---------------- START ----------------

ensure_database()

if os.environ.get("WERKZEUG_RUN_MAIN") == "true":
    threading.Thread(target=scheduler, daemon=True).start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
