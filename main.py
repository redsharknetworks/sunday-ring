import os
import io
import csv
import json
import zipfile
import threading
import logging
from datetime import datetime
import sqlite3
import requests
from flask import Flask, render_template, jsonify, send_file

app = Flask(__name__, template_folder="templates")

DB_FILE = "redshark.db"
OTX_KEY = os.environ.get("OTX_KEY","aa94a69a780ed789016bb72d51d9b58b823eb1e6173f6fffc34530693dacb03b")
ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_KEY","08cf00dc25d22cbd0f45ec5ebb87cb61e93c22349a6eb14544a100")

logging.basicConfig(level=logging.INFO)

LOCATIONS = [
    ("Kuala Lumpur",3.1390,101.6869),("George Town",5.4141,100.3288),
    ("Johor Bahru",1.4927,103.7414),("Kota Kinabalu",5.9804,116.0735)
]

MITRE_MAP = [
    "T1046 Network Discovery","T1059 Command Execution",
    "T1566 Phishing","T1071 C2 Communication"
]

# ---------------- DATABASE ---------------- #
def get_db():
    conn = sqlite3.connect(DB_FILE, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS indicators(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator TEXT UNIQUE,
            type TEXT,
            source TEXT,
            severity TEXT,
            mitre TEXT,
            score INTEGER,
            country TEXT,
            lat REAL,
            lon REAL,
            first_seen TEXT,
            last_seen TEXT
        )
        """)

init_db()

# ---------------- HELPERS ---------------- #
def detect_type(ind):
    import re
    ip = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
    hsh = re.compile(r"^[a-fA-F0-9]{32,128}$")
    domain = re.compile(r"^(?!\d+$)([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")
    url = re.compile(r"^https?://")
    if ip.match(ind): return "IP"
    elif hsh.match(ind): return "Hash"
    elif domain.match(ind) or url.match(ind): return "Domain"
    return "Unknown"

# ---------------- THREAT FETCH ---------------- #
def fetch_otx():
    out=[]
    try:
        r = requests.get("https://otx.alienvault.com/api/v1/pulses/subscribed",
                         headers={"X-OTX-API-KEY": OTX_KEY}, timeout=10)
        for pulse in r.json().get("results",[]):
            for i in pulse.get("indicators",[]):
                loc = LOCATIONS[int(datetime.utcnow().timestamp())%len(LOCATIONS)]
                typ = detect_type(i["indicator"])
                sev = "Critical" if typ=="IP" else "High"
                out.append({
                    "indicator": i["indicator"],
                    "type": typ,
                    "source": "OTX",
                    "severity": sev,
                    "mitre": MITRE_MAP[int(datetime.utcnow().timestamp())%len(MITRE_MAP)],
                    "score": 95 if sev=="Critical" else 80,
                    "country": loc[0],
                    "lat": loc[1],
                    "lon": loc[2],
                    "first_seen": datetime.utcnow().isoformat(),
                    "last_seen": datetime.utcnow().isoformat()
                })
    except Exception as e:
        logging.error(f"OTX error: {e}")
    return out

def fetch_abuse():
    out=[]
    try:
        r = requests.get("https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum=70&limit=50",
                         headers={"Key": ABUSEIPDB_KEY,"Accept":"application/json"}, timeout=10)
        for i in r.json().get("data",[]):
            loc = LOCATIONS[int(datetime.utcnow().timestamp())%len(LOCATIONS)]
            out.append({
                "indicator": i["ipAddress"],
                "type": "IP",
                "source": "AbuseIPDB",
                "severity": "Critical",
                "mitre": MITRE_MAP[int(datetime.utcnow().timestamp())%len(MITRE_MAP)],
                "score": 95,
                "country": loc[0],
                "lat": loc[1],
                "lon": loc[2],
                "first_seen": datetime.utcnow().isoformat(),
                "last_seen": datetime.utcnow().isoformat()
            })
    except Exception as e:
        logging.error(f"AbuseIPDB error: {e}")
    return out

def save_iocs(iocs):
    with get_db() as conn:
        for i in iocs:
            try:
                conn.execute("""
                    INSERT OR IGNORE INTO indicators
                    (indicator,type,source,severity,mitre,score,country,lat,lon,first_seen,last_seen)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)
                """, tuple(i.values()))
            except Exception as e:
                logging.error(f"DB insert error: {e}")

def cleanup_db(limit=5000):
    with get_db() as conn:
        conn.execute(f"""
        DELETE FROM indicators WHERE id NOT IN (
            SELECT id FROM indicators ORDER BY last_seen DESC LIMIT {limit}
        )
        """)

# ---------------- BACKGROUND ENGINE ---------------- #
def threat_engine():
    while True:
        logging.info("Fetching threat feeds...")
        data = fetch_otx() + fetch_abuse()
        if data:
            save_iocs(data)
            cleanup_db()
            logging.info(f"Saved {len(data)} IOCs")
        else:
            logging.info("No IOCs fetched")
        import time; time.sleep(600)

def start_engine():
    if not hasattr(start_engine,"started"):
        threading.Thread(target=threat_engine, daemon=True).start()
        start_engine.started = True

# ---------------- ROUTES ---------------- #
@app.before_first_request
def start_background():
    start_engine()

@app.route("/")
def dashboard():
    malaysia_time = (datetime.utcnow()).strftime("%Y-%m-%d %H:%M:%S")
    return render_template("dashboard.html", time=malaysia_time)

@app.route("/api/data")
def api_data():
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM indicators ORDER BY last_seen DESC LIMIT 500").fetchall()
        return jsonify([dict(r) for r in rows])

# ---------------- EXPORTS ---------------- #
@app.route("/export/json")
def export_json():
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM indicators").fetchall()
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w') as zf:
        zf.writestr("redshark_cti.json", json.dumps([dict(r) for r in rows], indent=2))
    zip_buffer.seek(0)
    return send_file(zip_buffer, as_attachment=True, download_name="redshark_cti_json.zip")

# ---------------- RUN ---------------- #
if __name__=="__main__":
    port = int(os.environ.get("PORT",5000))
    app.run(host="0.0.0.0", port=port)