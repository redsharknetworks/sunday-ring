import io
import csv
import json
import zipfile
import time
import threading
import logging
import re
from datetime import datetime, timedelta

import sqlite3
import requests
from flask import Flask, render_template_string, jsonify, send_file
from flask_socketio import SocketIO
from reportlab.platypus import SimpleDocTemplate, Table
from reportlab.lib.pagesizes import letter

# ---------------- CONFIG ---------------- #
app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")  # real-time updates
DB_FILE = "redshark.db"

# ⚠️ Hardcoded API keys (for Render test)
OTX_KEY = "aa94a69a780ed789016bb72d51d9b58b823eb1e6173f6fffc34530693dacb03b"
ABUSEIPDB_KEY = "08cf00dc25d22cbd0f45ec5ebb87cb61e93c22349a6eb14544a100"

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

LOCATIONS = [
    ("Kangar",6.4414,100.1986),("Alor Setar",6.1248,100.3678),("George Town",5.4141,100.3288),
    ("Ipoh",4.5975,101.0901),("Shah Alam",3.0738,101.5183),("Kuala Lumpur",3.1390,101.6869),
    ("Seremban",2.7297,101.9381),("Melaka",2.1896,102.2501),("Johor Bahru",1.4927,103.7414),
    ("Kuantan",3.8168,103.3317),("Kuala Terengganu",5.3302,103.1408),("Kota Bharu",6.1254,102.2386),
    ("Kuching",1.5533,110.3592),("Kota Kinabalu",5.9804,116.0735),("Putrajaya",2.9264,101.6964)
]

MITRE_MAP = [
    "T1046 Network Discovery","T1059 Command Execution","T1566 Phishing",
    "T1071 C2 Communication","T1105 Data Exfiltration","T1190 Exploit Public Facing App"
]

# ---------------- DATABASE ---------------- #
def init_db():
    with sqlite3.connect(DB_FILE, check_same_thread=False) as conn:
        c = conn.cursor()
        c.execute("""
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
        )""")
        conn.commit()
init_db()

def save_iocs(iocs):
    with sqlite3.connect(DB_FILE, check_same_thread=False) as conn:
        c = conn.cursor()
        for i in iocs:
            try:
                c.execute("""
                INSERT OR IGNORE INTO indicators
                (indicator,type,source,severity,mitre,score,country,lat,lon,first_seen,last_seen)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)
                """,(
                    i["indicator"],i["type"],i["source"],i["severity"],i["mitre"],
                    i["score"],i["country"],i["lat"],i["lon"],i["first_seen"],i["last_seen"]
                ))
            except Exception as e:
                logging.error(f"DB insert error: {e}")
        conn.commit()
        # push to frontend
        socketio.emit("update", iocs)

def cleanup_db(limit=5000):
    with sqlite3.connect(DB_FILE, check_same_thread=False) as conn:
        c = conn.cursor()
        c.execute(f"""
        DELETE FROM indicators
        WHERE id NOT IN (
            SELECT id FROM indicators
            ORDER BY last_seen DESC
            LIMIT {limit}
        )
        """)
        conn.commit()

# ---------------- FEED FETCHERS ---------------- #
def detect_type(indicator):
    ip_pattern = re.compile(r"^(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$")
    hash_pattern = re.compile(r"^[a-fA-F0-9]{32,128}$")
    domain_pattern = re.compile(r"^(?!\d+$)([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")
    url_pattern = re.compile(r"^https?://")

    if ip_pattern.match(indicator):
        return "IP"
    elif hash_pattern.match(indicator):
        return "Hash"
    elif url_pattern.match(indicator) or domain_pattern.match(indicator):
        return "Domain"
    return "Unknown"

def fetch_otx_iocs():
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
    headers = {"X-OTX-API-KEY": OTX_KEY}
    iocs = []
    try:
        r = requests.get(url, headers=headers, timeout=15)
        if r.status_code == 200:
            for pulse in r.json().get("results", []):
                for ind in pulse.get("indicators", []):
                    typ = detect_type(ind["indicator"])
                    loc = LOCATIONS[int(datetime.utcnow().timestamp()) % len(LOCATIONS)]
                    severity = "Critical" if typ=="IP" else "High"
                    iocs.append({
                        "indicator": ind["indicator"],
                        "type": typ,
                        "source": "OTX",
                        "severity": severity,
                        "mitre": MITRE_MAP[int(datetime.utcnow().timestamp()) % len(MITRE_MAP)],
                        "score": 95 if severity=="Critical" else 80,
                        "country": loc[0],
                        "lat": loc[1],
                        "lon": loc[2],
                        "first_seen": datetime.utcnow().isoformat(),
                        "last_seen": datetime.utcnow().isoformat()
                    })
    except Exception as e:
        logging.error(f"OTX fetch error: {e}")
    return iocs

def fetch_abuseipdb():
    url = "https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum=70&limit=100"
    headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
    iocs = []
    try:
        r = requests.get(url, headers=headers, timeout=15)
        if r.status_code == 200:
            for item in r.json().get("data", []):
                loc = LOCATIONS[int(datetime.utcnow().timestamp()) % len(LOCATIONS)]
                iocs.append({
                    "indicator": item["ipAddress"],
                    "type": "IP",
                    "source": "AbuseIPDB",
                    "severity": "Critical",
                    "mitre": MITRE_MAP[int(datetime.utcnow().timestamp()) % len(MITRE_MAP)],
                    "score": 95,
                    "country": loc[0],
                    "lat": loc[1],
                    "lon": loc[2],
                    "first_seen": datetime.utcnow().isoformat(),
                    "last_seen": datetime.utcnow().isoformat()
                })
    except Exception as e:
        logging.error(f"AbuseIPDB fetch error: {e}")
    return iocs

# ---------------- THREAT ENGINE ---------------- #
def threat_engine():
    while True:
        logging.info("Fetching threat feeds...")
        all_iocs = fetch_otx_iocs() + fetch_abuseipdb()
        if all_iocs:
            save_iocs(all_iocs)
            cleanup_db()
            logging.info(f"Saved {len(all_iocs)} IOCs")
        else:
            logging.info("No IOCs fetched")
        time.sleep(600)

threading.Thread(target=threat_engine, daemon=True).start()

# ---------------- API & DASHBOARD ---------------- #
@app.route("/api/data")
def api_data():
    with sqlite3.connect(DB_FILE, check_same_thread=False) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT indicator,type,source,severity,mitre,score,country,lat,lon,last_seen FROM indicators ORDER BY last_seen DESC LIMIT 500")
        rows = [dict(r) for r in c.fetchall()]
    return jsonify(rows)

@app.route("/")
def dashboard():
    malaysia_time = (datetime.utcnow()+timedelta(hours=8)).strftime("%Y-%m-%d %H:%M:%S")
    return render_template_string("""
<html>
<head>
<title>RedShark SOC Enterprise</title>
<script src="https://cdn.jsdelivr.net/npm/socket.io-client@4/dist/socket.io.min.js"></script>
<script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
</head>
<body>
<h1>RedShark Enterprise SOC Dashboard</h1>
<div id="updates">Realtime updates will appear here.</div>
<script>
var socket = io();
socket.on("update", function(data){
    $("#updates").html(JSON.stringify(data.slice(0,5), null, 2));
});
</script>
</body>
</html>
""", time=malaysia_time)

# ---------------- EXPORTS ---------------- #
@app.route("/export/json")
def export_json():
    with sqlite3.connect(DB_FILE, check_same_thread=False) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM indicators")
        rows = [dict(r) for r in c.fetchall()]
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w') as zf:
        zf.writestr("redshark_cti.json", json.dumps(rows, indent=2))
    zip_buffer.seek(0)
    return send_file(zip_buffer, as_attachment=True, download_name="redshark_cti_json.zip")

# ---------------- RUN SERVER ---------------- #
if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)