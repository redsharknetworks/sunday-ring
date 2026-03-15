# -------------------------------
# RedShark Cyber Threat Intelligence Platform
# Version: v23.1 (single-file deploy)
# -------------------------------
import os
import sqlite3
import random
import threading
import time
import requests
from datetime import datetime
from flask import Flask, render_template_string, jsonify, send_file
import io
import csv
import json
from reportlab.platypus import SimpleDocTemplate, Table
from reportlab.lib.pagesizes import letter

app = Flask(__name__)

# -------------------------------
# Storage
# -------------------------------
DB_DIR = "data"
DB_PATH = os.path.join(DB_DIR, "cti.db")
os.makedirs(DB_DIR, exist_ok=True)

# -------------------------------
# Malaysia Ibu Negeri (state capitals)
# -------------------------------
MALAYSIA_LOCATIONS = [
    ("Kangar",6.4414,100.1986),("Alor Setar",6.1248,100.3678),("George Town",5.4141,100.3288),
    ("Ipoh",4.5975,101.0901),("Shah Alam",3.0738,101.5183),("Kuala Lumpur",3.1390,101.6869),
    ("Seremban",2.7297,101.9381),("Melaka",2.1896,102.2501),("Johor Bahru",1.4927,103.7414),
    ("Kuantan",3.8168,103.3317),("Kuala Terengganu",5.3302,103.1408),("Kota Bharu",6.1254,102.2386),
    ("Kuching",1.5533,110.3592),("Kota Kinabalu",5.9804,116.0735),("Putrajaya",2.9264,101.6964)
]

def map_to_ibu_negeri():
    return random.choice(MALAYSIA_LOCATIONS)

# -------------------------------
# Database
# -------------------------------
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS events(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT,
        source TEXT,
        severity TEXT,
        country TEXT,
        rule TEXT,
        description TEXT,
        lat REAL,
        lon REAL,
        timestamp TEXT
    )
    """)
    conn.commit()
    conn.close()

init_db()

def insert_events(events):
    if not events:
        return
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    for e in events:
        # dedupe by ip+source
        exist = c.execute(
            "SELECT id FROM events WHERE ip=? AND source=?",
            (e["ip"], e["source"])
        ).fetchone()
        if exist:
            continue
        c.execute("""
            INSERT INTO events(ip,source,severity,country,rule,description,lat,lon,timestamp)
            VALUES (?,?,?,?,?,?,?,?,?)
        """, (
            e["ip"], e["source"], e["severity"], e["country"], e["rule"],
            e["description"], e["lat"], e["lon"], e["timestamp"]
        ))
    conn.commit()
    conn.close()

def get_events(limit=800):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    rows = c.execute(
        "SELECT * FROM events ORDER BY id DESC LIMIT ?",
        (limit,)
    ).fetchall()
    conn.close()
    return rows

# -------------------------------
# CTI Feeds (No API key)
# -------------------------------
def fetch_abusech():
    """
    Feodo Tracker IP blocklist
    """
    url = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
    events = []
    try:
        r = requests.get(url, timeout=20)
        if r.status_code != 200:
            return events
        for line in r.text.splitlines():
            if line.startswith("#") or not line.strip():
                continue
            ip = line.strip()
            lat, lon = map_to_ibu_negeri()[1:3]
            events.append({
                "ip": ip,
                "source": "Abuse.ch",
                "severity": "High",
                "country": "Malaysia",
                "rule": "FeodoBotnet",
                "description": "Botnet C2 from Feodo Tracker",
                "lat": lat,
                "lon": lon,
                "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
            })
    except Exception as e:
        print("Feodo feed error:", e)
    return events

def fetch_spamhaus():
    """
    Spamhaus DROP list
    """
    url = "https://www.spamhaus.org/drop/drop.txt"
    events = []
    try:
        r = requests.get(url, timeout=20)
        if r.status_code != 200:
            return events
        for line in r.text.splitlines():
            if line.startswith(";") or not line.strip():
                continue
            block = line.split(";")[0].strip()  # may be CIDR
            ip = block.split("/")[0]           # take base IP for visualization
            lat, lon = map_to_ibu_negeri()[1:3]
            events.append({
                "ip": ip,
                "source": "Spamhaus",
                "severity": "High",
                "country": "Malaysia",
                "rule": "Spamhaus DROP",
                "description": "Known criminal IP block (DROP)",
                "lat": lat,
                "lon": lon,
                "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
            })
    except Exception as e:
        print("Spamhaus feed error:", e)
    return events

# -------------------------------
# Fallback (real IOC examples)
# -------------------------------
def fallback_real_iocs():
    real_iocs = [
        "45.9.148.108","185.220.101.32","91.219.236.23","103.27.202.41",
        "194.147.32.109","5.188.86.79","37.120.222.132","80.82.77.202"
    ]
    events=[]
    for ip in real_iocs:
        lat,lon = map_to_ibu_negeri()[1:3]
        events.append({
            "ip": ip,
            "source": "Fallback-IOC",
            "severity": "High",
            "country": "Malaysia",
            "rule": "Fallback IOC",
            "description": "Recent malicious IP observed in global feeds",
            "lat": lat,
            "lon": lon,
            "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        })
    return events

# -------------------------------
# Feed Loop
# -------------------------------
def feed_loop():
    while True:
        try:
            events = []
            events += fetch_abusech()
            events += fetch_spamhaus()

            # if both feeds fail, insert fallback
            if not events:
                events = fallback_real_iocs()

            insert_events(events)
            print("IOC inserted:", len(events))
        except Exception as e:
            print("Feed loop error:", e)
        time.sleep(900)  # 15 minutes

threading.Thread(target=feed_loop, daemon=True).start()

# -------------------------------
# Aggregated Lines
# -------------------------------
def get_aggregated_lines(events):
    agg = {}
    for e in events:
        if e[3] != "High":
            continue
        key = (e[1], e[2])  # ip, source
        if key not in agg:
            ibu_lat, ibu_lon = map_to_ibu_negeri()[1:3]
            agg[key] = {
                "lat": e[7], "lon": e[8],
                "ibu_lat": ibu_lat, "ibu_lon": ibu_lon,
                "count": 0
            }
        agg[key]["count"] += 1
    return list(agg.values())

# -------------------------------
# API
# -------------------------------
@app.route("/data")
def data():
    events = get_events()

    heat_data = []
    markers = []
    table_rows = []
    severity_counts = {"High":0,"Medium":0,"Low":0}
    timeline = {}

    for e in events:
        severity_counts[e[3]] += 1
        hour = e[9][:13]
        timeline[hour] = timeline.get(hour,0)+1

        table_rows.append({
            "ip": e[1],
            "source": e[2],
            "severity": e[3],
            "rule": e[5],
            "timestamp": e[9]
        })

        if e[3] == "High":
            heat_data.append([e[7], e[8], 3])

        markers.append({
            "lat": e[7],
            "lon": e[8],
            "popup": f"{e[1]}<br>{e[2]}<br>{e[5]}"
        })

    lines = []
    for l in get_aggregated_lines(events):
        lines.append({
            "from":[l["lat"],l["lon"]],
            "to":[l["ibu_lat"],l["ibu_lon"]],
            "count":l["count"]
        })

    return jsonify({
        "heat_data":heat_data,
        "markers":markers,
        "lines":lines,
        "severity_counts":severity_counts,
        "timeline":timeline,
        "table_rows":table_rows
    })

# -------------------------------
# Downloads
# -------------------------------
@app.route("/download/csv")
def download_csv():
    events = get_events()
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(["IP","Source","Severity","Rule","Timestamp"])
    for e in events:
        cw.writerow([e[1],e[2],e[3],e[5],e[9]])
    return send_file(io.BytesIO(si.getvalue().encode()),
                     mimetype="text/csv",
                     as_attachment=True,
                     download_name="cti_report.csv")

@app.route("/download/json")
def download_json():
    events = get_events()
    data=[{
        "ip":e[1],"source":e[2],"severity":e[3],
        "rule":e[5],"timestamp":e[9]
    } for e in events]
    return send_file(io.BytesIO(json.dumps(data,indent=2).encode()),
                     mimetype="application/json",
                     as_attachment=True,
                     download_name="cti_report.json")

@app.route("/download/pdf")
def download_pdf():
    events = get_events()
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer,pagesize=letter)
    data=[["IP","Source","Severity","Rule","Timestamp"]]
    for e in events:
        data.append([e[1],e[2],e[3],e[5],e[9]])
    table=Table(data)
    doc.build([table])
    buffer.seek(0)
    return send_file(buffer,
                     mimetype="application/pdf",
                     as_attachment=True,
                     download_name="cti_report.pdf")

@app.route("/download/ids")
def download_ids():
    events = get_events()
    si=io.StringIO()
    for e in events:
        if e[3]=="High":
            sid=random.randint(1000000,9999999)
            rule=f'alert ip any any -> {e[1]} any (msg:"CTI {e[5]}"; sid:{sid}; rev:1;)'
            si.write(rule+"\n")
    return send_file(io.BytesIO(si.getvalue().encode()),
                     mimetype="text/plain",
                     as_attachment=True,
                     download_name="cti_ids.rules")

# -------------------------------
# Debug
# -------------------------------
@app.route("/debug")
def debug():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    count = c.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    conn.close()
    return {"events":count}

# -------------------------------
# Dashboard
# -------------------------------
@app.route("/")
def dashboard():
    return render_template_string("""
<!DOCTYPE html>
<html>
<head>
<title>RedShark Cyber Threat Intelligence Platform</title>
<meta charset="utf-8"/>
<link rel="stylesheet" href="https://unpkg.com/leaflet/dist/leaflet.css"/>
<script src="https://unpkg.com/leaflet/dist/leaflet.js"></script>
<script src="https://unpkg.com/leaflet.heat/dist/leaflet-heat.js"></script>
<style>
body{margin:0;background:#111;color:#eee;font-family:Arial}
#map{height:90vh}
header{padding:10px;text-align:center;color:#ff4444;font-size:22px}
footer{padding:10px;text-align:center;color:#777;font-size:12px}
</style>
</head>
<body>

<header>RedShark Cyber Threat Intelligence Platform</header>

<div id="map"></div>

<script>
var map=L.map('map').setView([4.21,101.97],6);
L.tileLayer(
 'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',
 {subdomains:'abcd',maxZoom:19,attribution:''}
).addTo(map);

var heat=L.heatLayer([], {radius:25}).addTo(map);
var markerLayer=L.layerGroup().addTo(map);
var lineLayer=L.layerGroup().addTo(map);

async function fetchData(){
 const r=await fetch('/data');
 const d=await r.json();

 heat.setLatLngs([]);
 markerLayer.clearLayers();
 lineLayer.clearLayers();

 d.heat_data.forEach(p=>heat.addLatLng(p));

 d.markers.forEach(m=>{
   L.marker([m.lat,m.lon]).bindPopup(m.popup).addTo(markerLayer);
 });

 d.lines.forEach(l=>{
   L.polyline([l.from,l.to],{
     color:'red',
     weight:Math.min(l.count*2,8),
     opacity:0.7
   }).addTo(lineLayer);
 });
}

fetchData();
setInterval(fetchData,60000);
</script>

<footer>
Developed and analysed by darkgrid@redshark.my using publicly available sources
</footer>

</body>
</html>
""")

# -------------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)