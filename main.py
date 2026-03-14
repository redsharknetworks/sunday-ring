import os
import sqlite3
import random
import requests
import threading
import time
from datetime import datetime
from flask import Flask, render_template_string, jsonify

app = Flask(__name__)

# ===============================
# Database Setup
# ===============================
DB_DIR = "data"
DB_PATH = os.path.join(DB_DIR, "cti.db")
if not os.path.exists(DB_DIR):
    os.makedirs(DB_DIR)

MALAYSIA_LOCATIONS = [
    ("Kangar", 6.4414, 100.1986),
    ("Alor Setar", 6.1248, 100.3678),
    ("George Town", 5.4141, 100.3288),
    ("Ipoh", 4.5975, 101.0901),
    ("Shah Alam", 3.0738, 101.5183),
    ("Kuala Lumpur", 3.1390, 101.6869),
    ("Seremban", 2.7297, 101.9381),
    ("Melaka", 2.1896, 102.2501),
    ("Johor Bahru", 1.4927, 103.7414),
    ("Kuantan", 3.8168, 103.3317),
    ("Kuala Terengganu", 5.3302, 103.1408),
    ("Kota Bharu", 6.1254, 102.2386),
    ("Kuching", 1.5533, 110.3592),
    ("Kota Kinabalu", 5.9804, 116.0735),
    ("Putrajaya", 2.9264, 101.6964),
]

SEVERITY_WEIGHT = {"High": 3, "Medium": 2, "Low": 1}

OTX_API_KEY = "aa94a69a780ed789016bb72d51d9b58b823eb1e6173f6fffc34530693dacb03b"
ABUSEIPDB_KEY = "08cf00dc25d22cbd0f45ec5ebb87cb61e289533bd33bceb9b93c22349a6eb8674d52aaf14544a100"
OTX_EXPORT_URL = "https://otx.alienvault.com/api/v1/indicators/export"
ABUSE_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
SPAMHAUS_DROP_URL = "https://www.spamhaus.org/drop/drop.txt"
EMERGINGTHREATS_URL = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"

# ===============================
# Database Functions
# ===============================
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
    c.execute("""
    CREATE TABLE IF NOT EXISTS geo_cache(
        ip TEXT PRIMARY KEY,
        country TEXT,
        lat REAL,
        lon REAL
    )
    """)
    conn.commit()
    conn.close()

def get_events(limit=500):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    rows = c.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return rows

# ===============================
# Geolocation with caching
# ===============================
def get_country_from_ip(ip):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    cached = c.execute("SELECT country,lat,lon FROM geo_cache WHERE ip=?", (ip,)).fetchone()
    if cached:
        conn.close()
        return cached[0], cached[1], cached[2]
    country, lat, lon = "Unknown", 0.0, 0.0
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = r.json()
        country = data.get("country","Unknown")
        lat = data.get("lat",0.0)
        lon = data.get("lon",0.0)
    except:
        pass
    c.execute("INSERT OR REPLACE INTO geo_cache(ip,country,lat,lon) VALUES(?,?,?,?)",(ip,country,lat,lon))
    conn.commit()
    conn.close()
    return country, lat, lon

# ===============================
# Background Feed Fetching
# ===============================
def fetch_cti_combined():
    while True:
        headers_otx = {"X-OTX-API-KEY": OTX_API_KEY}
        headers_abuse = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
        feeds = []

        try:
            r = requests.get(OTX_EXPORT_URL, headers=headers_otx, timeout=30)
            feeds += r.text.splitlines()[:100]
        except: pass
        try:
            r = requests.get(SPAMHAUS_DROP_URL, timeout=15)
            feeds += [line.split()[0] for line in r.text.splitlines() if line and not line.startswith(";")][:100]
        except: pass
        try:
            r = requests.get(EMERGINGTHREATS_URL, timeout=15)
            feeds += [line.strip() for line in r.text.splitlines() if line and not line.startswith("#")][:100]
        except: pass

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        for ip in feeds:
            ip = ip.strip()
            if not ip: continue
            exist = c.execute("SELECT id FROM events WHERE ip=?", (ip,)).fetchone()
            if exist: continue

            severity = "Low"
            try:
                rep = requests.get(ABUSE_CHECK_URL, headers=headers_abuse, params={"ipAddress": ip,"maxAgeInDays":90}, timeout=15)
                score = rep.json().get("data", {}).get("abuseConfidenceScore", 0)
                if score >= 80: severity="High"
                elif score >= 40: severity="Medium"
            except:
                severity = "Medium"

            country, src_lat, src_lon = get_country_from_ip(ip)

            if country=="Malaysia":
                loc = random.choice(MALAYSIA_LOCATIONS)
                lat, lon = loc[1], loc[2]
            else:
                lat, lon = src_lat, src_lon

            c.execute("""
            INSERT INTO events(ip,source,severity,country,rule,description,lat,lon,timestamp)
            VALUES(?,?,?,?,?,?,?,?,?)
            """,(ip,"CTI Combined",severity,country,f"RSK-{random.randint(1000,9999)}","Threat IOC detected",lat,lon,datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit()
        conn.close()
        time.sleep(600)  # refresh every 10 min

# ===============================
# Start background thread
# ===============================
init_db()
threading.Thread(target=fetch_cti_combined, daemon=True).start()

# ===============================
# Flask Dashboard
# ===============================
@app.route("/")
def dashboard():
    events = get_events()
    heat_data = []
    lines = []
    markers = []

    for e in events:
        weight = SEVERITY_WEIGHT.get(e[3],1)
        if e[4]=="Malaysia":
            heat_data.append([e[7], e[8], weight])
            if e[3]=="High":  # only high severity in marker cluster
                markers.append({
                    "lat": e[7],
                    "lon": e[8],
                    "popup": f"IP: {e[1]}<br>Source: {e[2]}<br>Severity: {e[3]}<br>Country: {e[4]}<br>Time: {e[9]}"
                })
        else:
            loc = random.choice(MALAYSIA_LOCATIONS)
            lines.append({"from_lat": e[7],"from_lon": e[8],"to_lat": loc[1],"to_lon": loc[2],"severity": e[3]})

    return render_template_string("""
<html>
<head>
<title>RedShark Cyber Threat Intelligence Platform</title>
<link rel="stylesheet" href="https://unpkg.com/leaflet/dist/leaflet.css" />
<link rel="stylesheet" href="https://unpkg.com/leaflet.markercluster/dist/MarkerCluster.css" />
<link rel="stylesheet" href="https://unpkg.com/leaflet.markercluster/dist/MarkerCluster.Default.css" />
<style>
body{margin:0;padding:0;font-family:Arial;background:#0f1720;color:#e5e7eb;}
#map{height:600px;}
.header{font-size:28px;padding:15px;background:#111827;}
.footer{text-align:center;font-size:12px;color:#9ca3af;margin-top:20px;}
</style>
<script src="https://unpkg.com/leaflet/dist/leaflet.js"></script>
<script src="https://unpkg.com/leaflet.heat/dist/leaflet-heat.js"></script>
<script src="https://unpkg.com/leaflet.markercluster/dist/leaflet.markercluster.js"></script>
</head>
<body>
<div class="header">RedShark Cyber Threat Intelligence Platform
<div style="font-size:12px">CTI Highlight {{time}}</div></div>

<div id="map"></div>

<div class="footer">
Developed and analysed by darkgrid@redshark.my using publicly available sources
</div>

<script>
var map = L.map('map').setView([4.2105,101.9758],6);
L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png',{attribution:'© OpenStreetMap'}).addTo(map);

// Heatmap
var heat = L.heatLayer({{heat_data|tojson}}, {radius:25, blur:15, maxZoom:10, max:9}).addTo(map);

// Attack lines
var lines = {{lines|tojson}};
lines.forEach(function(l){
    var latlngs = [[l.from_lat,l.from_lon],[l.to_lat,l.to_lon]];
    var color = l.severity=="High"?"red":"orange";
    L.polyline(latlngs,{color:color,weight:l.severity=="High"?3:1,opacity:0.7}).addTo(map);
});

// Marker cluster for high severity
var markers = L.markerClusterGroup();
var mdata = {{markers|tojson}};
mdata.forEach(function(m){
    var marker = L.marker([m.lat,m.lon]).bindPopup(m.popup);
    markers.addLayer(marker);
});
map.addLayer(markers);
</script>
</body>
</html>
""", heat_data=heat_data, lines=lines, markers=markers, time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

if __name__=="__main__":
    app.run(host="0.0.0.0", port=5000)