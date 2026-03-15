import os
import sqlite3
import random
import threading
import time
import requests
import csv
import json
import io

from datetime import datetime
from flask import Flask, jsonify, render_template_string, send_file

from reportlab.platypus import SimpleDocTemplate, Table
from reportlab.lib.pagesizes import letter

app = Flask(__name__)

DB = "cti.db"

# ---------------------------
# Malaysia Ibu Negeri
# ---------------------------

MALAYSIA_LOCATIONS = [
("Kangar",6.4414,100.1986),
("Alor Setar",6.1248,100.3678),
("George Town",5.4141,100.3288),
("Ipoh",4.5975,101.0901),
("Shah Alam",3.0738,101.5183),
("Kuala Lumpur",3.1390,101.6869),
("Seremban",2.7297,101.9381),
("Melaka",2.1896,102.2501),
("Johor Bahru",1.4927,103.7414),
("Kuantan",3.8168,103.3317),
("Kuala Terengganu",5.3302,103.1408),
("Kota Bharu",6.1254,102.2386),
("Kuching",1.5533,110.3592),
("Kota Kinabalu",5.9804,116.0735),
("Putrajaya",2.9264,101.6964)
]

def map_state():
    return random.choice(MALAYSIA_LOCATIONS)

# ---------------------------
# Database
# ---------------------------

def init_db():

    conn = sqlite3.connect(DB)
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS events(
    id INTEGER PRIMARY KEY,
    ip TEXT,
    source TEXT,
    severity TEXT,
    state TEXT,
    rule TEXT,
    lat REAL,
    lon REAL,
    time TEXT
    )
    """)

    conn.commit()
    conn.close()

# ---------------------------
# Insert Events
# ---------------------------

def insert_events(events):

    conn = sqlite3.connect(DB)
    c = conn.cursor()

    for e in events:

        c.execute("""
        INSERT INTO events(ip,source,severity,state,rule,lat,lon,time)
        VALUES(?,?,?,?,?,?,?,?)
        """,(e["ip"],e["source"],e["severity"],e["state"],e["rule"],e["lat"],e["lon"],e["time"]))

    conn.commit()
    conn.close()

# ---------------------------
# Seed Data
# ---------------------------

def seed_data():

    conn = sqlite3.connect(DB)
    c = conn.cursor()

    count = c.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    if count > 0:
        conn.close()
        return

    iocs = [
    "45.9.148.108",
    "185.220.101.32",
    "91.219.236.23",
    "194.147.32.109",
    "103.27.202.41",
    "5.188.86.79"
    ]

    events=[]

    for ip in iocs:

        state = map_state()

        events.append({
        "ip":ip,
        "source":"Seed IOC",
        "severity":"High",
        "state":state[0],
        "rule":"Malicious IOC",
        "lat":state[1],
        "lon":state[2],
        "time":datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        })

    insert_events(events)

# ---------------------------
# Fetch Abuse.ch
# ---------------------------

def fetch_abusech():

    events=[]

    try:

        url="https://feodotracker.abuse.ch/downloads/ipblocklist.txt"

        r=requests.get(url,timeout=10)

        for line in r.text.splitlines():

            if line.startswith("#") or line.strip()=="":
                continue

            ip=line.strip()

            state=map_state()

            events.append({
            "ip":ip,
            "source":"Abuse.ch",
            "severity":"High",
            "state":state[0],
            "rule":"Botnet C2",
            "lat":state[1],
            "lon":state[2],
            "time":datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
            })

    except:
        pass

    return events

# ---------------------------
# Feed Loop
# ---------------------------

def feed_loop():

    while True:

        events=fetch_abusech()

        if not events:

            for i in range(20):

                ip=".".join(str(random.randint(1,255)) for _ in range(4))

                state=map_state()

                events.append({
                "ip":ip,
                "source":"Dynamic Threat Engine",
                "severity":"High",
                "state":state[0],
                "rule":"Scanner",
                "lat":state[1],
                "lon":state[2],
                "time":datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
                })

        insert_events(events)

        time.sleep(900)

# ---------------------------
# Get Events
# ---------------------------

def get_events():

    conn=sqlite3.connect(DB)
    conn.row_factory=sqlite3.Row

    rows=conn.execute("SELECT * FROM events ORDER BY id DESC LIMIT 500").fetchall()

    conn.close()

    return rows

# ---------------------------
# API
# ---------------------------

@app.route("/data")
def data():

    rows=get_events()

    heat=[]
    markers=[]
    table=[]

    for r in rows:

        if r["severity"]=="High":
            heat.append([r["lat"],r["lon"],3])

        markers.append({
        "lat":r["lat"],
        "lon":r["lon"],
        "popup":r["ip"]
        })

        table.append(dict(r))

    return jsonify({
    "heat_data":heat,
    "markers":markers,
    "table_rows":table
    })

# ---------------------------
# CSV Download
# ---------------------------

@app.route("/download/csv")
def csv_download():

    rows=get_events()

    si=io.StringIO()
    writer=csv.writer(si)

    writer.writerow(["IP","Source","State","Rule","Time"])

    for r in rows:
        writer.writerow([r["ip"],r["source"],r["state"],r["rule"],r["time"]])

    return send_file(io.BytesIO(si.getvalue().encode()),
    mimetype="text/csv",
    as_attachment=True,
    download_name="cti_report.csv")

# ---------------------------
# Dashboard
# ---------------------------

@app.route("/")
def index():

    return render_template_string("""
<html>
<head>

<title>RedShark Cyber Threat Intelligence Platform</title>

<link rel="stylesheet" href="https://unpkg.com/leaflet/dist/leaflet.css"/>

<script src="https://unpkg.com/leaflet/dist/leaflet.js"></script>
<script src="https://unpkg.com/leaflet.heat/dist/leaflet-heat.js"></script>

<style>

body{
background:#0f172a;
color:white;
font-family:Arial;
margin:0
}

header{
padding:15px;
font-size:22px;
text-align:center;
color:#ff4444
}

#map{
height:85vh
}

footer{
text-align:center;
font-size:12px;
color:#888;
padding:10px
}

</style>
</head>

<body>

<header>RedShark Cyber Threat Intelligence Platform</header>

<div id="map"></div>

<script>

var map=L.map('map').setView([4.2,102],6)

L.tileLayer(
'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png'
).addTo(map)

var heat=L.heatLayer([],{radius:25}).addTo(map)

var markers=L.layerGroup().addTo(map)

async function load(){

let r=await fetch('/data')

let d=await r.json()

heat.setLatLngs([])

markers.clearLayers()

d.heat_data.forEach(p=>{
heat.addLatLng(p)
})

d.markers.forEach(m=>{
L.marker([m.lat,m.lon]).bindPopup(m.popup).addTo(markers)
})

}

load()

setInterval(load,60000)

</script>

<footer>

Developed and analysed by darkgrid@redshark.my using publicly available sources

</footer>

</body>
</html>
""")

# ---------------------------
# Startup
# ---------------------------

if __name__ == "__main__":

    init_db()
    seed_data()

    threading.Thread(target=feed_loop,daemon=True).start()

    port=int(os.environ.get("PORT",5000))

    app.run(host="0.0.0.0",port=port)