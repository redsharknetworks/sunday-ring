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
from reportlab.platypus import SimpleDocTemplate, Table
from reportlab.lib.pagesizes import letter

app = Flask(__name__)

# -------------------------------
DB_DIR = "data"
DB_PATH = os.path.join(DB_DIR, "cti.db")
if not os.path.exists(DB_DIR):
    os.makedirs(DB_DIR)

MALAYSIA_LOCATIONS = [
    ("Kangar",6.4414,100.1986),("Alor Setar",6.1248,100.3678),("George Town",5.4141,100.3288),
    ("Ipoh",4.5975,101.0901),("Shah Alam",3.0738,101.5183),("Kuala Lumpur",3.1390,101.6869),
    ("Seremban",2.7297,101.9381),("Melaka",2.1896,102.2501),("Johor Bahru",1.4927,103.7414),
    ("Kuantan",3.8168,103.3317),("Kuala Terengganu",5.3302,103.1408),("Kota Bharu",6.1254,102.2386),
    ("Kuching",1.5533,110.3592),("Kota Kinabalu",5.9804,116.0735),("Putrajaya",2.9264,101.6964)
]

OTX_API_KEY = "YOUR_OTX_KEY"
ABUSEIPDB_KEY = "YOUR_ABUSEIPDB_KEY"

# -------------------------------
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS events(
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
    )""")
    conn.commit()
    conn.close()
init_db()

def map_to_ibu_negeri():
    return random.choice(MALAYSIA_LOCATIONS)

# -------------------------------
def fetch_otx():
    headers={"X-OTX-API-KEY":OTX_API_KEY}
    url="https://otx.alienvault.com/api/v1/indicators/IPv4/recent"
    try:
        r=requests.get(url,headers=headers,timeout=10)
        data=r.json().get("results",[])
        events=[]
        for d in data:
            ip=d.get("indicator")
            lat,lon=map_to_ibu_negeri()[1:3]
            events.append({"ip":ip,"source":"OTX","severity":"High","country":"Malaysia",
                           "rule":"OTX","description":d.get("description",""),
                           "lat":lat,"lon":lon,"timestamp":datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
        return events
    except Exception as e:
        print("OTX fetch error:",e)
        return []

def fetch_abuseipdb():
    url="https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum=75"
    headers={"Key":ABUSEIPDB_KEY,"Accept":"application/json"}
    try:
        r=requests.get(url,headers=headers,timeout=10)
        data=r.json().get("data",[])
        events=[]
        for d in data:
            ip=d.get("ipAddress")
            lat,lon=map_to_ibu_negeri()[1:3]
            events.append({"ip":ip,"source":"AbuseIPDB","severity":"High","country":"Malaysia",
                           "rule":"AbuseIPDB","description":"Reported malicious IP",
                           "lat":lat,"lon":lon,"timestamp":datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
        return events
    except Exception as e:
        print("AbuseIPDB fetch error:",e)
        return []

def insert_events(events):
    conn=sqlite3.connect(DB_PATH)
    c=conn.cursor()
    for e in events:
        exist=c.execute("SELECT id FROM events WHERE ip=? AND source=?",(e["ip"],e["source"])).fetchone()
        if exist: continue
        c.execute("INSERT INTO events(ip,source,severity,country,rule,description,lat,lon,timestamp) VALUES (?,?,?,?,?,?,?,?,?)",
                  (e["ip"],e["source"],e["severity"],e["country"],e["rule"],e["description"],e["lat"],e["lon"],e["timestamp"]))
    conn.commit()
    conn.close()

def initial_dummy_load():
    events=[]
    otx_events=fetch_otx()
    abuse_events=fetch_abuseipdb()
    combined=otx_events+abuse_events
    fallback=combined[:10]
    for e in fallback:
        lat,lon=map_to_ibu_negeri()[1:3]
        events.append({"ip":e["ip"],"source":e["source"],"severity":e["severity"],
                       "country":"Malaysia","rule":e["rule"],"description":e.get("description",""),
                       "lat":lat,"lon":lon,"timestamp":datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
    insert_events(events)

initial_dummy_load()

def feed_loop():
    while True:
        events=fetch_otx()+fetch_abuseipdb()
        conn=sqlite3.connect(DB_PATH)
        c=conn.cursor()
        count=c.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        conn.close()
        if count==0:
            initial_dummy_load()
        insert_events(events)
        time.sleep(600)

threading.Thread(target=feed_loop,daemon=True).start()

# -------------------------------
def get_events(limit=500):
    conn=sqlite3.connect(DB_PATH)
    c=conn.cursor()
    rows=c.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?",(limit,)).fetchall()
    conn.close()
    return rows

def get_aggregated_lines(events):
    agg={}
    for e in events:
        if e[3]!="High": continue
        key=(e[1],e[2])
        if key not in agg:
            ibu_lat,ibu_lon=map_to_ibu_negeri()[1:3]
            agg[key]={"lat":e[7],"lon":e[8],"ibu_lat":ibu_lat,"ibu_lon":ibu_lon,"count":0}
        agg[key]["count"]+=1
    return agg.values()

@app.route("/data")
def get_dashboard_data():
    events=get_events()
    heat_data=[]
    markers=[]
    severity_counts={"High":0,"Medium":0,"Low":0}
    timeline={}
    table_rows=[]
    for e in events:
        severity_counts[e[3]]+=1
        hour=e[9][:13]
        timeline[hour]=timeline.get(hour,0)+1
        table_rows.append({"ip":e[1],"source":e[2],"severity":e[3],
                           "country":e[4],"rule":e[5],"description":e[6],
                           "timestamp":e[9]})
        if e[3]=="High": heat_data.append([e[7],e[8],3])
        markers.append({"lat":e[7],"lon":e[8],"popup":f"IP: {e[1]}<br>Severity: {e[3]}<br>Rule:{e[5]}"})
    lines=[]
    for l in get_aggregated_lines(events):
        lines.append({"from":[l["lat"],l["lon"]],"to":[l["ibu_lat"],l["ibu_lon"]],"count":l["count"]})
    return jsonify({"heat_data":heat_data,"markers":markers,"lines":lines,
                    "severity_counts":severity_counts,"timeline":timeline,"table_rows":table_rows})

# -------------------------------
@app.route("/download/csv")
def download_csv():
    events=get_events()
    si=io.StringIO()
    cw=csv.writer(si)
    cw.writerow(["IP","Source","Severity","Country","Rule","Description","Lat","Lon","Timestamp"])
    for e in events:
        cw.writerow([e[1],e[2],e[3],e[4],e[5],e[6],e[7],e[8],e[9]])
    return send_file(io.BytesIO(si.getvalue().encode()),mimetype="text/csv",as_attachment=True,download_name="cti_report.csv")

@app.route("/download/json")
def download_json():
    import json
    events=get_events()
    data=[{"ip":e[1],"source":e[2],"severity":e[3],"country":e[4],
           "rule":e[5],"description":e[6],"lat":e[7],"lon":e[8],"timestamp":e[9]} for e in events]
    return send_file(io.BytesIO(json.dumps(data,indent=2).encode()),mimetype="application/json",as_attachment=True,download_name="cti_report.json")

@app.route("/download/pdf")
def download_pdf():
    events=get_events()
    buffer=io.BytesIO()
    doc=SimpleDocTemplate(buffer,pagesize=letter)
    data=[["IP","Source","Severity","Country","Rule","Description","Lat","Lon","Timestamp"]]
    for e in events: data.append([e[1],e[2],e[3],e[4],e[5],e[6],e[7],e[8],e[9]])
    table=Table(data)
    doc.build([table])
    buffer.seek(0)
    return send_file(buffer,mimetype="application/pdf",as_attachment=True,download_name="cti_report.pdf")

@app.route("/download/ids")
def download_ids():
    events=get_events()
    si=io.StringIO()
    for e in events:
        if e[3]=="High":
            rule=f'alert ip any any -> {e[1]} any (msg:"CTI High Severity {e[5]}"; sid:{random.randint(1000000,9999999)}; rev:1;)'
            si.write(rule+"\n")
    return send_file(io.BytesIO(si.getvalue().encode()),mimetype="text/plain",as_attachment=True,download_name="cti_ids.rules")

# -------------------------------
@app.route("/")
def dashboard():
    return render_template_string("""
<!DOCTYPE html>
<html>
<head>
<title>RedShark Cyber Threat Intelligence Platform</title>
<meta charset="utf-8" />
<link rel="stylesheet" href="https://unpkg.com/leaflet/dist/leaflet.css"/>
<script src="https://unpkg.com/leaflet/dist/leaflet.js"></script>
<script src="https://unpkg.com/leaflet.heat/dist/leaflet-heat.js"></script>
<style>
html,body,#map{height:100%;margin:0;padding:0;background:#1c1c1c;color:#eee;}
.leaflet-popup-content{color:#000;}
</style>
</head>
<body>
<h2 style="text-align:center;color:#ff4444;">RedShark Cyber Threat Intelligence Platform</h2>
<div id="map"></div>
<script>
var map=L.map('map').setView([4.2105,101.9758],6);
L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',{attribution:'',subdomains:'abcd',maxZoom:19}).addTo(map);
var heat=L.heatLayer([], {radius:25,blur:15,maxZoom:17}).addTo(map);
var markerLayer=L.layerGroup().addTo(map);
var lineLayer=L.layerGroup().addTo(map);
var ibuMarkersLayer=L.layerGroup().addTo(map);

async function fetchData(){
    const res=await fetch("/data");
    const data=await res.json();
    heat.setLatLngs([]);
    markerLayer.clearLayers();
    lineLayer.clearLayers();
    ibuMarkersLayer.clearLayers();
    data.heat_data.forEach(p=>heat.addLatLng(p));
    data.markers.forEach(m=>L.marker([m.lat,m.lon]).bindPopup(m.popup).addTo(markerLayer));
    let ibuMarkers={};
    data.lines.forEach(line=>{
        let poly=L.polyline([line.from,line.to],{color:'red',weight:Math.min(line.count*2,8),opacity:0.7,smoothFactor:1}).addTo(lineLayer);
        let key=line.to.join(",");
        if(!ibuMarkers[key]){
            let marker=L.circleMarker(line.to,{radius:4+Math.min(line.count,6),color:'red',fillColor:'red',fillOpacity:0.8}).bindPopup(`Attacks: ${line.count}`);
            marker.addTo(ibuMarkersLayer);
            ibuMarkers[key]=marker;
        }
    });
}
fetchData();
setInterval(fetchData,60000);
</script>
<footer style="text-align:center;color:#888;padding:10px;">Developed and analysed by darkgrid@redshark.my using publicly available sources</footer>
</body>
</html>
""")

if __name__=="__main__":
    app.run(host="0.0.0.0",port=5000,debug=True)