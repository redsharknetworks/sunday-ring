import os
import sqlite3
import random
import requests
import threading
import time
import ipaddress
from datetime import datetime
from flask import Flask, render_template_string, jsonify, send_file
import io
import csv
from reportlab.platypus import SimpleDocTemplate, Table
from reportlab.lib.pagesizes import letter

app = Flask(__name__)

DB_DIR = "data"
DB_PATH = os.path.join(DB_DIR, "cti.db")
if not os.path.exists(DB_DIR):
    os.makedirs(DB_DIR)

MALAYSIA_LOCATIONS = [
    ("Kuala Lumpur", 3.1390, 101.6869),
    ("George Town", 5.4141, 100.3288),
    ("Ipoh", 4.5975, 101.0901),
    ("Shah Alam", 3.0738, 101.5183),
    ("Johor Bahru", 1.4927, 103.7414),
    ("Melaka", 2.1896, 102.2501),
]

SEVERITY_WEIGHT = {"High": 3, "Medium": 2, "Low": 1}

IOC_TEST_IPS = [
    "103.146.203.11",
    "222.246.32.12",
    "112.134.139.180",
    "103.163.13.144",
    "49.156.41.98",
    "117.216.1.7",
    "119.200.32.11"
]

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

def get_events(limit=500):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    rows = c.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return rows

# -------------------------------
def insert_real_ioc_dummy():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    for ip in IOC_TEST_IPS:
        exist = c.execute("SELECT id FROM events WHERE ip=?", (ip,)).fetchone()
        if exist: continue
        loc = random.choice(MALAYSIA_LOCATIONS)
        c.execute("""
        INSERT INTO events(ip,source,severity,country,rule,description,lat,lon,timestamp)
        VALUES(?,?,?,?,?,?,?,?,?)
        """,(ip,"Real IOC Test","High","Malaysia",f"RSK-{random.randint(1000,9999)}","Imported real IOC",loc[1],loc[2],datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()

# -------------------------------
init_db()
insert_real_ioc_dummy()

# -------------------------------
@app.route("/data")
def get_dashboard_data():
    events = get_events()
    heat_data=[]
    markers=[]
    severity_counts={"High":0,"Medium":0,"Low":0}
    timeline={}
    table_rows=[]
    for e in events:
        severity_counts[e[3]] +=1
        hour = e[9][:13]
        timeline[hour] = timeline.get(hour,0)+1
        table_rows.append({
            "ip": e[1],"source": e[2],"severity": e[3],
            "country": e[4],"rule": e[5],"description": e[6],
            "timestamp": e[9]
        })
        # Only High for heatmap
        if e[3]=="High":
            heat_data.append([e[7], e[8], 3])
        markers.append({"lat": e[7], "lon": e[8], "popup": f"IP: {e[1]}<br>Severity: {e[3]}<br>Rule:{e[5]}"})
    return jsonify({
        "heat_data": heat_data,
        "markers": markers,
        "severity_counts": severity_counts,
        "timeline": timeline,
        "table_rows": table_rows
    })

# -------------------------------
# Downloads: CSV, JSON, PDF, IDS rules
@app.route("/download/csv")
def download_csv():
    events = get_events()
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(["IP","Source","Severity","Country","Rule","Description","Lat","Lon","Timestamp"])
    for e in events:
        cw.writerow([e[1], e[2], e[3], e[4], e[5], e[6], e[7], e[8], e[9]])
    return send_file(io.BytesIO(si.getvalue().encode()), mimetype="text/csv", as_attachment=True, download_name="cti_report.csv")

@app.route("/download/json")
def download_json():
    import json
    events = get_events()
    data = [{"ip": e[1], "source": e[2], "severity": e[3], "country": e[4], "rule": e[5], "description": e[6], "lat": e[7], "lon": e[8], "timestamp": e[9]} for e in events]
    return send_file(io.BytesIO(json.dumps(data, indent=2).encode()), mimetype="application/json", as_attachment=True, download_name="cti_report.json")

@app.route("/download/pdf")
def download_pdf():
    events = get_events()
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    data = [["IP","Source","Severity","Country","Rule","Description","Lat","Lon","Timestamp"]]
    for e in events:
        data.append([e[1], e[2], e[3], e[4], e[5], e[6], e[7], e[8], e[9]])
    table = Table(data)
    doc.build([table])
    buffer.seek(0)
    return send_file(buffer, mimetype="application/pdf", as_attachment=True, download_name="cti_report.pdf")

@app.route("/download/ids")
def download_ids():
    events = get_events()
    si = io.StringIO()
    for e in events:
        if e[3]=="High":
            rule = f'alert ip any any -> {e[1]} any (msg:"CTI High Severity {e[5]}"; sid:{random.randint(1000000,9999999)}; rev:1;)'
            si.write(rule+"\n")
    return send_file(io.BytesIO(si.getvalue().encode()), mimetype="text/plain", as_attachment=True, download_name="cti_ids.rules")

# -------------------------------
@app.route("/")
def dashboard():
    return render_template_string("""
<html>
<head>
<title>RedShark Cyber Threat Intelligence Platform</title>
<link rel="stylesheet" href="https://unpkg.com/leaflet/dist/leaflet.css"/>
<link rel="stylesheet" href="https://unpkg.com/leaflet.markercluster/dist/MarkerCluster.css"/>
<link rel="stylesheet" href="https://unpkg.com/leaflet.markercluster/dist/MarkerCluster.Default.css"/>
<script src="https://unpkg.com/leaflet/dist/leaflet.js"></script>
<script src="https://unpkg.com/leaflet.heat/dist/leaflet-heat.js"></script>
<script src="https://unpkg.com/leaflet.markercluster/dist/leaflet.markercluster.js"></script>
<script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
<style>
body{margin:0;padding:0;font-family:Arial;background:#0f1720;color:#e5e7eb;}
#map{height:400px;} .chart{flex:1 1 45%;margin:10px;background:#111827;padding:10px;border-radius:8px;}
.header{font-size:28px;padding:15px;background:#111827;}
.footer{text-align:center;font-size:12px;color:#9ca3af;margin-top:20px;}
#charts{display:flex;flex-wrap:wrap;}
table{width:100%; border-collapse: collapse; background:#111827; color:#e5e7eb;}
th, td{padding:6px; border:1px solid #1f2937;} thead{background:#1f2937;}
#table_container{max-height:300px; overflow:auto; margin:10px;}
.button-group{margin:10px;}
.button-group a{margin-right:10px;padding:6px 10px;background:#1f2937;color:#e5e7eb;border-radius:5px;text-decoration:none;}
</style>
</head>
<body>
<div class="header">RedShark Cyber Threat Intelligence Platform</div>

<div class="button-group">
<a href="/download/csv">Download CSV</a>
<a href="/download/json">Download JSON</a>
<a href="/download/pdf">Download PDF</a>
<a href="/download/ids">Download IDS Rules</a>
</div>

<div id="map"></div>
<div id="charts">
<div class="chart" id="severity_chart"></div>
<div class="chart" id="timeline_chart"></div>
</div>

<div id="table_container"><table><thead><tr>
<th>IP</th><th>Source</th><th>Severity</th><th>Country</th><th>Rule</th><th>Description</th><th>Timestamp</th>
</tr></thead><tbody id="table_body"></tbody></table></div>

<div class="footer">
Developed by darkgrid@redshark.my using publicly available sources
</div>

<script>
var map = L.map('map').setView([4.2105,101.9758],6);
L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',{maxZoom:19}).addTo(map);
var heat = L.heatLayer([], {radius:25, blur:15, maxZoom:10, max:9}).addTo(map);
var markers = L.markerClusterGroup(); map.addLayer(markers);

function fetchData(){
    fetch("/data").then(r=>r.json()).then(d=>{
        heat.setLatLngs(d.heat_data);
        markers.clearLayers();
        d.markers.forEach(function(m){
            if(m.popup.includes("High")){
                var icon = L.circleMarker([m.lat,m.lon], {radius:6,fillColor:"red",color:"red",weight:1,opacity:1,fillOpacity:0.8});
                icon.bindPopup(m.popup); markers.addLayer(icon);
            }
        });
        // Charts
        Plotly.newPlot('severity_chart',[{x:Object.keys(d.severity_counts),y:Object.values(d.severity_counts),type:'bar',marker:{color:['red','orange','cyan']}}], {title:'Severity Distribution',paper_bgcolor:'#111827',plot_bgcolor:'#111827',font:{color:'#e5e7eb'}});
        Plotly.newPlot('timeline_chart',[{x:Object.keys(d.timeline),y:Object.values(d.timeline),type:'scatter'}], {title:'Threat Timeline',paper_bgcolor:'#111827',plot_bgcolor:'#111827',font:{color:'#e5e7eb'}});
        // Table
        var tbody = document.getElementById("table_body"); tbody.innerHTML="";
        d.table_rows.forEach(function(r){tbody.innerHTML+=`<tr><td>${r.ip}</td><td>${r.source}</td><td>${r.severity}</td><td>${r.country}</td><td>${r.rule}</td><td>${r.description}</td><td>${r.timestamp}</td></tr>`;});
    });
}
fetchData(); setInterval(fetchData,60000);
</script>
</body>
</html>
""")

if __name__=="__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)