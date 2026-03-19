import os
import io
import csv
import json
import zipfile
import logging
import random
from datetime import datetime, timedelta

import sqlite3
import requests
from flask import Flask, jsonify, render_template_string, send_file

# ---------------- CONFIG ---------------- #
app = Flask(__name__)
DB_FILE = "redshark.db"

OTX_KEY = "aa94a69a780ed789016bb72d51d9b58b823eb1e6173f6fffc34530693dacb03b"
ABUSEIPDB_KEY = "08cf00dc25d22cbd0f45ec5ebb87cb61e93c22349a6eb14544a100"

logging.basicConfig(level=logging.INFO)

LOCATIONS = [
    ("Kangar",6.44,100.19),("Alor Setar",6.12,100.36),("George Town",5.41,100.32),
    ("Ipoh",4.59,101.09),("Kuala Lumpur",3.13,101.68),("Shah Alam",3.07,101.51),
    ("Seremban",2.72,101.93),("Melaka",2.18,102.25),("Johor Bahru",1.49,103.74)
]

MITRE_MAP = [
    "T1046 Network Discovery","T1059 Command Execution","T1566 Phishing",
    "T1071 C2 Communication","T1105 Data Exfiltration","T1190 Exploit Public Facing App"
]

# ---------------- DATABASE ---------------- #
def init_db():
    with sqlite3.connect(DB_FILE) as conn:
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

# ---------------- HELPER FUNCTIONS ---------------- #
def detect_type(indicator):
    import re
    if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", indicator):
        return "IP"
    if re.match(r"^[a-fA-F0-9]{32,128}$", indicator):
        return "Hash"
    return "Domain"

def save_iocs(iocs, source="OTX"):
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        for ind in iocs:
            typ = detect_type(ind)
            loc = random.choice(LOCATIONS)
            sev = "Critical" if typ=="IP" else "High"
            mitre = random.choice(MITRE_MAP)
            now = datetime.utcnow().isoformat()
            try:
                c.execute("""
                INSERT OR IGNORE INTO indicators(indicator,type,source,severity,mitre,score,country,lat,lon,first_seen,last_seen)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)
                """, (ind, typ, source, sev, mitre, 95 if sev=="Critical" else 80, loc[0], loc[1], loc[2], now, now))
            except:
                pass
        conn.commit()

# ---------------- FETCH FEEDS ---------------- #
def fetch_otx():
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
    headers = {"X-OTX-API-KEY": OTX_KEY}
    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            return [i["indicator"] for pulse in r.json().get("results", []) for i in pulse.get("indicators", [])]
    except:
        logging.warning("OTX fetch failed")
    return []

def fetch_abuseipdb():
    url = "https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum=70&limit=50"
    headers = {"Key": ABUSEIPDB_KEY,"Accept":"application/json"}
    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            return [item["ipAddress"] for item in r.json().get("data",[])]
    except:
        logging.warning("AbuseIPDB fetch failed")
    return []

# ---------------- ROUTES ---------------- #
@app.route("/update_feeds")
def update_feeds():
    otx_iocs = fetch_otx()
    abuse_iocs = fetch_abuseipdb()
    save_iocs(otx_iocs, "OTX")
    save_iocs(abuse_iocs, "AbuseIPDB")
    return jsonify({"status":"ok","otx":len(otx_iocs),"abuse":len(abuse_iocs)})

@app.route("/api/data")
def api_data():
    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM indicators ORDER BY last_seen DESC LIMIT 500")
        rows = [dict(r) for r in c.fetchall()]
    return jsonify(rows)

@app.route("/")
def dashboard():
    malaysia_time = (datetime.utcnow() + timedelta(hours=8)).strftime("%Y-%m-%d %H:%M:%S")
    return render_template_string(DASHBOARD_HTML, time=malaysia_time)

# ---------------- EXPORTS ---------------- #
@app.route("/export/json")
def export_json():
    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM indicators")
        rows = [dict(r) for r in c.fetchall()]
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer,'w') as zf:
        zf.writestr("redshark_cti.json", json.dumps(rows, indent=2))
    zip_buffer.seek(0)
    return send_file(zip_buffer, as_attachment=True, download_name="redshark_cti_json.zip")

@app.route("/export/csv")
def export_csv():
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM indicators")
        rows = c.fetchall()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id","indicator","type","source","severity","mitre","score","country","lat","lon","first_seen","last_seen"])
    writer.writerows(rows)
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer,'w') as zf:
        zf.writestr("redshark_cti.csv", output.getvalue())
    zip_buffer.seek(0)
    return send_file(zip_buffer, as_attachment=True, download_name="redshark_cti_csv.zip")

@app.route("/export/ids")
def export_ids():
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("SELECT indicator,type,severity FROM indicators")
        rows = c.fetchall()
    zip_buffer = io.BytesIO()
    rules=""
    sid=1000000
    for ind,typ,sev in rows:
        if typ=="IP":
            rules+=f'alert ip any any -> {ind} any (msg:"RedShark {sev} threat"; sid:{sid}; rev:1;)\n'
        elif typ=="Domain":
            rules+=f'alert tcp any any -> any 80 (msg:"RedShark {sev} Domain {ind}"; content:"{ind}"; sid:{sid}; rev:1;)\n'
        else:
            rules+=f'# Hash {ind} severity {sev} (sid:{sid})\n'
        sid+=1
    with zipfile.ZipFile(zip_buffer,'w') as zf:
        zf.writestr("redshark_ids.rules", rules)
    zip_buffer.seek(0)
    return send_file(zip_buffer, as_attachment=True, download_name="redshark_ids.zip")

# ---------------- DASHBOARD HTML ---------------- #
DASHBOARD_HTML = """<!DOCTYPE html>
<html>
<head>
<title>RedShark Enterprise SOC</title>
<link rel="stylesheet" href="https://cdn.datatables.net/1.13.6/css/jquery.dataTables.min.css">
<script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
<script src="https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js"></script>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
body{background:#020617;color:white;font-family:Arial;margin:0;padding:0}
h1{text-align:center;color:#38bdf8;margin:20px 0;}
.ticker{padding:10px;overflow-x:auto;white-space:nowrap;border-top:1px solid #334155;border-bottom:1px solid #334155;}
#dashboard-container{max-width:1200px;margin:0 auto;}
#map{height:400px;width:100%;border-radius:10px;margin-bottom:20px;}
canvas{width:100% !important;height:300px !important;background:#111827;padding:10px;border-radius:10px;}
.low{color:#22c55e;}.medium{color:#facc15;}.high{color:orange;}.critical{color:red;}
.heat-critical{animation:blink 2s infinite;}.heat-high{animation:blink 2s infinite;}
@keyframes blink{0%{opacity:0.6;}50%{opacity:1;}100%{opacity:0.6;}}
button{margin:5px;padding:10px 15px;background:#38bdf8;color:#000;border:none;border-radius:5px;cursor:pointer;font-weight:bold;}
button:hover{background:#0ea5e9;color:#fff;}
#cti{width:100% !important;}
</style>
</head>
<body>
<h1>RedShark Enterprise SOC Dashboard</h1>
<div id="dashboard-container">
<div class="ticker" id="ticker"></div>
<div id="map"></div>
<div class="chart-container"><canvas id="mitre"></canvas></div>
<div class="chart-container"><canvas id="severity"></canvas></div>
<div class="chart-container"><canvas id="timeline"></canvas></div>
<table id="cti" class="display">
<thead>
<tr><th>Indicator</th><th>Type</th><th>Source</th><th>Severity</th>
<th>MITRE</th><th>Score</th><th>Country</th><th>Last Seen</th></tr>
</thead>
<tbody></tbody>
</table>
<div style="text-align:center;margin:20px;">
<button onclick="window.location='/export/json'">JSON</button>
<button onclick="window.location='/export/csv'">CSV</button>
<button onclick="window.location='/export/ids'">IDS RULES</button>
<button onclick="window.location='/update_feeds'">Update Feeds</button>
</div>
<script>
var map=L.map('map').setView([4.5,102],6);
L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png').addTo(map);
var markers=[],mitreChart,severityChart,timelineChart;

function fetchData(){
    $.getJSON("/api/data",function(points){
        renderTicker(points);
        renderTable(points);
        renderMap(points);
        renderCharts(points);
    });
}

function renderTicker(points){
    var html=""; points.slice(0,10).forEach(p=>{
        html+=`🚨 <span class="${p.severity.toLowerCase()}">${p.severity}</span> ${p.indicator} via ${p.source} &nbsp;&nbsp;`;
    });
    $("#ticker").html(html);
}

function renderTable(points){
    var table=$("#cti").DataTable(); table.clear();
    points.forEach(p=>{
        var sev_color=(p.severity=="High")?"orange":(p.severity=="Critical")?"red":(p.severity=="Medium")?"#facc15":"#22c55e";
        var cls=(p.severity=="Critical")?"heat-critical":(p.severity=="High")?"heat-high":"";
        table.row.add([
            p.indicator,p.type,p.source,
            `<span style="color:${sev_color};font-weight:bold" class="${cls}">${p.severity}</span>`,
            p.mitre,p.score,p.country,p.last_seen
        ]);
    }); table.draw();
}

function renderMap(points){
    markers.forEach(m=>map.removeLayer(m)); markers=[];
    points.forEach(p=>{
        var options={radius:6,color:"green",fillOpacity:0.6}; var cls="";
        if(p.severity=="Critical"){options.color="red";options.radius=8;cls="heat-critical";}
        else if(p.severity=="High"){options.color="orange";options.radius=7;cls="heat-high";}
        var marker=L.circleMarker([p.lat,p.lon],options).addTo(map);
        if(cls && marker._path){marker._path.classList.add(cls);}
        marker.bindPopup(p.indicator+"<br>"+p.type+" — "+p.severity);
        markers.push(marker);
    });
}

function renderCharts(points){
    // MITRE
    var mitreLabels=points.map(p=>p.mitre); var mitreCounts={}; mitreLabels.forEach(m=>mitreCounts[m]=(mitreCounts[m]||0)+1);
    if(mitreChart) mitreChart.destroy();
    var ctx_m=document.getElementById('mitre').getContext('2d');
    mitreChart=new Chart(ctx_m,{type:'bar',data:{labels:Object.keys(mitreCounts),datasets:[{label:'MITRE Count',data:Object.values(mitreCounts),backgroundColor:'#38bdf8'}]},options:{plugins:{legend:{display:false}},scales:{y:{ticks:{color:'white'}},x:{ticks:{color:'white'}}}}});

    // Severity
    var sevCounts={"Low":0,"Medium":0,"High":0,"Critical":0}; points.forEach(p=>sevCounts[p.severity]++);
    if(severityChart) severityChart.destroy();
    var ctx_s=document.getElementById('severity').getContext('2d');
    severityChart=new Chart(ctx_s,{type:'bar',data:{labels:Object.keys(sevCounts),datasets:[{label:'Severity',data:Object.values(sevCounts),backgroundColor:['green','#facc15','orange','red']} ]},options:{plugins:{legend:{display:false}},scales:{y:{ticks:{color:'white'}},x:{ticks:{color:'white'}}}}});

    // Timeline
    var timeline={}; points.forEach(p=>{var t=p.last_seen.substring(0,13); timeline[t]=(timeline[t]||0)+1;});
    if(timelineChart) timelineChart.destroy();
    var ctx_t=document.getElementById('timeline').getContext('2d');
    timelineChart=new Chart(ctx_t,{type:'line',data:{labels:Object.keys(timeline),datasets:[{label:'Events',data:Object.values(timeline),borderColor:'#38bdf8',fill:false}]},options:{plugins:{legend:{display:true}},scales:{y:{ticks:{color:'white'}},x:{ticks:{color:'white'}}}}});
}

$(document).ready(function(){
    $('#cti').DataTable({pageLength:50});
    fetchData(); setInterval(fetchData,60000);
});
</script>
</body></html>
"""

# ---------------- RUN ---------------- #
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)