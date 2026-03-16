import io
import csv
import json
import zipfile
import time
import threading
import logging
import os
import re
import random
from datetime import datetime, timedelta

import sqlite3
import requests
from flask import Flask, render_template_string, jsonify, send_file
from reportlab.platypus import SimpleDocTemplate, Table
from reportlab.lib.pagesizes import letter

# ---------------- CONFIG ---------------- #

app = Flask(__name__)

# Render/Railway safe database
DB_FILE = "/tmp/redshark.db"

# Threat intelligence keys
OTX_KEY = "aa94a69a780ed789016bb72d51d9b58b823eb1e6173f6fffc34530693dacb03b"
ABUSEIPDB_KEY = "08cf00dc25d22cbd0f45ec5ebb87cb61e289533bd33bceb9b93c22349a6eb8674d52aaf14544a100"

logging.basicConfig(level=logging.INFO)

# Malaysia monitoring points
LOCATIONS = [
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

MITRE_MAP = [
"T1046 Network Discovery",
"T1059 Command Execution",
"T1566 Phishing",
"T1071 C2 Communication",
"T1105 Data Exfiltration",
"T1190 Exploit Public Facing App"
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
        )
        """)

        conn.commit()

init_db()

# ---------------- IOC TYPE DETECTION ---------------- #

def detect_type(ind):

    ip_pattern = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
    md5_pattern = re.compile(r"^[a-fA-F0-9]{32}$")
    sha1_pattern = re.compile(r"^[a-fA-F0-9]{40}$")
    sha256_pattern = re.compile(r"^[a-fA-F0-9]{64}$")

    if ip_pattern.match(ind):
        return "IP"

    if md5_pattern.match(ind):
        return "MD5"

    if sha1_pattern.match(ind):
        return "SHA1"

    if sha256_pattern.match(ind):
        return "SHA256"

    if ind.startswith("http"):
        return "URL"

    return "Domain"

# ---------------- THREAT SCORING ---------------- #

def calculate_score(source,severity):

    base=50

    if source=="AbuseIPDB":
        base+=25

    if severity=="Critical":
        base+=25
    elif severity=="High":
        base+=15

    return min(base,100)

# ---------------- SAVE IOC ---------------- #

def save_iocs(iocs):

    with sqlite3.connect(DB_FILE) as conn:

        c=conn.cursor()

        for i in iocs:

            try:

                c.execute("""
                INSERT OR IGNORE INTO indicators
                (indicator,type,source,severity,mitre,score,country,lat,lon,first_seen,last_seen)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)
                """,(
                    i["indicator"],
                    i["type"],
                    i["source"],
                    i["severity"],
                    i["mitre"],
                    i["score"],
                    i["country"],
                    i["lat"],
                    i["lon"],
                    i["first_seen"],
                    i["last_seen"]
                ))

            except Exception as e:
                logging.error(e)

        conn.commit()

# ---------------- FETCH OTX ---------------- #

def fetch_otx():

    url="https://otx.alienvault.com/api/v1/pulses/subscribed"
    headers={"X-OTX-API-KEY":OTX_KEY}

    iocs=[]

    try:

        r=requests.get(url,headers=headers,timeout=20)

        if r.status_code==200:

            for pulse in r.json().get("results",[]):

                for ind in pulse.get("indicators",[]):

                    indicator=ind["indicator"]

                    typ=detect_type(indicator)

                    sev="Critical" if typ=="IP" else "High"

                    loc=random.choice(LOCATIONS)

                    iocs.append({

                        "indicator":indicator,
                        "type":typ,
                        "source":"OTX",
                        "severity":sev,
                        "mitre":random.choice(MITRE_MAP),
                        "score":calculate_score("OTX",sev),
                        "country":loc[0],
                        "lat":loc[1],
                        "lon":loc[2],
                        "first_seen":datetime.utcnow().isoformat(),
                        "last_seen":datetime.utcnow().isoformat()

                    })

    except Exception as e:
        logging.error(e)

    return iocs

# ---------------- FETCH ABUSEIPDB ---------------- #

def fetch_abuse():

    url="https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum=70&limit=100"

    headers={
        "Key":ABUSEIPDB_KEY,
        "Accept":"application/json"
    }

    iocs=[]

    try:

        r=requests.get(url,headers=headers,timeout=20)

        if r.status_code==200:

            for ip in r.json().get("data",[]):

                loc=random.choice(LOCATIONS)

                sev="Critical"

                iocs.append({

                    "indicator":ip["ipAddress"],
                    "type":"IP",
                    "source":"AbuseIPDB",
                    "severity":sev,
                    "mitre":random.choice(MITRE_MAP),
                    "score":calculate_score("AbuseIPDB",sev),
                    "country":loc[0],
                    "lat":loc[1],
                    "lon":loc[2],
                    "first_seen":datetime.utcnow().isoformat(),
                    "last_seen":datetime.utcnow().isoformat()

                })

    except Exception as e:
        logging.error(e)

    return iocs

# ---------------- THREAT ENGINE ---------------- #

def threat_engine():

    while True:

        logging.info("Fetching threat intelligence feeds")

        iocs = fetch_otx() + fetch_abuse()

        if iocs:

            save_iocs(iocs)

            logging.info(f"{len(iocs)} indicators saved")

        else:

            logging.info("No IOC fetched")

        time.sleep(600)

# ---------------- SOC EVENT SUMMARY ---------------- #

def soc_events():

    with sqlite3.connect(DB_FILE) as conn:

        c=conn.cursor()

        c.execute("""
        SELECT indicator,severity,source,country
        FROM indicators
        ORDER BY last_seen DESC
        LIMIT 10
        """)

        rows=c.fetchall()

    alerts=[]

    for r in rows:

        alerts.append(
        f"🚨 {r[1]} threat {r[0]} detected via {r[2]} in {r[3]}"
        )

    return alerts

# ---------------- DASHBOARD HTML ---------------- #

DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>

<title>RedShark Cyber SOC</title>

<link rel="stylesheet" href="https://cdn.datatables.net/1.13.6/css/jquery.dataTables.min.css">

<script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>

<script src="https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js"></script>

<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>

<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>

<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

<style>

body{
background:#020617;
color:white;
font-family:Arial;
margin:0;
padding:0
}

h1{
text-align:center;
color:#38bdf8;
margin:20px
}

.container{
width:95%;
margin:auto
}

.panel{
background:#111827;
border-radius:8px;
padding:15px;
margin-bottom:20px
}

#map{
height:420px
}

.ticker{
overflow:hidden;
white-space:nowrap;
border-top:1px solid #333;
border-bottom:1px solid #333;
padding:10px;
background:#020617
}

.ticker span{
display:inline-block;
padding-right:80px
}

.critical{
color:red;
animation:blink 2s infinite
}

.high{
color:orange;
animation:blink 2s infinite
}

.medium{color:#facc15}
.low{color:#22c55e}

@keyframes blink{
0%{opacity:0.5}
50%{opacity:1}
100%{opacity:0.5}
}

.footer{
text-align:center;
font-size:12px;
color:#aaa;
margin-top:30px
}

button{
padding:10px 15px;
margin:5px;
border:none;
background:#38bdf8;
border-radius:5px;
font-weight:bold
}

button:hover{
background:#0ea5e9;
color:white
}

</style>
</head>

<body>

<h1>RedShark Cyber SOC Dashboard</h1>

<div class="container">

<div class="panel">
<b>Live SOC Threat Feed</b>
<div class="ticker" id="ticker"></div>
</div>

<div class="panel">
<b>Malaysia Cyber Attack Map</b>
<div id="map"></div>
</div>

<div class="panel">
<canvas id="mitreChart"></canvas>
</div>

<div class="panel">
<canvas id="severityChart"></canvas>
</div>

<div class="panel">
<canvas id="timelineChart"></canvas>
</div>

<div class="panel">

<table id="iocTable" class="display">

<thead>
<tr>
<th>Indicator</th>
<th>Type</th>
<th>Source</th>
<th>Severity</th>
<th>MITRE</th>
<th>Score</th>
<th>Country</th>
<th>Last Seen</th>
</tr>
</thead>

<tbody></tbody>

</table>

</div>

<div style="text-align:center">

<button onclick="window.location='/export/json'">JSON</button>
<button onclick="window.location='/export/csv'">CSV</button>
<button onclick="window.location='/export/pdf'">PDF</button>
<button onclick="window.location='/export/ids'">IDS RULES</button>

</div>

<div class="footer">
Developed and analysed by darkgrid@redshark.my using publicly available sources
</div>

</div>

<script>

var map=L.map('map').setView([4.5,102],6)

L.tileLayer(
'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png'
).addTo(map)

var markers=[]
var mitreChart
var severityChart
var timelineChart

function loadData(){

$.getJSON("/api/data",function(data){

renderTicker(data)
renderTable(data)
renderMap(data)
renderCharts(data)

})

}

function renderTicker(data){

var html=""

data.slice(0,10).forEach(d=>{

html+=`<span class="${d.severity.toLowerCase()}">
🚨 ${d.severity} ${d.indicator} via ${d.source}
</span>`

})

$("#ticker").html(html)

}

function renderTable(data){

var table=$("#iocTable").DataTable()

table.clear()

data.forEach(d=>{

var cls=d.severity.toLowerCase()

table.row.add([
d.indicator,
d.type,
d.source,
`<span class="${cls}">${d.severity}</span>`,
d.mitre,
d.score,
d.country,
d.last_seen
])

})

table.draw()

}

function renderMap(data){

markers.forEach(m=>map.removeLayer(m))
markers=[]

data.forEach(d=>{

var color="green"

if(d.severity=="High")color="orange"
if(d.severity=="Critical")color="red"

var marker=L.circleMarker([d.lat,d.lon],{
radius:6,
color:color,
fillOpacity:0.7
}).addTo(map)

marker.bindPopup(
"<b>"+d.indicator+"</b><br>"+
d.type+"<br>"+
d.severity+"<br>"+
d.source
)

markers.push(marker)

})

}

function renderCharts(data){

var mitreCounts={}

data.forEach(d=>{
mitreCounts[d.mitre]=(mitreCounts[d.mitre]||0)+1
})

var ctx1=document.getElementById("mitreChart")

if(mitreChart)mitreChart.destroy()

mitreChart=new Chart(ctx1,{
type:"bar",
data:{
labels:Object.keys(mitreCounts),
datasets:[{
label:"MITRE ATT&CK",
data:Object.values(mitreCounts),
backgroundColor:"#38bdf8"
}]
}
})

var sev={"Low":0,"Medium":0,"High":0,"Critical":0}

data.forEach(d=>{
sev[d.severity]++
})

var ctx2=document.getElementById("severityChart")

if(severityChart)severityChart.destroy()

severityChart=new Chart(ctx2,{
type:"bar",
data:{
labels:Object.keys(sev),
datasets:[{
label:"Severity",
data:Object.values(sev),
backgroundColor:["green","#facc15","orange","red"]
}]
}
})

var timeline={}

data.forEach(d=>{
var t=d.last_seen.substring(0,13)
timeline[t]=(timeline[t]||0)+1
})

var ctx3=document.getElementById("timelineChart")

if(timelineChart)timelineChart.destroy()

timelineChart=new Chart(ctx3,{
type:"line",
data:{
labels:Object.keys(timeline),
datasets:[{
label:"Threat Timeline",
data:Object.values(timeline),
borderColor:"#38bdf8"
}]
}
})

}

$(document).ready(function(){

$('#iocTable').DataTable({pageLength:50})

loadData()

setInterval(loadData,60000)

})

</script>

</body>
</html>
"""

# ---------------- API ROUTES ---------------- #

@app.route("/api/data")
def api_data():
    """Return last 500 indicators as JSON"""
    with sqlite3.connect(DB_FILE, check_same_thread=False) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT indicator,type,source,severity,mitre,score,country,lat,lon,last_seen FROM indicators ORDER BY last_seen DESC LIMIT 500")
        rows = [dict(r) for r in c.fetchall()]
    return jsonify(rows)

@app.route("/")
def dashboard():
    malaysia_time = (datetime.utcnow()+timedelta(hours=8)).strftime("%Y-%m-%d %H:%M:%S")
    return render_template_string(DASHBOARD_HTML, time=malaysia_time)

@app.route("/health")
def health():
    return jsonify({"status":"ok","time":datetime.utcnow().isoformat()})

# ---------------- EXPORTS ---------------- #

@app.route("/export/json")
def export_json():
    with sqlite3.connect(DB_FILE, check_same_thread=False) as conn:
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
    with sqlite3.connect(DB_FILE, check_same_thread=False) as conn:
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

@app.route("/export/pdf")
def export_pdf():
    with sqlite3.connect(DB_FILE, check_same_thread=False) as conn:
        c = conn.cursor()
        c.execute("SELECT indicator,type,source,severity,mitre,score,country,lat,lon,last_seen FROM indicators LIMIT 100")
        rows = c.fetchall()
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    table_data = [["Indicator","Type","Source","Severity","MITRE","Score","Country","Lat","Lon","Last Seen"]] + list(rows)
    table = Table(table_data)
    doc.build([table])
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer,'w') as zf:
        zf.writestr("redshark_cti.pdf", buffer.getvalue())
    zip_buffer.seek(0)
    return send_file(zip_buffer, as_attachment=True, download_name="redshark_cti_pdf.zip")

@app.route("/export/ids")
def export_ids():
    """Generate IDS rules for Snort/Suricata"""
    with sqlite3.connect(DB_FILE, check_same_thread=False) as conn:
        c = conn.cursor()
        c.execute("SELECT indicator,type,severity FROM indicators")
        rows = c.fetchall()

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer,'w') as zf:
        rules = ""
        sid_counter = 1000000
        for ind, typ, sev in rows:
            if typ == "IP":
                rule = f'alert ip any any -> {ind} any (msg:"RedShark {sev} threat"; sid:{sid_counter}; rev:1;)\n'
            elif typ == "Domain":
                rule = f'alert tcp any any -> any 80 (msg:"RedShark {sev} Domain {ind}"; content:"{ind}"; sid:{sid_counter}; rev:1;)\n'
            else:  # Hash
                rule = f'# Hash {ind} severity {sev} (sid:{sid_counter})\n'
            rules += rule
            sid_counter += 1
        zf.writestr("redshark_ids.rules", rules)
    zip_buffer.seek(0)
    return send_file(zip_buffer, as_attachment=True, download_name="redshark_ids.zip")

# ---------------- THREAT ENGINE ---------------- #

def threat_engine():
    """Continuously fetch OTX + AbuseIPDB and save to DB"""
    while True:
        logging.info("Fetching threat feeds...")
        all_iocs = fetch_otx_iocs() + fetch_abuseipdb()
        if all_iocs:
            save_iocs(all_iocs)
            cleanup_db()
            logging.info(f"Saved {len(all_iocs)} IOCs")
        else:
            logging.info("No IOCs fetched")
        time.sleep(600)  # 10 min interval

threading.Thread(target=threat_engine, daemon=True).start()

# ---------------- RUN SERVER ---------------- #

if __name__ == "__main__":
    # For Render deployment, port is assigned via $PORT
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, threaded=True)

