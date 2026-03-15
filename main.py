import sqlite3
import requests
import threading
import time
import io
import csv
import zipfile
import random
import re
from datetime import datetime
from flask import Flask, jsonify, render_template_string, send_file

app = Flask(__name__)

DB="redshark_cti.db"

OTX_KEY="aa94a69a780ed789016bb72d51d9b58b823eb1e6173f6fffc34530693dacb03b"
ABUSE_KEY="08cf00dc25d22cbd0f45ec5ebb87cb61e289533bd33bceb9b93c22349a6eb8674d52aaf14544a100"

# Malaysia states coordinates
STATES=[
("Perlis",6.4414,100.1986),
("Kedah",6.1248,100.3678),
("Penang",5.4141,100.3288),
("Perak",4.5975,101.0901),
("Selangor",3.0738,101.5183),
("Kuala Lumpur",3.1390,101.6869),
("Putrajaya",2.9264,101.6964),
("Negeri Sembilan",2.7297,101.9381),
("Melaka",2.1896,102.2501),
("Johor",1.4927,103.7414),
("Pahang",3.8126,103.3256),
("Terengganu",5.3117,103.1324),
("Kelantan",6.1254,102.2381),
("Sarawak",1.5533,110.3592),
("Sabah",5.9804,116.0735)
]

MITRE=[
"T1566 Phishing",
"T1071 Command & Control",
"T1046 Network Discovery",
"T1105 Exfiltration",
"T1059 Command Execution"
]

# ---------------------------
# IOC TYPE DETECTION
# ---------------------------

def detect_type(value):

    if re.match(r'^https?://', value):
        return "URL"

    if re.match(r'^[a-fA-F0-9]{32}$', value):
        return "MD5"

    if re.match(r'^[a-fA-F0-9]{40}$', value):
        return "SHA1"

    if re.match(r'^[a-fA-F0-9]{64}$', value):
        return "SHA256"

    if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', value):
        return "IP"

    return "Other"


# ---------------------------
# DATABASE
# ---------------------------

def init_db():

    conn=sqlite3.connect(DB)
    c=conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS indicators(
    indicator TEXT PRIMARY KEY,
    type TEXT,
    source TEXT,
    severity TEXT,
    mitre TEXT,
    score INTEGER,
    country TEXT,
    lat REAL,
    lon REAL,
    last_seen TEXT)
    """)

    conn.commit()
    conn.close()

init_db()


def save_iocs(iocs):

    conn=sqlite3.connect(DB)
    c=conn.cursor()

    for i in iocs:

        try:

            c.execute("""
            INSERT OR IGNORE INTO indicators
            VALUES(?,?,?,?,?,?,?,?,?,?)
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
            i["last_seen"]
            ))

        except:
            pass

    conn.commit()
    conn.close()


# ---------------------------
# FEEDS
# ---------------------------

def fetch_otx():

    url="https://otx.alienvault.com/api/v1/pulses/subscribed"
    headers={"X-OTX-API-KEY":OTX_KEY}

    iocs=[]

    try:

        r=requests.get(url,headers=headers,timeout=15)
        data=r.json()

        for pulse in data.get("results",[]):

            for ind in pulse.get("indicators",[]):

                indicator=ind.get("indicator")

                if not indicator:
                    continue

                typ=detect_type(indicator)

                state=random.choice(STATES)

                severity="High"

                if typ=="IP":
                    severity="Critical"

                iocs.append({
                "indicator":indicator,
                "type":typ,
                "source":"OTX",
                "severity":severity,
                "mitre":random.choice(MITRE),
                "score":85,
                "country":state[0],
                "lat":state[1],
                "lon":state[2],
                "last_seen":datetime.utcnow().isoformat()
                })

    except:
        pass

    return iocs


def fetch_abuse():

    url="https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum=75&limit=100"

    headers={
    "Key":ABUSE_KEY,
    "Accept":"application/json"
    }

    iocs=[]

    try:

        r=requests.get(url,headers=headers,timeout=15)
        data=r.json()

        for item in data.get("data",[]):

            ip=item["ipAddress"]

            typ=detect_type(ip)

            state=random.choice(STATES)

            iocs.append({
            "indicator":ip,
            "type":typ,
            "source":"AbuseIPDB",
            "severity":"Critical",
            "mitre":random.choice(MITRE),
            "score":95,
            "country":state[0],
            "lat":state[1],
            "lon":state[2],
            "last_seen":datetime.utcnow().isoformat()
            })

    except:
        pass

    return iocs


def fetch_urlhaus():

    url="https://urlhaus-api.abuse.ch/v1/urls/recent/"

    iocs=[]

    try:

        r=requests.get(url,timeout=15)
        data=r.json()

        for item in data.get("urls",[])[:50]:

            url=item["url"]

            typ=detect_type(url)

            state=random.choice(STATES)

            iocs.append({
            "indicator":url,
            "type":typ,
            "source":"URLHaus",
            "severity":"High",
            "mitre":random.choice(MITRE),
            "score":80,
            "country":state[0],
            "lat":state[1],
            "lon":state[2],
            "last_seen":datetime.utcnow().isoformat()
            })

    except:
        pass

    return iocs


# ---------------------------
# FEED LOOP
# ---------------------------

def feed_loop():

    while True:

        iocs=[]

        iocs+=fetch_otx()
        iocs+=fetch_abuse()
        iocs+=fetch_urlhaus()

        if iocs:
            save_iocs(iocs)

        time.sleep(600)

threading.Thread(target=feed_loop,daemon=True).start()


# ---------------------------
# API
# ---------------------------

@app.route("/api/data")
def api_data():

    conn=sqlite3.connect(DB)
    conn.row_factory=sqlite3.Row
    c=conn.cursor()

    c.execute("""
    SELECT * FROM indicators
    ORDER BY last_seen DESC
    LIMIT 500
    """)

    rows=[dict(r) for r in c.fetchall()]

    conn.close()

    return jsonify(rows)


# ---------------------------
# EXPORT CSV
# ---------------------------

@app.route("/export/csv")
def export_csv():

    conn=sqlite3.connect(DB)
    c=conn.cursor()

    c.execute("SELECT * FROM indicators")
    rows=c.fetchall()

    output=io.StringIO()

    writer=csv.writer(output)

    writer.writerow([
    "indicator","type","source","severity",
    "mitre","score","country","lat","lon","last_seen"
    ])

    writer.writerows(rows)

    mem=io.BytesIO()
    mem.write(output.getvalue().encode())
    mem.seek(0)

    return send_file(mem,download_name="redshark_iocs.csv",as_attachment=True)


# ---------------------------
# IDS RULE EXPORT
# ---------------------------

@app.route("/export/ids")
def export_ids():

    conn=sqlite3.connect(DB)
    c=conn.cursor()

    c.execute("SELECT indicator FROM indicators WHERE type='IP'")
    rows=c.fetchall()

    rules=""
    sid=100000

    for r in rows:
        rules+=f'alert ip {r[0]} any -> any any (msg:"RedShark IOC"; sid:{sid}; rev:1;)\\n'
        sid+=1

    mem=io.BytesIO()

    with zipfile.ZipFile(mem,"w") as z:
        z.writestr("redshark.rules",rules)

    mem.seek(0)

    return send_file(mem,download_name="ids_rules.zip",as_attachment=True)


# ---------------------------
# DASHBOARD
# ---------------------------

@app.route("/")
def dashboard():
    return render_template_string(DASHBOARD_HTML)


DASHBOARD_HTML="""
<!DOCTYPE html>
<html>

<head>

<title>RedShark Sunday Ring</title>

<link rel="stylesheet"
href="https://cdn.datatables.net/1.13.6/css/jquery.dataTables.min.css">

<script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>

<script src="https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js"></script>

<link rel="stylesheet"
href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>

<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>

<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

<style>

body{
background:#020617;
color:white;
font-family:Arial;
margin:0;
}

h1{
text-align:center;
color:#00eaff;
margin:20px;
}

#container{
max-width:1200px;
margin:auto;
}

#map{
height:420px;
margin-bottom:20px;
}

#charts{
display:flex;
gap:20px;
margin-bottom:20px;
}

.chartbox{
flex:1;
background:#111827;
padding:10px;
}

.low{background:#22c55e}
.medium{background:#f59e0b}
.high{background:crimson}
.critical{background:red;font-weight:bold}

</style>

</head>

<body>

<h1>REDSHARK – SUNDAY RING</h1>

<div id="container">

<div id="map"></div>

<div id="charts">

<div class="chartbox"><canvas id="mitre"></canvas></div>
<div class="chartbox"><canvas id="severity"></canvas></div>
<div class="chartbox"><canvas id="timeline"></canvas></div>

</div>

<table id="cti" class="display">

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

<script>

var map=L.map('map').setView([4.5,102],6)

L.tileLayer(
'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png'
).addTo(map)

var markers=[]
var mitreChart
var severityChart
var timelineChart

function fetchData(){

$.getJSON("/api/data",function(data){

var table=$("#cti").DataTable()
table.clear()

markers.forEach(m=>map.removeLayer(m))
markers=[]

var mitreCount={}
var severityCount={}
var timelineCount={}

data.forEach(p=>{

table.row.add([
p.indicator,
p.type,
p.source,
`<span class="${p.severity.toLowerCase()}">${p.severity}</span>`,
p.mitre,
p.score,
p.country,
p.last_seen
])

var color="green"
var radius=6

if(p.severity=="High"){
color="crimson"
radius=10
}

if(p.severity=="Critical"){
color="red"
radius=12
}

var marker=L.circleMarker(
[p.lat,p.lon],
{radius:radius,color:color,fillOpacity:0.8}
).addTo(map)

markers.push(marker)

mitreCount[p.mitre]=(mitreCount[p.mitre]||0)+1
severityCount[p.severity]=(severityCount[p.severity]||0)+1

var hour=p.last_seen.substring(0,13)
timelineCount[hour]=(timelineCount[hour]||0)+1

})

table.draw()

updateCharts(mitreCount,severityCount,timelineCount)

})

}

function updateCharts(mitre,severity,timeline){

if(mitreChart) mitreChart.destroy()

mitreChart=new Chart(
document.getElementById("mitre"),
{
type:"bar",
data:{
labels:Object.keys(mitre),
datasets:[{label:"MITRE Techniques",data:Object.values(mitre)}]
}
})

if(severityChart) severityChart.destroy()

severityChart=new Chart(
document.getElementById("severity"),
{
type:"doughnut",
data:{
labels:Object.keys(severity),
datasets:[{data:Object.values(severity)}]
}
})

if(timelineChart) timelineChart.destroy()

timelineChart=new Chart(
document.getElementById("timeline"),
{
type:"line",
data:{
labels:Object.keys(timeline),
datasets:[{label:"IOC Timeline",data:Object.values(timeline)}]
}
})

}

$(document).ready(function(){

$('#cti').DataTable({pageLength:50})

fetchData()

setInterval(fetchData,60000)

})

</script>

</body>
</html>
"""

if __name__=="__main__":
    app.run(host="0.0.0.0",port=5000)