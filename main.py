import os
import io
import csv
import json
import time
import sqlite3
import threading
import requests
from datetime import datetime, timedelta
from flask import Flask, render_template_string, jsonify, send_file

from reportlab.platypus import SimpleDocTemplate, Table
from reportlab.lib.pagesizes import letter
import zipfile

# ---------------- CONFIG ---------------- #
app = Flask(__name__)
DB_FILE = "redshark.db"
OTX_KEY = "aa94a69a780ed789016bb72d51d9b58b823eb1e6173f6fffc34530693dacb03b"
ABUSEIPDB_KEY = "08cf00dc25d22cbd0f45ec5ebb87cb61e289533bd33bceb9b93c22349a6eb8674d52aaf14544a100"

# ---------------- DATABASE ---------------- #
def init_db():
    conn = sqlite3.connect(DB_FILE)
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
    conn.close()
init_db()

def cleanup_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
    DELETE FROM indicators
    WHERE id NOT IN (
        SELECT id FROM indicators
        ORDER BY last_seen DESC
        LIMIT 5000
    )
    """)
    conn.commit()
    conn.close()

# ---------------- LOCATIONS ---------------- #
locations = [
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

mitre_map = [
    "T1046 Network Discovery",
    "T1059 Command Execution",
    "T1566 Phishing",
    "T1071 C2 Communication",
    "T1105 Data Exfiltration",
    "T1190 Exploit Public Facing App"
]

# ---------------- HELPER ---------------- #
def save_iocs(feed):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    for f in feed:
        try:
            c.execute("""
            INSERT OR IGNORE INTO indicators
            (indicator,type,source,severity,mitre,score,country,lat,lon,first_seen,last_seen)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
            """,(
                f["indicator"],f["type"],f["source"],f["severity"],f["mitre"],
                f["score"],f["country"],f["lat"],f["lon"],f["first_seen"],f["last_seen"]
            ))
        except Exception as e:
            print("DB insert error:", e)
    conn.commit()
    conn.close()

# ---------------- FEED FETCH ---------------- #
def fetch_otx_iocs():
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
    headers = {"X-OTX-API-KEY": OTX_KEY}
    iocs = []
    try:
        r = requests.get(url, headers=headers, timeout=15)
        if r.status_code == 200:
            data = r.json()
            pulses = data.get("results",[])
            for pulse in pulses:
                for ind in pulse.get("indicators",[]):
                    typ = "IP" if ind.get("type","IPv4")=="IPv4" else "Domain"
                    loc = locations[int(datetime.utcnow().timestamp()) % len(locations)]
                    iocs.append({
                        "indicator": ind["indicator"],
                        "type": typ,
                        "source": "OTX",
                        "severity": "Critical" if typ=="IP" else "High",
                        "mitre": mitre_map[int(datetime.utcnow().timestamp()) % len(mitre_map)],
                        "score": 95,
                        "country": loc[0],
                        "lat": loc[1],
                        "lon": loc[2],
                        "first_seen": datetime.utcnow().isoformat(),
                        "last_seen": datetime.utcnow().isoformat()
                    })
    except Exception as e:
        print("OTX fetch error:", e)
    return iocs

def fetch_abuseipdb():
    url = "https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum=70&limit=100"
    headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
    iocs = []
    try:
        r = requests.get(url, headers=headers, timeout=15)
        if r.status_code == 200:
            data = r.json()
            for item in data.get("data",[]):
                loc = locations[int(datetime.utcnow().timestamp()) % len(locations)]
                iocs.append({
                    "indicator": item["ipAddress"],
                    "type": "IP",
                    "source": "AbuseIPDB",
                    "severity": "Critical",
                    "mitre": mitre_map[int(datetime.utcnow().timestamp()) % len(mitre_map)],
                    "score": 90,
                    "country": loc[0],
                    "lat": loc[1],
                    "lon": loc[2],
                    "first_seen": datetime.utcnow().isoformat(),
                    "last_seen": datetime.utcnow().isoformat()
                })
    except Exception as e:
        print("AbuseIPDB fetch error:", e)
    return iocs

def threat_engine():
    while True:
        feed = fetch_otx_iocs() + fetch_abuseipdb()
        if feed:
            save_iocs(feed)
        cleanup_db()
        time.sleep(60)

threading.Thread(target=threat_engine,daemon=True).start()

# ---------------- DASHBOARD ---------------- #
DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
<title>RedShark Cyber Threat Intelligence Platform</title>
<link rel="stylesheet" href="https://cdn.datatables.net/1.13.6/css/jquery.dataTables.min.css">
<script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
<script src="https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js"></script>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script src="https://unpkg.com/leaflet.heat/dist/leaflet-heat.js"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
body{background:#020617;color:white;font-family:Arial}
h1{text-align:center;color:#38bdf8}
.highlight{background:#1e293b;padding:15px;margin:20px;border-left:5px solid red}
.ticker{padding:10px;border-top:1px solid #334155;border-bottom:1px solid #334155}
#map{height:450px;margin:20px}
canvas{margin:20px}
.low{color:green}
.medium{color:orange}
.high{color:red}
.critical{color:red;font-weight:bold;animation:pulse 1s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:0}}
</style>
</head>
<body>
<h1>RedShark Cyber Threat Intelligence Platform</h1>
<div class="highlight"><b>Latest Malaysia Security Highlight (GMT+8)</b><br>{{time}}</div>
<div class="ticker">
{% for r in rows[:10] %}
🚨 {{r[3]}} {{r[0]}} via {{r[2]}} &nbsp;&nbsp;
{% endfor %}
</div>
<div id="map"></div>
<canvas id="mitre" height="250"></canvas>
<canvas id="severity" height="250"></canvas>
<canvas id="timeline" height="250"></canvas>
<table id="cti" class="display">
<thead>
<tr>
<th>Indicator</th><th>Type</th><th>Source</th><th>Severity</th>
<th>MITRE</th><th>Score</th><th>Country</th><th>Last Seen</th>
</tr>
</thead>
<tbody>
{% for r in rows %}
<tr>
<td>{{r[0]}}</td><td>{{r[1]}}</td><td>{{r[2]}}</td>
<td class="{{r[3]|lower}}">{{r[3]}}</td>
<td>{{r[4]}}</td><td>{{r[5]}}</td><td>{{r[6]}}</td><td>{{r[9]}}</td>
</tr>
{% endfor %}
</tbody>
</table>
<div style="text-align:center;margin:20px">
<button onclick="window.location='/export/json'">JSON</button>
<button onclick="window.location='/export/csv'">CSV</button>
<button onclick="window.location='/export/pdf'">PDF</button>
<button onclick="window.location='/export/idszip'">IDS ZIP</button>
<button onclick="window.location='/refresh'">Refresh</button>
</div>
<div style="text-align:center;margin:10px;font-size:12px;color:#888">
Developed and analysed by darkgrid@redshark.my using publicly available sources
</div>
<script>
$(document).ready(function(){ $('#cti').DataTable({pageLength:50}) })
var map=L.map('map').setView([4.5,102],6)
L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png').addTo(map)
var points={{rows|tojson}}
var heat=[]
points.forEach(function(p){ 
    var intensity=(p[3]=="Critical")?1:0.5;
    heat.push([p[7],p[8],intensity]) 
})
L.heatLayer(heat,{radius:25,blur:15}).addTo(map)

// MITRE chart
var mitre_labels = points.map(p=>p[4])
var mitre_counts = {}
mitre_labels.forEach(m=>mitre_counts[m]=(mitre_counts[m]||0)+1)
new Chart(document.getElementById('mitre'),{
type:'bar',
data:{labels:Object.keys(mitre_counts),datasets:[{label:'MITRE ATT&CK Count',data:Object.values(mitre_counts),backgroundColor:'rgba(56,189,248,0.7)'}]},
options:{plugins:{legend:{display:false}}}
})

// Severity chart
var sev={"Low":0,"Medium":0,"High":0,"Critical":0}
points.forEach(p=>sev[p[3]]++)
new Chart(document.getElementById('severity'),{
type:'doughnut',
data:{labels:Object.keys(sev),datasets:[{data:Object.values(sev),backgroundColor:["green","orange","red","darkred"]}]}
})

// Timeline chart
var timeline={}
points.forEach(p=>{ var t=p[9].substring(0,13); timeline[t]=(timeline[t]||0)+1 })
new Chart(document.getElementById('timeline'),{
type:'line',
data:{labels:Object.keys(timeline),datasets:[{label:"Threat Events",data:Object.values(timeline),borderColor:"#38bdf8",fill:false}]}
})
</script>
</body>
</html>
"""

@app.route("/")
def dashboard():
    conn=sqlite3.connect(DB_FILE); c=conn.cursor()
    c.execute("SELECT indicator,type,source,severity,mitre,score,country,lat,lon,last_seen FROM indicators ORDER BY last_seen DESC LIMIT 500")
    rows=c.fetchall(); conn.close()
    malaysia_time=(datetime.utcnow()+timedelta(hours=8)).strftime("%Y-%m-%d %H:%M:%S")
    return render_template_string(DASHBOARD_HTML, rows=rows, time=malaysia_time)

# ---------------- EXPORTS ---------------- #
@app.route("/export/json")
def export_json():
    conn=sqlite3.connect(DB_FILE); c=conn.cursor()
    c.execute("SELECT * FROM indicators"); rows=c.fetchall(); conn.close()
    return jsonify(rows)

@app.route("/export/csv")
def export_csv():
    conn=sqlite3.connect(DB_FILE); c=conn.cursor()
    c.execute("SELECT * FROM indicators"); rows=c.fetchall(); conn.close()
    output=io.StringIO(); writer=csv.writer(output)
    writer.writerow(["id","indicator","type","source","severity","mitre","score","country","lat","lon","first_seen","last_seen"])
    writer.writerows(rows)
    return send_file(io.BytesIO(output.getvalue().encode()),as_attachment=True,download_name="redshark_cti.csv")

@app.route("/export/pdf")
def export_pdf():
    conn=sqlite3.connect(DB_FILE); c=conn.cursor()
    c.execute("SELECT indicator,type,source,severity,mitre FROM indicators LIMIT 100")
    rows=c.fetchall(); conn.close()
    buffer=io.BytesIO(); doc=SimpleDocTemplate(buffer,pagesize=letter)
    table=Table(rows); doc.build([table]); buffer.seek(0)
    return send_file(buffer,as_attachment=True,download_name="redshark_report.pdf")

@app.route("/export/idszip")
def export_idszip():
    conn=sqlite3.connect(DB_FILE); c=conn.cursor()
    c.execute("SELECT indicator FROM indicators WHERE type='IP'"); rows=c.fetchall(); conn.close()
    mem=io.BytesIO()
    with zipfile.ZipFile(mem,'w',zipfile.ZIP_DEFLATED) as z:
        sid = 100000
        rules=""
        for r in rows:
            rules+=f'alert ip {r[0]} any -> any any (msg:"RedShark IOC"; sid:{sid}; rev:1;)\n'
            sid+=1
        z.writestr("redshark.rules", rules)
    mem.seek(0)
    return send_file(mem,as_attachment=True,download_name="redshark_ids.zip")

@app.route("/refresh")
def refresh():
    feed = fetch_otx_iocs() + fetch_abuseipdb()
    save_iocs(feed)
    cleanup_db()
    return "Threat feed refreshed"

# ---------------- RUN ---------------- #
if __name__=="__main__":
    app.run(host="0.0.0.0", port=5000)