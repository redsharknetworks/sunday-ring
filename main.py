import io
import csv
import json
import zipfile
import time
import threading
import logging
from datetime import datetime, timedelta

import sqlite3
import requests
from flask import Flask, render_template_string, jsonify, send_file
from reportlab.platypus import SimpleDocTemplate, Table
from reportlab.lib.pagesizes import letter

# ---------------- CONFIG ---------------- #
app = Flask(__name__)
DB_FILE = "redshark.db"
OTX_KEY = "aa94a69a780ed789016bb72d51d9b58b823eb1e6173f6fffc34530693dacb03b"
ABUSEIPDB_KEY = "08cf00dc25d22cbd0f45ec5ebb87cb61e289533bd33bceb9b93c22349a6eb14544a100"

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
                    itype = ind.get("type","IPv4")
                    typ = "IP" if itype=="IPv4" else "Domain" if "domain" in itype.lower() else "Hash"
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
            data = r.json()
            for item in data.get("data",[]):
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
        time.sleep(600)  # fetch every 10 minutes

# ---------------- START BACKGROUND THREAD ---------------- #
threading.Thread(target=threat_engine, daemon=True).start()

# ---------------- DASHBOARD HTML ---------------- #
DASHBOARD_HTML = """<!DOCTYPE html>
<html>
<head>
<title>RedShark CTI Dashboard</title>
<link rel="stylesheet" href="https://cdn.datatables.net/1.13.6/css/jquery.dataTables.min.css">
<script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
<script src="https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js"></script>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
body{background:#020617;color:white;font-family:Arial;margin:0;padding:0}
h1{text-align:center;color:#38bdf8;margin:20px 0;}
.highlight{background:#1e293b;padding:15px;margin:20px;border-left:5px solid red;font-weight:bold;}
.ticker{padding:10px;border-top:1px solid #334155;border-bottom:1px solid #334155;overflow-x:auto;white-space:nowrap;}
#map{height:450px;margin:20px;border-radius:10px;}
canvas{margin:20px;border-radius:10px;background:#111827;padding:10px;}
.low{color:#22c55e;}
.medium{color:#facc15;}
.high{color:#f87171;}
.critical-marker{color:#f43f5e;font-weight:bold;animation:pulse 1s infinite;}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:0}}
button{margin:5px;padding:10px 15px;background:#38bdf8;color:#000;border:none;border-radius:5px;cursor:pointer;font-weight:bold;}
button:hover{background:#0ea5e9;color:#fff;}
#charts{display:flex;flex-wrap:wrap;justify-content:space-around;}
.chart-container{flex:1 1 300px;max-width:500px;}
</style>
</head>
<body>
<h1>RedShark Cyber Threat Intelligence Platform</h1>
<div class="highlight" id="highlight">Latest Malaysia Security Highlight (GMT+8): {{time}}</div>
<div class="ticker" id="ticker">
{% for r in rows[:10] %}
🚨 <span class="{{r['severity']|lower}}">{{r['severity']}}</span> {{r['indicator']}} via {{r['source']}} &nbsp;&nbsp;
{% endfor %}
</div>
<div id="map"></div>
<div id="charts">
  <div class="chart-container"><canvas id="mitre" height="250"></canvas></div>
  <div class="chart-container"><canvas id="severity" height="250"></canvas></div>
  <div class="chart-container"><canvas id="timeline" height="250"></canvas></div>
</div>
<table id="cti" class="display" style="width:95%;margin:20px auto;">
<thead>
<tr><th>Indicator</th><th>Type</th><th>Source</th><th>Severity</th>
<th>MITRE</th><th>Score</th><th>Country</th><th>Last Seen</th></tr>
</thead>
<tbody>
{% for r in rows %}
<tr>
<td>{{r['indicator']}}</td><td>{{r['type']}}</td><td>{{r['source']}}</td>
<td class="{{r['severity']|lower}}">{{r['severity']}}</td><td>{{r['mitre']}}</td><td>{{r['score']}}</td>
<td>{{r['country']}}</td><td>{{r['last_seen']}}</td>
</tr>
{% endfor %}
</tbody>
</table>
<div style="text-align:center;margin:20px;">
<button onclick="window.location='/export/json'">JSON</button>
<button onclick="window.location='/export/csv'">CSV</button>
<button onclick="window.location='/export/pdf'">PDF</button>
<button onclick="window.location='/export/ids'">IDS RULES</button>
</div>
<div style="text-align:center;margin:10px;font-size:12px;color:#888;">
Developed and analysed by darkgrid@redshark.my using publicly available sources
</div>
<script>
var map = L.map('map').setView([4.5,102],6);
L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png').addTo(map);
var markers=[],mitreChart,severityChart,timelineChart;

function initCharts(points){
    var mitreLabels=points.map(p=>p.mitre);
    var mitreCounts={}; mitreLabels.forEach(m=>mitreCounts[m]=(mitreCounts[m]||0)+1);
    mitreChart=new Chart(document.getElementById('mitre'),{type:'bar',data:{labels:Object.keys(mitreCounts),datasets:[{label:'MITRE ATT&CK Count',data:Object.values(mitreCounts),backgroundColor:'rgba(56,189,248,0.7)'}]},options:{plugins:{legend:{display:false}}}});
    
    var sev={"Low":0,"Medium":0,"High":0,"Critical":0}; points.forEach(p=>sev[p.severity]++);
    severityChart=new Chart(document.getElementById('severity'),{type:'doughnut',data:{labels:Object.keys(sev),datasets:[{data:Object.values(sev),backgroundColor:["green","orange","red","darkred"]}]}});

    var timeline={}; points.forEach(p=>{var t=p.last_seen.substring(0,13); timeline[t]=(timeline[t]||0)+1;});
    timelineChart=new Chart(document.getElementById('timeline'),{type:'line',data:{labels:Object.keys(timeline),datasets:[{label:"Threat Events",data:Object.values(timeline),borderColor:"#38bdf8",fill:false}]}})
}

function renderMap(points){
    markers.forEach(m=>map.removeLayer(m)); markers=[];
    points.forEach(function(p){
        var marker=L.circleMarker([p.lat,p.lon],{radius:p.severity=="Critical"?10:7,color:p.severity=="Critical"?"red":"blue",fillOpacity:p.severity=="Critical"?0.8:0.5}).addTo(map);
        marker.bindPopup(p.indicator+"<br>"+p.severity);
        if(p.severity=="Critical" && marker._icon) marker._icon.classList.add("critical-marker");
        markers.push(marker);
    });
}

$(document).ready(function(){
    $('#cti').DataTable({pageLength:50});
    var initialPoints = {{rows|tojson}};
    renderMap(initialPoints); initCharts(initialPoints);
});
</script>
</body></html>
"""

# ---------------- DASHBOARD ROUTE ---------------- #
@app.route("/")
def dashboard():
    try:
        with sqlite3.connect(DB_FILE, check_same_thread=False) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute("SELECT indicator,type,source,severity,mitre,score,country,lat,lon,last_seen FROM indicators ORDER BY last_seen DESC LIMIT 500")
            rows = [dict(r) for r in c.fetchall()]
        malaysia_time = (datetime.utcnow()+timedelta(hours=8)).strftime("%Y-%m-%d %H:%M:%S")
        return render_template_string(DASHBOARD_HTML, rows=rows, time=malaysia_time)
    except Exception as e:
        logging.error(f"Dashboard error: {e}")
        return f"Error loading dashboard: {e}",500

# ---------------- EXPORT ROUTES ---------------- #
@app.route("/export/json")
def export_json():
    with sqlite3.connect(DB_FILE, check_same_thread=False) as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM indicators")
        rows = c.fetchall()
    return jsonify(rows)

@app.route("/export/csv")
def export_csv():
    with sqlite3.connect(DB_FILE, check_same_thread=False) as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM indicators")
        rows = c.fetchall()
    output=io.StringIO()
    writer=csv.writer(output)
    writer.writerow(["id","indicator","type","source","severity","mitre","score","country","lat","lon","first_seen","last_seen"])
    writer.writerows(rows)
    return send_file(io.BytesIO(output.getvalue().encode()), as_attachment=True, download_name="redshark_cti.csv")

@app.route("/export/pdf")
def export_pdf():
    with sqlite3.connect(DB_FILE, check_same_thread=False) as conn:
        c = conn.cursor()
        c.execute("SELECT indicator,type,source,severity,mitre,score,country,lat,lon,last_seen FROM indicators LIMIT 100")
        rows = c.fetchall()
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    table_data=[["Indicator","Type","Source","Severity","MITRE","Score","Country","Lat","Lon","Last Seen"]]+list(rows)
    table=Table(table_data)
    doc.build([table])
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name="redshark_report.pdf")

@app.route("/export/ids")
def export_ids():
    with sqlite3.connect(DB_FILE, check_same_thread=False) as conn:
        c = conn.cursor()
        c.execute("SELECT indicator FROM indicators WHERE type='IP'")
        rows = c.fetchall()
    sid=100000
    mem=io.BytesIO()
    with zipfile.ZipFile(mem,'w',zipfile.ZIP_DEFLATED) as z:
        rules=""
        for r in rows:
            rules+=f'alert ip {r[0]} any -> any any (msg:"RedShark IOC"; sid:{sid}; rev:1;)\n'
            sid+=1
        z.writestr("redshark_ids.rules",rules)
    mem.seek(0)
    return send_file(mem, as_attachment=True, download_name="redshark_ids_rules.zip")

# ---------------- REFRESH ROUTE ---------------- #
@app.route("/refresh")
def refresh():
    return "Feed fetching is handled in background thread. Refresh automatically every 10 minutes."

# ---------------- RUN ---------------- #
if __name__=="__main__":
    app.run(host="0.0.0.0", port=5000)