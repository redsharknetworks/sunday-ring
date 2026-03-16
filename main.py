import io
import csv
import json
import zipfile
import time
import threading
import logging
import re
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
ABUSEIPDB_KEY = "08cf00dc25d22cbd0f45ec5ebb87cb61e93c22349a6eb14544a100"

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
        saved = 0
        for i in iocs:
            try:
                c.execute("""
                INSERT OR REPLACE INTO indicators
                (indicator,type,source,severity,mitre,score,country,lat,lon,first_seen,last_seen)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)
                """,(
                    i["indicator"],i["type"],i["source"],i["severity"],i["mitre"],
                    i["score"],i["country"],i["lat"],i["lon"],i["first_seen"],i["last_seen"]
                ))
                saved += 1
            except Exception as e:
                logging.error(f"DB insert error for {i['indicator']}: {e}")
        conn.commit()
        logging.info(f"{saved} IOCs saved to database")

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
        logging.info("Database cleanup done")

# ---------------- FEED FETCHERS ---------------- #
def detect_type(indicator):
    ip_pattern = re.compile(r"^(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$")
    hash_pattern = re.compile(r"^[a-fA-F0-9]{32,128}$")
    domain_pattern = re.compile(r"^(?!\d+$)([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")
    url_pattern = re.compile(r"^https?://")

    if ip_pattern.match(indicator):
        return "IP"
    elif hash_pattern.match(indicator):
        return "Hash"
    elif url_pattern.match(indicator) or domain_pattern.match(indicator):
        return "Domain"
    return "Unknown"

def fetch_otx_iocs():
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
    headers = {"X-OTX-API-KEY": OTX_KEY}
    iocs = []
    try:
        r = requests.get(url, headers=headers, timeout=15)
        r.raise_for_status()
        data = r.json()
        for pulse in data.get("results", []):
            for ind in pulse.get("indicators", []):
                typ = detect_type(ind["indicator"])
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
        logging.info(f"OTX fetched {len(iocs)} IOCs")
    except Exception as e:
        logging.error(f"OTX fetch error: {e}")
    return iocs

def fetch_abuseipdb():
    url = "https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum=70&limit=100"
    headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
    iocs = []
    try:
        r = requests.get(url, headers=headers, timeout=15)
        r.raise_for_status()
        for item in r.json().get("data", []):
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
        logging.info(f"AbuseIPDB fetched {len(iocs)} IOCs")
    except Exception as e:
        logging.error(f"AbuseIPDB fetch error: {e}")
    return iocs

def threat_engine():
    while True:
        try:
            logging.info("Fetching threat feeds...")
            all_iocs = fetch_otx_iocs() + fetch_abuseipdb()
            if all_iocs:
                save_iocs(all_iocs)
                cleanup_db()
                logging.info(f"Total {len(all_iocs)} IOCs processed")
            else:
                logging.warning("No IOCs fetched")
        except Exception as e:
            logging.error(f"Threat engine error: {e}")
        time.sleep(600)

# Start background thread
threading.Thread(target=threat_engine, daemon=True).start()

# ---------------- DASHBOARD HTML ---------------- #
DASHBOARD_HTML = """<!DOCTYPE html>
<html>
<head>
<title>RedShark SOC Dashboard</title>
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
#dashboard-container{max-width:1200px;margin:0 auto;}
#map{height:450px;width:100%;border-radius:10px;margin-bottom:20px;}
.chart-container{width:100%;margin-bottom:20px;height:300px;}
canvas{width:100% !important;height:100% !important;background:#111827;padding:10px;border-radius:10px;}
.low{color:#22c55e;}
.medium{color:#facc15;}
.high{color:orange;}
.critical{color:red;}
.heat-critical{animation:blink 2s infinite;}
.heat-high{animation:blink 2s infinite;}
@keyframes blink{0%{opacity:0.6;}50%{opacity:1;}100%{opacity:0.6;}}
button{margin:5px;padding:10px 15px;background:#38bdf8;color:#000;border:none;border-radius:5px;cursor:pointer;font-weight:bold;}
button:hover{background:#0ea5e9;color:#fff;}
#cti{width:100% !important;}
</style>
</head>
<body>
<h1>RedShark Cyber SOC Dashboard</h1>
<div id="dashboard-container">
<div class="highlight" id="highlight">Latest Malaysia Security Highlight (GMT+8): {{time}}</div>
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
<button onclick="window.location='/export/pdf'">PDF</button>
<button onclick="window.location='/export/ids'">IDS RULES</button>
</div>
<div style="text-align:center;margin:10px;font-size:12px;color:#888;">
Developed and analysed by darkgrid@redshark.my using publicly available sources
</div>

<script>
var map=L.map('map').setView([4.5,102],6);
L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png').addTo(map);
var markers=[],mitreChart,severityChart,timelineChart;

function fetchData(){
    $.getJSON("/api/data", function(points){
        renderTicker(points);
        renderTable(points);
        renderMap(points);
        renderCharts(points);
    });
}

function renderTicker(points){
    var html="";
    points.slice(0,10).forEach(p=>{
        html+=`🚨 <span class="${p.severity.toLowerCase()}">${p.severity}</span> ${p.indicator} via ${p.source} &nbsp;&nbsp;`;
    });
    $("#ticker").html(html);
}

function renderTable(points){
    var table=$("#cti").DataTable();
    table.clear();
    points.forEach(p=>{
        var sev_color=(p.severity=="High")?"orange":(p.severity=="Critical")?"red":(p.severity=="Medium")?"#facc15":"#22c55e";
        var cls=(p.severity=="Critical")?"heat-critical":(p.severity=="High")?"heat-high":"";
        table.row.add([
            p.indicator,
            p.type,
            p.source,
            `<span style="color:${sev_color};font-weight:bold" class="${cls}">${p.severity}</span>`,
            p.mitre,
            p.score,
            p.country,
            p.last_seen
        ]);
    });
    table.draw();
}

function renderMap(points){
    markers.forEach(m=>map.removeLayer(m));
    markers=[];
    points.forEach(p=>{
        var options={radius:6,color:"green",fillOpacity:0.6};
        var cls="";
        if(p.severity=="Critical"){options.color="red";options.radius=8;cls="heat-critical";}
        else if(p.severity=="High"){options.color="orange";options.radius=7;cls="heat-high";}
        var marker=L.circleMarker([p.lat,p.lon],options).addTo(map);
        if(cls && marker._path){marker._path.classList.add(cls);}
        marker.bindPopup(p.indicator+"<br>"+p.type+" — "+p.severity);
        markers.push(marker);
    });
}

function renderCharts(points){
    // MITRE chart
    var mitreLabels=points.map(p=>p.mitre);
    var mitreCounts={}; mitreLabels.forEach(m=>mitreCounts[m]=(mitreCounts[m]||0)+1);
    if(mitreChart) mitreChart.destroy();
    var ctx_m=document.getElementById('mitre').getContext('2d');
    var mitre_grad=ctx_m.createLinearGradient(0,0,0,300);
    mitre_grad.addColorStop(0,'#38bdf8'); mitre_grad.addColorStop(1,'rgba(0,0,0,0.2)');
    mitreChart=new Chart(ctx_m,{type:'bar',data:{
        labels:Object.keys(mitreCounts),
        datasets:[{label:'MITRE ATT&CK Count',data:Object.values(mitreCounts),backgroundColor:mitre_grad}]
    },options:{plugins:{legend:{display:false}},scales:{y:{beginAtZero:true,ticks:{color:'white'}},x:{ticks:{color:'white'}}}}});

    // Severity chart
    var sevCounts={"Low":0,"Medium":0,"High":0,"Critical":0};
    points.forEach(p=>sevCounts[p.severity]++);
    var ctx_s=document.getElementById('severity').getContext('2d');
    if(severityChart) severityChart.destroy();
    var colors={"Low":"green","Medium":"#facc15","High":"orange","Critical":"red"};
    var gradients=[];
    Object.keys(sevCounts).forEach((sev,i)=>{
        var grad=ctx_s.createLinearGradient(0,0,0,300);
        grad.addColorStop(0,colors[sev]);
        grad.addColorStop(1,"rgba(0,0,0,0.2)");
        gradients.push(grad);
    });
    severityChart=new Chart(ctx_s,{type:'bar',data:{labels:Object.keys(sevCounts),datasets:[{label:'Severity Count',data:Object.values(sevCounts),backgroundColor:gradients,borderColor:Object.values(colors),borderWidth:1}]},options:{plugins:{legend:{display:false}},scales:{y:{beginAtZero:true,ticks:{color:'white'}},x:{ticks:{color:'white'}}},responsive:true,maintainAspectRatio:false}});

    // Timeline chart
    var timeline={};
    points.forEach(p=>{var t=p.last_seen.substring(0,13); timeline[t]=(timeline[t]||0)+1;});
    if(timelineChart) timelineChart.destroy();
    timelineChart=new Chart(document.getElementById('timeline'),{type:'line',data:{labels:Object.keys(timeline),datasets:[{label:"Threat Events",data:Object.values(timeline),borderColor:"#38bdf8",fill:false}]},options:{plugins:{legend:{display:true}},responsive:true,maintainAspectRatio:false}});
}

$(document).ready(function(){
    $('#cti').DataTable({pageLength:50});
    fetchData();
    setInterval(fetchData,60000);
});
</script>
</body></html>

# ---------------- DASHBOARD ROUTE ---------------- #
@app.route("/")
def dashboard():
    malaysia_time = (datetime.utcnow()+timedelta(hours=8)).strftime("%Y-%m-%d %H:%M:%S")
    return render_template_string(DASHBOARD_HTML, time=malaysia_time)

# ---------------- API ROUTE ---------------- #
@app.route("/api/data")
def api_data():
    with sqlite3.connect(DB_FILE, check_same_thread=False) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT indicator,type,source,severity,mitre,score,country,lat,lon,last_seen FROM indicators ORDER BY last_seen DESC LIMIT 500")
        rows = [dict(r) for r in c.fetchall()]
    return jsonify(rows)

# ---------------- EXPORT ROUTES ---------------- #
@app.route("/export/json")
def export_json():
    with sqlite3.connect(DB_FILE, check_same_thread=False) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM indicators")
        rows = [dict(r) for r in c.fetchall()]
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w') as zf:
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
    with sqlite3.connect(DB_FILE, check_same_thread=False) as conn:
        c = conn.cursor()
        c.execute("SELECT indicator,type,severity FROM indicators")
        rows = c.fetchall()
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w') as zf:
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

# ---------------- RUN SERVER ---------------- #
if __name__ == "__main__":
    # Use threaded=True for multiple simultaneous requests
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), threaded=True)