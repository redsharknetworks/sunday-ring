import os
import io
import csv
import json
import random
import sqlite3
import threading
import zipfile
from datetime import datetime, timedelta

from flask import Flask, render_template_string, send_file, jsonify, request
from flask_socketio import SocketIO, emit
from reportlab.platypus import SimpleDocTemplate, Table
from reportlab.lib.pagesizes import letter, landscape

app = Flask(__name__)
app.config['SECRET_KEY'] = 'redshark_v15'
socketio = SocketIO(app)

DB_FILE = "redshark_v15.db"
DISCLAIMER = "Developed and analysed by darkgrid@redshark.my using publicly available sources"

# ---------------- DATABASE ---------------- #
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS indicators(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        indicator TEXT,
        type TEXT,
        source TEXT,
        severity TEXT,
        mitre TEXT,
        score INTEGER,
        category TEXT,
        country TEXT,
        lat REAL,
        lon REAL,
        asn TEXT,
        reputation TEXT,
        first_seen TEXT,
        last_seen TEXT
    )
    """)
    conn.commit()
    conn.close()

init_db()

# ---------------- GLOBAL LOCATIONS ---------------- #
locations = [
    ("Malaysia",4.2,102.0),
    ("Singapore",1.35,103.82),
    ("China",35,103),
    ("USA",37,-95),
    ("Russia",61,105),
    ("Germany",51,10),
    ("Brazil",-10,-55)
]

# ---------------- MITRE ATT&CK ---------------- #
mitre_map = [
"T1046 Network Service Discovery",
"T1059 Command Execution",
"T1566 Phishing",
"T1071 C2 Communication",
"T1105 Exfiltration",
"T1190 Exploit Public Application"
]

# ---------------- THREAT TYPES ---------------- #
threat_categories = ["Malware","Phishing","Botnet","C2","Recon"]

# ---------------- IOC GENERATOR ---------------- #
def random_ip(): return f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"
def random_domain(): return f"malicious{random.randint(1,999)}.net"
def random_hash(): return os.urandom(16).hex()
def threat_score(sev):
    return {"Low": random.randint(10,30),
            "Medium": random.randint(40,60),
            "High": random.randint(70,85),
            "Critical": random.randint(90,100)}[sev]

# ---------------- THREAT ENRICHMENT PLACEHOLDER ---------------- #
def enrich_ioc(indicator_type):
    # Placeholder enrichment data
    asn = f"AS{random.randint(1000,99999)}"
    reputation = random.choice(["malicious","suspicious","clean"])
    return asn, reputation

# ---------------- FEED ENGINE ---------------- #
def generate_feed():
    feeds = ["OTX","Talos","AbuseIPDB"]
    data = []
    for _ in range(random.randint(12,25)):
        typ = random.choice(["IP","Domain","Hash"])
        indicator = random_ip() if typ=="IP" else random_domain() if typ=="Domain" else random_hash()
        loc = random.choice(locations)
        sev = random.choice(["Low","Medium","High","Critical"])
        category = random.choice(threat_categories)
        asn, reputation = enrich_ioc(typ)
        data.append({
            "indicator": indicator,
            "type": typ,
            "source": random.choice(feeds),
            "severity": sev,
            "mitre": random.choice(mitre_map),
            "score": threat_score(sev),
            "category": category,
            "country": loc[0],
            "lat": loc[1],
            "lon": loc[2],
            "asn": asn,
            "reputation": reputation,
            "first_seen": datetime.utcnow().isoformat(),
            "last_seen": datetime.utcnow().isoformat()
        })
    return data

def save_iocs(feed, emit_update=True):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    for f in feed:
        c.execute("""
        INSERT INTO indicators
        (indicator,type,source,severity,mitre,score,category,country,lat,lon,asn,reputation,first_seen,last_seen)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,(f["indicator"],f["type"],f["source"],f["severity"],f["mitre"],
             f["score"],f["category"],f["country"],f["lat"],f["lon"],
             f["asn"], f["reputation"], f["first_seen"], f["last_seen"]))
    conn.commit()
    conn.close()
    # Emit to WebSocket clients
    if emit_update:
        socketio.emit('new_iocs', {'iocs': feed}, broadcast=True)

# ---------------- BACKGROUND FEED ENGINE ---------------- #
def threat_engine():
    while True:
        save_iocs(generate_feed())
        socketio.sleep(60)  # use socketio.sleep for compatibility with WebSocket

threading.Thread(target=threat_engine,daemon=True).start()

# ---------------- DASHBOARD ---------------- #
@app.route("/")
def dashboard():
    html="""
<!DOCTYPE html>
<html>
<head>
<title>RedShark Threat Intelligence Platform</title>
<link rel="stylesheet" href="https://cdn.datatables.net/1.13.6/css/jquery.dataTables.min.css">
<script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
<script src="https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js"></script>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.7.2/socket.io.min.js"></script>
<style>
body{background:#020617;color:white;font-family:Arial}
h1{text-align:center;color:#38bdf8}
.highlight{background:#1e293b;padding:15px;margin:20px;border-left:5px solid red}
.ticker{padding:10px;border-top:1px solid #334155;border-bottom:1px solid #334155;overflow-x:auto;white-space:nowrap}
#map{height:450px;margin:20px}
#mitre,#severity{height:250px;margin:20px}
.low{color:green}
.medium{color:orange}
.high{color:red}
.critical{color:red;font-weight:bold;animation:blink 1s infinite}
#disclaimer{font-size:0.8em;text-align:center;color:#888;margin:30px}
@keyframes blink{50%{opacity:0}}
</style>
</head>
<body>
<h1>RedShark Threat Intelligence Platform</h1>
<div class="highlight" id="highlight"><b>Latest Malaysia Security Highlight (GMT+8)</b><br>No major threat detected</div>
<div class="ticker" id="ticker"></div>
<div id="map"></div>
<canvas id="mitre"></canvas>
<canvas id="severity"></canvas>
<table id="cti" class="display">
<thead>
<tr>
<th>Indicator</th>
<th>Type</th>
<th>Source</th>
<th>Severity</th>
<th>Category</th>
<th>MITRE</th>
<th>Score</th>
<th>Country</th>
<th>ASN</th>
<th>Reputation</th>
<th>Last Seen</th>
</tr>
</thead>
<tbody id="table-body"></tbody>
</table>
<div style="text-align:center;margin:20px">
<button onclick="window.location='/export/json'">JSON</button>
<button onclick="window.location='/export/csv'">CSV</button>
<button onclick="window.location='/export/pdf'">PDF</button>
<button onclick="window.location='/export/ids'">IDS</button>
<button onclick="window.location='/export/zip'">IOC ZIP</button>
</div>
<small id="disclaimer">{{disclaimer}}</small>
<script>
var socket = io();
var map = L.map('map').setView([20,0],2)
L.tileLayer('https://tile.openstreetmap.org/{z}/{x}/{y}.png').addTo(map)
var markers=[];

var mitre_chart = new Chart(document.getElementById('mitre'),{
type:'bar',data:{labels:[],datasets:[{label:'MITRE ATT&CK Count',data:[],backgroundColor:[],borderRadius:10,borderWidth:1}]},
options:{plugins:{legend:{display:false}},scales:{y:{beginAtZero:true}}}
})
var severity_chart = new Chart(document.getElementById('severity'),{
type:'bar',data:{labels:[],datasets:[{label:'Severity Count',data:[],backgroundColor:['#22c55e','#f97316','#ef4444','#b91c1c'],borderRadius:10,borderWidth:1}]},
options:{plugins:{legend:{display:false}},scales:{y:{beginAtZero:true}}}
})

function update_dashboard(iocs){
    // update table
    var tbody = $('#table-body'); tbody.empty();
    var ticker_html = ''; var highlight_text = 'No major threat detected';
    iocs.forEach(function(i,idx){
        tbody.append('<tr>'+
            `<td>${i.indicator}</td>`+
            `<td>${i.type}</td>`+
            `<td>${i.source}</td>`+
            `<td class="${i.severity.toLowerCase()}">${i.severity}</td>`+
            `<td>${i.category}</td>`+
            `<td>${i.mitre}</td>`+
            `<td>${i.score}</td>`+
            `<td>${i.country}</td>`+
            `<td>${i.asn}</td>`+
            `<td>${i.reputation}</td>`+
            `<td>${i.last_seen}</td>`+
            '</tr>');
        if(idx<10){ ticker_html+=`🚨 ${i.severity} ${i.category} ${i.indicator} via ${i.source} &nbsp;&nbsp;` }
        if(idx===0) highlight_text=`${i.severity} ${i.category} threat ${i.indicator} via ${i.source} at ${(new Date()).toLocaleString('en-US',{timeZone:'Asia/Kuala_Lumpur'})}`
    });
    $('#ticker').html(ticker_html); $('#highlight').html('<b>Latest Malaysia Security Highlight (GMT+8)</b><br>'+highlight_text);

    // update map
    markers.forEach(m=>map.removeLayer(m)); markers=[];
    iocs.forEach(function(i){
        var color="blue"; if(i.severity=="Low") color="green"; if(i.severity=="Medium") color="orange";
        if(i.severity=="High") color="red"; if(i.severity=="Critical") color="darkred";
        var marker=L.circleMarker([i.lat,i.lon],{radius:7,color:color,fillOpacity:0.7}).addTo(map)
        .bindPopup(i.indicator+"<br>"+i.severity+" "+i.category);
        markers.push(marker);
    });

    // update charts
    var mitre_counts = {}; var severity_counts={};
    iocs.forEach(function(i){ mitre_counts[i.mitre]=(mitre_counts[i.mitre]||0)+1; severity_counts[i.severity]=(severity_counts[i.severity]||0)+1; });
    mitre_chart.data.labels=Object.keys(mitre_counts); mitre_chart.data.datasets[0].data=Object.values(mitre_counts);
    mitre_chart.data.datasets[0].backgroundColor=Object.keys(mitre_counts).map(_=>'rgba(56,189,248,0.7)'); mitre_chart.update();
    severity_chart.data.labels=Object.keys(severity_counts); severity_chart.data.datasets[0].data=Object.values(severity_counts); severity_chart.update();
}

socket.on('new_iocs', function(data){ update_dashboard(data.iocs); });
</script>
</body>
</html>
"""
    return render_template_string(html,disclaimer=DISCLAIMER)

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
    output=io.StringIO(); writer=csv.writer(output); writer.writerows(rows)
    return send_file(io.BytesIO(output.getvalue().encode()),as_attachment=True,download_name="redshark_cti.csv")

@app.route("/export/pdf")
def export_pdf():
    conn=sqlite3.connect(DB_FILE); c=conn.cursor()
    c.execute("SELECT indicator,type,source,severity,mitre,score,category FROM indicators LIMIT 100")
    rows=c.fetchall(); conn.close()
    buffer=io.BytesIO(); doc=SimpleDocTemplate(buffer,pagesize=landscape(letter))
    table=Table(rows); doc.build([table]); buffer.seek(0)
    return send_file(buffer,as_attachment=True,download_name="redshark_report.pdf")

@app.route("/export/ids")
def export_ids():
    conn=sqlite3.connect(DB_FILE); c=conn.cursor()
    c.execute("SELECT indicator FROM indicators WHERE type='IP'"); rows=c.fetchall(); conn.close()
    rules=""; sid=100000
    for r in rows:
        rules+=f'alert ip {r[0]} any -> any any (msg:"RedShark IOC"; sid:{sid}; rev:1;)\n'; sid+=1
    return send_file(io.BytesIO(rules.encode()),as_attachment=True,download_name="redshark.rules")

@app.route("/export/zip")
def export_zip():
    conn=sqlite3.connect(DB_FILE); c=conn.cursor()
    c.execute("SELECT indicator FROM indicators"); rows=c.fetchall(); conn.close()
    mem=io.BytesIO()
    with zipfile.ZipFile(mem,'w',zipfile.ZIP_DEFLATED) as z:
        z.writestr("ioc_list.txt","\n".join([r[0] for r in rows]))
    mem.seek(0)
    return send_file(mem,as_attachment=True,download_name="redshark_iocs.zip")

# ---------------- REFRESH ---------------- #
@app.route("/refresh")
def refresh():
    save_iocs(generate_feed())
    return "Threat feed refreshed"

# ---------------- RUN ---------------- #
if __name__=="__main__":
    port=int(os.environ.get("PORT",5000))
    socketio.run(app,host="0.0.0.0",port=port,debug=True)