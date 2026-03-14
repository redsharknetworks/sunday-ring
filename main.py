import os
import io
import csv
import json
import time
import random
import sqlite3
import threading
import zipfile
from datetime import datetime, timedelta

from flask import Flask, render_template_string, send_file, jsonify, request
from reportlab.platypus import SimpleDocTemplate, Table
from reportlab.lib.pagesizes import letter

app = Flask(__name__)
DB_FILE = "redshark_soc.db"

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

# ---------------- LOCATIONS ---------------- #
locations = [
    ("Malaysia",4.2,102.0),
    ("Singapore",1.35,103.82),
    ("China",35,103),
    ("USA",37,-95),
    ("Russia",61,105),
    ("Germany",51,10),
    ("Brazil",-10,-55)
]

# ---------------- MITRE ---------------- #
mitre_map = [
    "T1046 Network Service Discovery",
    "T1059 Command Execution",
    "T1566 Phishing",
    "T1071 C2 Communication",
    "T1105 Exfiltration",
    "T1190 Exploit Public Application"
]

# ---------------- IOC GENERATOR ---------------- #
def random_ip(): return f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"
def random_domain(): return f"malicious{random.randint(1,999)}.net"
def random_hash(): return os.urandom(16).hex()

# ---------------- AI THREAT SCORE ---------------- #
def threat_score(sev):
    return {"Low": random.randint(10,30),
            "Medium": random.randint(40,60),
            "High": random.randint(70,85),
            "Critical": random.randint(90,100)}[sev]

# ---------------- FEED ENGINE ---------------- #
def generate_feed():
    feeds = ["OTX","Talos","AbuseIPDB"]
    data = []
    for i in range(random.randint(15,30)):
        typ = random.choice(["IP","Domain","Hash"])
        indicator = random_ip() if typ=="IP" else random_domain() if typ=="Domain" else random_hash()
        loc = random.choice(locations)
        sev = random.choice(["Low","Medium","High","Critical"])
        data.append({
            "indicator": indicator,
            "type": typ,
            "source": random.choice(feeds),
            "severity": sev,
            "mitre": random.choice(mitre_map),
            "score": threat_score(sev),
            "country": loc[0],
            "lat": loc[1],
            "lon": loc[2],
            "first_seen": datetime.utcnow().isoformat(),
            "last_seen": datetime.utcnow().isoformat()
        })
    return data

def save_iocs(feed):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    for f in feed:
        c.execute("""
        INSERT INTO indicators
        (indicator,type,source,severity,mitre,score,country,lat,lon,first_seen,last_seen)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)
        """,(f["indicator"],f["type"],f["source"],f["severity"],f["mitre"],
             f["score"],f["country"],f["lat"],f["lon"],f["first_seen"],f["last_seen"]))
    conn.commit()
    conn.close()

def threat_engine():
    while True:
        save_iocs(generate_feed())
        time.sleep(45)
threading.Thread(target=threat_engine,daemon=True).start()

# ---------------- DASHBOARD ---------------- #
@app.route("/")
def dashboard():
    search = request.args.get("q","")
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    if search:
        c.execute("""
        SELECT indicator,type,source,severity,mitre,score,country,lat,lon,last_seen
        FROM indicators WHERE indicator LIKE ? ORDER BY last_seen DESC
        """,(f"%{search}%",))
    else:
        c.execute("""
        SELECT indicator,type,source,severity,mitre,score,country,lat,lon,last_seen
        FROM indicators ORDER BY last_seen DESC
        """)
    rows = c.fetchall()
    conn.close()

    malaysia_time=(datetime.utcnow()+timedelta(hours=8)).strftime("%Y-%m-%d %H:%M:%S")
    highlight="No major threat detected"
    if rows:
        latest=rows[0]
        highlight=f"{latest[3]} threat {latest[0]} via {latest[2]} at {malaysia_time}"

    ticker=[f"{r[3]} {r[0]} via {r[2]}" for r in rows[:15]]

    html = """
<!DOCTYPE html>
<html>
<head>
<title>RedShark SOC Platform</title>
<link rel="stylesheet" href="https://cdn.datatables.net/1.13.6/css/jquery.dataTables.min.css">
<script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
<script src="https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js"></script>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
body{background:#020617;color:white;font-family:Arial}
h1{text-align:center;color:#38bdf8}
.highlight{background:#1e293b;padding:15px;margin:20px;border-left:5px solid red}
.ticker{padding:10px;border-top:1px solid #334155;border-bottom:1px solid #334155;white-space:nowrap;overflow-x:auto}
#map{height:450px;margin:20px}
#mitre{height:250px;margin:20px}
.low{color:green}
.medium{color:orange}
.high{color:red}
.critical{color:red;font-weight:bold;animation:blink 1s infinite}
@keyframes blink{50%{opacity:0}}
</style>
</head>
<body>
<h1>RedShark SOC Platform</h1>
<div class="highlight"><b>Latest Malaysia Security Highlight (GMT+8)</b><br>{{highlight}}</div>
<form method="get" style="text-align:center">
<input name="q" placeholder="Search IOC"><button type="submit">Search</button>
</form>
<div class="ticker">{% for t in ticker %}🚨 {{t}} &nbsp;&nbsp;{% endfor %}</div>
<div id="map"></div>
<canvas id="mitre"></canvas>
<table id="cti" class="display">
<thead>
<tr>
<th>Indicator</th><th>Type</th><th>Source</th><th>Severity</th><th>MITRE</th><th>Score</th><th>Country</th><th>Last Seen</th>
</tr>
</thead>
<tbody>
{% for r in rows %}
<tr>
<td>{{r[0]}}</td><td>{{r[1]}}</td><td>{{r[2]}}</td><td class="{{r[3]|lower}}">{{r[3]}}</td><td>{{r[4]}}</td><td>{{r[5]}}</td><td>{{r[6]}}</td><td>{{r[9]}}</td>
</tr>
{% endfor %}
</tbody>
</table>
<div style="text-align:center;margin:20px">
<button onclick="window.location='/export/json'">JSON</button>
<button onclick="window.location='/export/csv'">CSV</button>
<button onclick="window.location='/export/pdf'">PDF</button>
<button onclick="window.location='/export/ids'">IDS</button>
<button onclick="window.location='/export/zip'">IOC ZIP</button>
<button onclick="window.location='/refresh'">Refresh</button>
</div>
<script>
$(document).ready(function(){ $('#cti').DataTable({pageLength:50})})
var map=L.map('map').setView([20,0],2)
L.tileLayer('https://tile.openstreetmap.org/{z}/{x}/{y}.png').addTo(map)
var points={{rows|tojson}}
points.forEach(function(p){
var lat=p[7],lon=p[8],color="blue"
if(p[3]=="Low")color="green"
if(p[3]=="Medium")color="orange"
if(p[3]=="High")color="red"
if(p[3]=="Critical")color="darkred"
L.circleMarker([lat,lon],{radius:7,color:color,fillOpacity:0.7}).addTo(map)
.bindPopup(p[0]+"<br>"+p[3])
})
var mitre_labels = {{rows|map(attribute=4)|list|tojson}}
var mitre_counts = {}
mitre_labels.forEach(function(m){ mitre_counts[m]=(mitre_counts[m]||0)+1 })
var ctx = document.getElementById('mitre').getContext('2d')
new Chart(ctx,{type:'bar',data:{labels:Object.keys(mitre_counts),datasets:[{label:'MITRE ATT&CK Count',data:Object.values(mitre_counts),backgroundColor:'rgba(56,189,248,0.7)'}]},options:{plugins:{legend:{display:false}}}})
</script>
</body>
</html>
"""
    return render_template_string(html,rows=rows,highlight=highlight,ticker=ticker)

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
    c.execute("SELECT indicator,type,source,severity,mitre FROM indicators LIMIT 100")
    rows=c.fetchall(); conn.close()
    buffer=io.BytesIO(); doc=SimpleDocTemplate(buffer,pagesize=letter)
    table=Table(rows); doc.build([table]); buffer.seek(0)
    return send_file(buffer,as_attachment=True,download_name="redshark_report.pdf")

@app.route("/export/ids")
def export_ids():
    conn=sqlite3.connect(DB_FILE); c=conn.cursor()
    c.execute("SELECT indicator FROM indicators WHERE type='IP'"); rows=c.fetchall(); conn.close()
    rules=""; sid=100000
    for r in rows: rules+=f'alert ip {r[0]} any -> any any (msg:"RedShark IOC"; sid:{sid}; rev:1;)\\n'; sid+=1
    return send_file(io.BytesIO(rules.encode()),as_attachment=True,download_name="redshark.rules")

@app.route("/export/zip")
def export_zip():
    conn=sqlite3.connect(DB_FILE); c=conn.cursor()
    c.execute("SELECT indicator FROM indicators"); rows=c.fetchall(); conn.close()
    mem=io.BytesIO()
    with zipfile.ZipFile(mem,'w',zipfile.ZIP_DEFLATED) as z: z.writestr("ioc_list.txt","\\n".join([r[0] for r in rows]))
    mem.seek(0)
    return send_file(mem,as_attachment=True,download_name="redshark_iocs.zip")

# ---------------- REFRESH ---------------- #
@app.route("/refresh")
def refresh():
    save_iocs(generate_feed())
    return "Threat feed refreshed"

# ---------------- RUN ---------------- #
if __name__=="__main__":
    app.run(host="0.0.0.0",port=5000)