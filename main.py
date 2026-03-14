import os
import io
import csv
import json
import random
import sqlite3
import zipfile
from datetime import datetime
from flask import Flask, render_template_string, send_file, jsonify

app = Flask(__name__)
DB_FILE = os.path.join("/tmp","redshark_v16_3.db")
DISCLAIMER = "Developed and analysed by darkgrid@redshark.my using publicly available sources"

# ---------------- STATE CAPITALS (Ibu Negeri) ---------------- #
malaysia_capitals = [
    ("Johor Bahru", 1.4927, 103.7414),
    ("Alor Setar", 6.1200, 100.3675),
    ("Kota Bharu", 6.1250, 102.2383),
    ("Malacca City", 2.1896, 102.2501),
    ("Seremban", 2.7290, 101.9387),
    ("Kuantan", 3.8070, 103.3268),
    ("Ipoh", 4.5975, 101.0901),
    ("Kangar", 6.4400, 100.2000),
    ("George Town", 5.4141, 100.3288),
    ("Kota Kinabalu", 5.9804, 116.0735),
    ("Kuching", 1.5533, 110.3593),
    ("Shah Alam", 3.0738, 101.5183),
    ("Kuala Terengganu", 5.3300, 103.1400),
    ("Kuala Lumpur", 3.1390, 101.6869)
]

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
        city TEXT,
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

# ---------------- GEOIP / LOCATION ---------------- #
def get_geoip_location(ip_type=True):
    """Assign IPs to realistic Malaysian cities"""
    city, lat, lon = random.choice(malaysia_capitals)
    # Slight randomization to avoid exact overlap
    lat += random.uniform(-0.015,0.015)
    lon += random.uniform(-0.015,0.015)
    return city, lat, lon

# ---------------- IOC GENERATOR ---------------- #
def random_ip(): return f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"
def random_domain(): return f"malicious{random.randint(1,999)}.net"
def random_hash(): return os.urandom(16).hex()
def threat_score(sev): return {"Low":random.randint(10,30),"Medium":random.randint(40,60),"High":random.randint(70,85),"Critical":random.randint(90,100)}[sev]

def generate_feed(n=20):
    feeds = ["OTX","Talos","AbuseIPDB"]
    categories = ["Malware","Phishing","Botnet","C2","Recon"]
    mitre_map = [
        "T1046 Network Service Discovery",
        "T1059 Command Execution",
        "T1566 Phishing",
        "T1071 C2 Communication",
        "T1105 Exfiltration",
        "T1190 Exploit Public Application"
    ]
    iocs = []
    for _ in range(n):
        typ = random.choice(["IP","Domain","Hash"])
        indicator = random_ip() if typ=="IP" else random_domain() if typ=="Domain" else random_hash()
        city, lat, lon = get_geoip_location()
        sev = random.choice(["Low","Medium","High","Critical"])
        iocs.append({
            "indicator": indicator,
            "type": typ,
            "source": random.choice(feeds),
            "severity": sev,
            "mitre": random.choice(mitre_map),
            "score": threat_score(sev),
            "category": random.choice(categories),
            "country": "Malaysia",
            "city": city,
            "lat": lat,
            "lon": lon,
            "asn": f"AS{random.randint(1000,99999)}",
            "reputation": random.choice(["malicious","suspicious","clean"]),
            "first_seen": datetime.utcnow().isoformat(),
            "last_seen": datetime.utcnow().isoformat()
        })
    return iocs

def save_iocs(iocs):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    for f in iocs:
        c.execute("""
        INSERT INTO indicators
        (indicator,type,source,severity,mitre,score,category,country,city,lat,lon,asn,reputation,first_seen,last_seen)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,(f["indicator"],f["type"],f["source"],f["severity"],f["mitre"],
             f["score"],f["category"],f["country"],f["city"],f["lat"],f["lon"],
             f["asn"],f["reputation"],f["first_seen"],f["last_seen"]))
    conn.commit()
    conn.close()

# ---------------- DASHBOARD ---------------- #
@app.route("/")
def dashboard():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT * FROM indicators ORDER BY last_seen DESC")
    rows = c.fetchall()
    conn.close()
    html = """<!DOCTYPE html>
<html>
<head>
<title>RedShark Threat Intelligence Platform</title>
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
<th>Indicator</th><th>Type</th><th>Source</th><th>Severity</th><th>Category</th>
<th>MITRE</th><th>Score</th><th>Country</th><th>City</th><th>ASN</th><th>Reputation</th><th>Last Seen</th>
</tr>
</thead>
<tbody>
{% for r in rows %}
<tr>
<td>{{r[1]}}</td><td>{{r[2]}}</td><td>{{r[3]}}</td>
<td class="{{r[4]|lower}}">{{r[4]}}</td><td>{{r[7]}}</td>
<td>{{r[5]}}</td><td>{{r[6]}}</td><td>{{r[8]}}</td>
<td>{{r[9]}}</td><td>{{r[12]}}</td><td>{{r[13]}}</td><td>{{r[15]}}</td>
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
<small id="disclaimer">{{disclaimer}}</small>
<script>
$(document).ready(function(){ $('#cti').DataTable({pageLength:50})})
var map=L.map('map').setView([4.2,102],5)
L.tileLayer('https://tile.openstreetmap.org/{z}/{x}/{y}.png').addTo(map)
{% for r in rows %}
var color="blue"; if("{{r[4]}}"=="Low") color="green"; if("{{r[4]}}"=="Medium") color="orange";
if("{{r[4]}}"=="High") color="red"; if("{{r[4]}}"=="Critical") color="darkred";
L.circleMarker([{{r[10]}},{{r[11]}}],{radius:7,color:color,fillOpacity:0.7}).addTo(map)
.bindPopup("{{r[1]}}<br>{{r[4]}} {{r[7]}} ({{r[9]}})");
{% endfor %}

// MITRE chart
var mitre_labels = {% raw %}{{ rows | map(attribute=5) | list | tojson }}{% endraw %}
var mitre_counts = {}
mitre_labels.forEach(function(m){ mitre_counts[m]=(mitre_counts[m]||0)+1 })
var ctx = document.getElementById('mitre').getContext('2d')
new Chart(ctx,{type:'bar',data:{labels:Object.keys(mitre_counts),datasets:[{label:'MITRE ATT&CK Count',data:Object.values(mitre_counts),backgroundColor:'rgba(56,189,248,0.7)',borderRadius:5,barPercentage:0.6}]} ,options:{plugins:{legend:{display:false}},responsive:true,maintainAspectRatio:false}})

// Severity chart
var sev_labels = ["Low","Medium","High","Critical"]
var sev_data = [0,0,0,0]
{% raw %}
rows.forEach(function(r){ 
  if(r[4]=="Low") sev_data[0]++; if(r[4]=="Medium") sev_data[1]++; 
  if(r[4]=="High") sev_data[2]++; if(r[4]=="Critical") sev_data[3]++;
})
{% endraw %}
var ctx2 = document.getElementById('severity').getContext('2d')
new Chart(ctx2,{type:'doughnut',data:{labels:sev_labels,datasets:[{data:sev_data,backgroundColor:['green','orange','red','darkred']}]},options:{plugins:{legend:{position:'bottom'}},responsive:true,maintainAspectRatio:false}})
</script>
</body>
</html>"""
    return render_template_string(html, rows=rows, disclaimer=DISCLAIMER)

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
    output=io.StringIO(); csv.writer(output).writerows(rows)
    return send_file(io.BytesIO(output.getvalue().encode()),as_attachment=True,download_name="redshark_cti.csv")

@app.route("/export/pdf")
def export_pdf():
    from reportlab.platypus import SimpleDocTemplate, Table
    from reportlab.lib.pagesizes import landscape, letter
    conn=sqlite3.connect(DB_FILE); c=conn.cursor()
    c.execute("SELECT indicator,type,source,severity,mitre,score,category,city FROM indicators LIMIT 100"); rows=c.fetchall(); conn.close()
    buffer=io.BytesIO(); doc=SimpleDocTemplate(buffer,pagesize=landscape(letter))
    table=Table(rows); doc.build([table]); buffer.seek(0)
    return send_file(buffer,as_attachment=True,download_name="redshark_report.pdf")

@app.route("/export/ids")
def export_ids():
    conn=sqlite3.connect(DB_FILE); c=conn.cursor()
    c.execute("SELECT indicator FROM indicators WHERE type='IP'"); rows=c.fetchall(); conn.close()
    rules=""; sid=100000
    for r in rows: rules+=f'alert ip {r[0]} any -> any any (msg:"RedShark IOC"; sid:{sid}; rev:1;)\n'; sid+=1
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
    return "IOC feed refreshed"

# ---------------- RUN ---------------- #
if __name__=="__main__":
    port=int(os.environ.get("PORT",5000))
    app.run(host="0.0.0.0", port=port, debug=True)