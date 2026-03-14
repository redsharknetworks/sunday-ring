import os
import io
import csv
import json
import random
import sqlite3
import zipfile
from datetime import datetime, timedelta
from flask import Flask, render_template_string, send_file, jsonify

app = Flask(__name__)
DB_FILE = os.path.join("/tmp","redshark_v16.db")  # Render-safe
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

    # Prepopulate sample Malaysian IOCs
    c.execute("SELECT COUNT(*) FROM indicators")
    if c.fetchone()[0]==0:
        sample = []
        for _ in range(15):
            lat = random.uniform(1.0, 7.5)       # Malaysia lat
            lon = random.uniform(99.5, 119.0)    # Malaysia lon
            sev = random.choice(["Low","Medium","High","Critical"])
            sample.append((
                f"malicious{random.randint(1,999)}.net",
                "Domain",
                random.choice(["OTX","Talos","AbuseIPDB"]),
                sev,
                random.choice([
                    "T1046 Network Service Discovery",
                    "T1059 Command Execution",
                    "T1566 Phishing",
                    "T1071 C2 Communication",
                    "T1105 Exfiltration",
                    "T1190 Exploit Public Application"
                ]),
                {"Low":20,"Medium":50,"High":75,"Critical":95}[sev],
                random.choice(["Malware","Phishing","Botnet","C2","Recon"]),
                "Malaysia",
                lat,
                lon,
                f"AS{random.randint(1000,99999)}",
                random.choice(["malicious","suspicious","clean"]),
                datetime.utcnow().isoformat(),
                datetime.utcnow().isoformat()
            ))
        c.executemany("""
        INSERT INTO indicators(indicator,type,source,severity,mitre,score,category,country,lat,lon,asn,reputation,first_seen,last_seen)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, sample)
        conn.commit()
    conn.close()

init_db()

# ---------------- IOC GENERATOR ---------------- #
def random_ip(): return f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"
def random_domain(): return f"malicious{random.randint(1,999)}.net"
def random_hash(): return os.urandom(16).hex()
def threat_score(sev): return {"Low": random.randint(10,30),"Medium": random.randint(40,60),"High": random.randint(70,85),"Critical": random.randint(90,100)}[sev]
def enrich_ioc(typ): return (f"AS{random.randint(1000,99999)}", random.choice(["malicious","suspicious","clean"]))

def generate_feed():
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
    data = []
    for _ in range(random.randint(12,25)):
        typ = random.choice(["IP","Domain","Hash"])
        indicator = random_ip() if typ=="IP" else random_domain() if typ=="Domain" else random_hash()
        lat = random.uniform(1.0, 7.5)       # Malaysia-focused
        lon = random.uniform(99.5, 119.0)
        sev = random.choice(["Low","Medium","High","Critical"])
        category = random.choice(categories)
        asn, reputation = enrich_ioc(typ)
        data.append({
            "indicator": indicator,
            "type": typ,
            "source": random.choice(feeds),
            "severity": sev,
            "mitre": random.choice(mitre_map),
            "score": threat_score(sev),
            "category": category,
            "country": "Malaysia",
            "lat": lat,
            "lon": lon,
            "asn": asn,
            "reputation": reputation,
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
        (indicator,type,source,severity,mitre,score,category,country,lat,lon,asn,reputation,first_seen,last_seen)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,(f["indicator"],f["type"],f["source"],f["severity"],f["mitre"],
             f["score"],f["category"],f["country"],f["lat"],f["lon"],
             f["asn"], f["reputation"], f["first_seen"], f["last_seen"]))
    conn.commit()
    conn.close()

# ---------------- DASHBOARD ---------------- #
@app.route("/")
def dashboard():
    conn = sqlite3.connect(DB_FILE); c = conn.cursor()
    c.execute("SELECT * FROM indicators ORDER BY last_seen DESC")
    rows = c.fetchall(); conn.close()
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
<th>MITRE</th><th>Score</th><th>Country</th><th>ASN</th><th>Reputation</th><th>Last Seen</th>
</tr>
</thead>
<tbody>
{% for r in rows %}
<tr>
<td>{{r[1]}}</td><td>{{r[2]}}</td><td>{{r[3]}}</td>
<td class="{{r[4]|lower}}">{{r[4]}}</td><td>{{r[7]}}</td>
<td>{{r[5]}}</td><td>{{r[6]}}</td><td>{{r[8]}}</td>
<td>{{r[10]}}</td><td>{{r[11]}}</td><td>{{r[14]}}</td>
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
L.circleMarker([{{r[9]}},{{r[10]}}],{radius:7,color:color,fillOpacity:0.7}).addTo(map)
.bindPopup("{{r[1]}}<br>{{r[4]}} {{r[7]}}");
{% endfor %}
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
    c.execute("SELECT indicator,type,source,severity,mitre,score,category FROM indicators LIMIT 100"); rows=c.fetchall(); conn.close()
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