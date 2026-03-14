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

from flask import Flask, render_template_string, send_file, jsonify
import requests

app = Flask(__name__)

DB_FILE="redshark_cti.db"

# ------------------------------------------------
# DATABASE INIT
# ------------------------------------------------

def init_db():

    conn=sqlite3.connect(DB_FILE)
    cursor=conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS indicators(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    indicator TEXT,
    type TEXT,
    source TEXT,
    severity TEXT,
    country TEXT,
    first_seen TEXT,
    last_seen TEXT
    )
    """)

    conn.commit()
    conn.close()

init_db()

# ------------------------------------------------
# MALAYSIA REGIONS
# ------------------------------------------------

malaysia_regions=[
("Kuala Lumpur",3.1390,101.6869),
("Cyberjaya",2.9225,101.6559),
("Penang",5.4164,100.3327),
("Johor",1.4927,103.7414),
("Sabah",5.9804,116.0735),
("Sarawak",1.5533,110.3592)
]

# ------------------------------------------------
# IOC GENERATOR
# ------------------------------------------------

def random_ip():
    return f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"

def random_domain():
    return f"bad{random.randint(1,999)}.com"

def random_hash():
    return os.urandom(16).hex()

# ------------------------------------------------
# SIMULATED THREAT FEED
# ------------------------------------------------

def generate_feed():

    feeds=["OTX","AbuseIPDB","Talos"]

    data=[]

    for i in range(random.randint(5,15)):

        typ=random.choice(["IP","Domain","Hash"])

        if typ=="IP":
            indicator=random_ip()
        elif typ=="Domain":
            indicator=random_domain()
        else:
            indicator=random_hash()

        region=random.choice(malaysia_regions)

        data.append({

        "indicator":indicator,
        "type":typ,
        "source":random.choice(feeds),
        "severity":random.choice(["Low","Medium","High","Critical"]),
        "country":region[0],
        "first_seen":datetime.utcnow().isoformat(),
        "last_seen":datetime.utcnow().isoformat()

        })

    return data

# ------------------------------------------------
# SAVE IOC
# ------------------------------------------------

def save_iocs(feed):

    conn=sqlite3.connect(DB_FILE)
    cursor=conn.cursor()

    for f in feed:

        cursor.execute("""
        INSERT INTO indicators
        (indicator,type,source,severity,country,first_seen,last_seen)
        VALUES (?,?,?,?,?,?,?)
        """,(
        f["indicator"],
        f["type"],
        f["source"],
        f["severity"],
        f["country"],
        f["first_seen"],
        f["last_seen"]
        ))

    conn.commit()
    conn.close()

# ------------------------------------------------
# BACKGROUND ENGINE
# ------------------------------------------------

def threat_engine():

    while True:

        feed=generate_feed()
        save_iocs(feed)

        time.sleep(120)

threading.Thread(target=threat_engine,daemon=True).start()

# ------------------------------------------------
# DASHBOARD
# ------------------------------------------------

@app.route("/")
def dashboard():

    conn=sqlite3.connect(DB_FILE)
    cursor=conn.cursor()

    cursor.execute("""
    SELECT indicator,type,source,severity,country,first_seen,last_seen
    FROM indicators
    ORDER BY last_seen DESC
    """)

    rows=cursor.fetchall()
    conn.close()

    map_points=[]

    for r in rows:

        region=random.choice(malaysia_regions)

        map_points.append({
        "indicator":r[0],
        "type":r[1],
        "source":r[2],
        "severity":r[3],
        "lat":region[1],
        "lon":region[2]
        })

    malaysia_time=(datetime.utcnow()+timedelta(hours=8)).strftime("%Y-%m-%d %H:%M:%S")

    highlight="No threat detected"

    if rows:

        latest=rows[0]

        highlight=f"{latest[3]} threat {latest[0]} detected via {latest[2]} at {malaysia_time}"

    ticker=[f"{r[3]} {r[0]} via {r[2]}" for r in rows[:10]]

    html="""

<!DOCTYPE html>
<html>

<head>

<title>RedShark Threat Intelligence Dashboard</title>

<link rel="stylesheet"
href="https://cdn.datatables.net/1.13.6/css/jquery.dataTables.min.css">

<script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>

<script src="https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js"></script>

<link rel="stylesheet"
href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>

<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>

<style>

body{background:#020617;color:white;font-family:Arial}

h1{text-align:center;color:#38bdf8}

.highlight{background:#1e293b;padding:15px;margin:20px;border-left:5px solid red}

.ticker{padding:10px;border-top:1px solid #334155;border-bottom:1px solid #334155}

#map{height:450px;margin:20px}

.low{color:green}
.medium{color:orange}
.high{color:red}
.critical{color:darkred;font-weight:bold;animation:blink 1s infinite}

@keyframes blink{50%{opacity:0}}

</style>

</head>

<body>

<h1>RedShark Threat Intelligence Dashboard</h1>

<div class="highlight">
<b>Latest Security Highlight</b><br>
{{highlight}}
</div>

<div class="ticker">
{% for t in ticker %}
🚨 {{t}} &nbsp;&nbsp;
{% endfor %}
</div>

<div id="map"></div>

<table id="ctitable" class="display">

<thead>

<tr>
<th>Indicator</th>
<th>Type</th>
<th>Source</th>
<th>Severity</th>
<th>Region</th>
<th>First Seen</th>
<th>Last Seen</th>
</tr>

</thead>

<tbody>

{% for r in rows %}

<tr>
<td>{{r[0]}}</td>
<td>{{r[1]}}</td>
<td>{{r[2]}}</td>
<td class="{{r[3]|lower}}">{{r[3]}}</td>
<td>{{r[4]}}</td>
<td>{{r[5]}}</td>
<td>{{r[6]}}</td>
</tr>

{% endfor %}

</tbody>
</table>

<div style="text-align:center;margin:40px;">

<button onclick="window.location='/export/json'">Download JSON</button>

<button onclick="window.location='/export/csv'">Download CSV</button>

<button onclick="window.location='/export/report'">Download PDF</button>

<button onclick="window.location='/export/ids'">IDS Rules</button>

<button onclick="window.location='/export/zip'">IOC ZIP</button>

<button onclick="window.location='/analytics'">SOC Analytics</button>

<button onclick="window.location='/refresh'">Refresh Feed</button>

</div>

<script>

$(document).ready(function(){

$('#ctitable').DataTable({
pageLength:50
})

})

var map=L.map('map').setView([4.5,102],6)

L.tileLayer('https://tile.openstreetmap.org/{z}/{x}/{y}.png').addTo(map)

var points={{map_points|tojson}}

points.forEach(function(p){

var color="blue"

if(p.severity=="Low")color="green"
if(p.severity=="Medium")color="orange"
if(p.severity=="High")color="red"
if(p.severity=="Critical")color="darkred"

L.circleMarker([p.lat,p.lon],{
radius:8,
color:color,
fillOpacity:0.7
}).addTo(map)
.bindPopup(p.indicator+"<br>"+p.severity)

})

</script>

</body>
</html>

"""

    return render_template_string(html,
        rows=rows,
        map_points=map_points,
        highlight=highlight,
        ticker=ticker)

# ------------------------------------------------
# ANALYTICS
# ------------------------------------------------

@app.route("/analytics")
def analytics():

    conn=sqlite3.connect(DB_FILE)
    cursor=conn.cursor()

    cursor.execute("SELECT severity,COUNT(*) FROM indicators GROUP BY severity")
    sev=cursor.fetchall()

    conn.close()

    return jsonify(sev)

# ------------------------------------------------
# EXPORT JSON
# ------------------------------------------------

@app.route("/export/json")
def export_json():

    conn=sqlite3.connect(DB_FILE)
    cursor=conn.cursor()

    cursor.execute("SELECT * FROM indicators")
    rows=cursor.fetchall()

    conn.close()

    return jsonify(rows)

# ------------------------------------------------
# EXPORT CSV
# ------------------------------------------------

@app.route("/export/csv")
def export_csv():

    conn=sqlite3.connect(DB_FILE)
    cursor=conn.cursor()

    cursor.execute("SELECT * FROM indicators")
    rows=cursor.fetchall()

    conn.close()

    output=io.StringIO()

    writer=csv.writer(output)
    writer.writerows(rows)

    output.seek(0)

    return send_file(io.BytesIO(output.getvalue().encode()),
    as_attachment=True,
    download_name="redshark_cti.csv")

# ------------------------------------------------
# IDS RULES
# ------------------------------------------------

@app.route("/export/ids")
def export_ids():

    conn=sqlite3.connect(DB_FILE)
    cursor=conn.cursor()

    cursor.execute("SELECT indicator FROM indicators WHERE type='IP'")
    rows=cursor.fetchall()

    conn.close()

    rules=""

    sid=100000

    for r in rows:

        rules+=f'alert ip {r[0]} any -> any any (msg:"RedShark IOC"; sid:{sid}; rev:1;)\n'
        sid+=1

    return send_file(io.BytesIO(rules.encode()),
    as_attachment=True,
    download_name="redshark.rules")

# ------------------------------------------------
# ZIP IOC
# ------------------------------------------------

@app.route("/export/zip")
def export_zip():

    conn=sqlite3.connect(DB_FILE)
    cursor=conn.cursor()

    cursor.execute("SELECT indicator FROM indicators")
    rows=cursor.fetchall()

    conn.close()

    mem=io.BytesIO()

    with zipfile.ZipFile(mem,'w',zipfile.ZIP_DEFLATED) as z:

        z.writestr("ioc.txt","\n".join([r[0] for r in rows]))

    mem.seek(0)

    return send_file(mem,
    as_attachment=True,
    download_name="redshark_iocs.zip")

# ------------------------------------------------
# PDF REPORT
# ------------------------------------------------

@app.route("/export/report")
def export_report():

    from reportlab.platypus import SimpleDocTemplate,Table
    from reportlab.lib.pagesizes import letter

    conn=sqlite3.connect(DB_FILE)
    cursor=conn.cursor()

    cursor.execute("SELECT * FROM indicators LIMIT 100")
    rows=cursor.fetchall()

    conn.close()

    buffer=io.BytesIO()

    doc=SimpleDocTemplate(buffer,pagesize=letter)

    table=Table(rows)

    doc.build([table])

    buffer.seek(0)

    return send_file(buffer,
    as_attachment=True,
    download_name="redshark_report.pdf")

# ------------------------------------------------
# MANUAL REFRESH
# ------------------------------------------------

@app.route("/refresh")
def refresh():

    save_iocs(generate_feed())

    return "Threat feed refreshed"

# ------------------------------------------------

if __name__=="__main__":

    app.run(host="0.0.0.0",port=5000)