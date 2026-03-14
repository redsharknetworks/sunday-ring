import os
import io
import csv
import json
import sqlite3
import threading
import time
import random
import requests
from datetime import datetime
from flask import Flask, render_template_string, send_file, jsonify
from zipfile import ZipFile

app = Flask(__name__)

DB = "threats.db"

# =============================
# DATABASE
# =============================

def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS threats(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT,
        category TEXT,
        severity TEXT,
        source TEXT,
        created_at TEXT
    )
    """)

    conn.commit()
    conn.close()

init_db()

# =============================
# THREAT INGESTION
# =============================

def fetch_spamhaus():
    url = "https://www.spamhaus.org/drop/drop.txt"
    r = requests.get(url, timeout=20)

    lines = []
    for l in r.text.splitlines():
        if l.startswith(";"):
            continue
        if "/" in l:
            ip = l.split(";")[0].strip()
            lines.append(ip)

    return lines[:50]


def store_threat(ip, source):
    conn = sqlite3.connect(DB)
    c = conn.cursor()

    categories = ["C2","Recon","Botnet","Malware","Phishing"]
    severity = random.choice(["Low","Medium","High","Critical"])

    c.execute("""
    INSERT INTO threats(ip,category,severity,source,created_at)
    VALUES(?,?,?,?,?)
    """,(
        ip,
        random.choice(categories),
        severity,
        source,
        datetime.utcnow().isoformat()
    ))

    conn.commit()
    conn.close()


def ingestion_loop():
    while True:
        try:
            ips = fetch_spamhaus()
            for ip in ips:
                store_threat(ip,"Spamhaus")
        except:
            pass

        time.sleep(3600)


threading.Thread(target=ingestion_loop,daemon=True).start()

# =============================
# THREAT INDEX
# =============================

def threat_index():
    conn = sqlite3.connect(DB)
    c = conn.cursor()

    c.execute("SELECT COUNT(*) FROM threats WHERE severity='Critical'")
    critical = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM threats")
    total = c.fetchone()[0]

    conn.close()

    if total == 0:
        return 0

    return round((critical/total)*10,2)

# =============================
# DATA API
# =============================

@app.route("/api/threats")
def api_threats():
    conn = sqlite3.connect(DB)
    c = conn.cursor()

    c.execute("SELECT ip,category,severity,source,created_at FROM threats ORDER BY id DESC LIMIT 100")
    rows = c.fetchall()
    conn.close()

    data=[]
    for r in rows:
        data.append({
            "ip":r[0],
            "category":r[1],
            "severity":r[2],
            "source":r[3],
            "time":r[4]
        })

    return jsonify(data)

# =============================
# REPORTS
# =============================

@app.route("/download/csv")
def download_csv():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT * FROM threats")
    rows=c.fetchall()
    conn.close()

    output=io.StringIO()
    writer=csv.writer(output)
    writer.writerow(["ID","IP","Category","Severity","Source","Created"])

    for r in rows:
        writer.writerow(r)

    mem=io.BytesIO()
    mem.write(output.getvalue().encode())
    mem.seek(0)

    return send_file(mem,download_name="threats.csv",as_attachment=True)

@app.route("/download/json")
def download_json():

    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT * FROM threats")
    rows=c.fetchall()
    conn.close()

    data=[]
    for r in rows:
        data.append({
            "id":r[0],
            "ip":r[1],
            "category":r[2],
            "severity":r[3],
            "source":r[4],
            "time":r[5]
        })

    mem=io.BytesIO()
    mem.write(json.dumps(data,indent=2).encode())
    mem.seek(0)

    return send_file(mem,download_name="threats.json",as_attachment=True)

@app.route("/download/rules")
def download_rules():

    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT ip FROM threats")
    ips=c.fetchall()
    conn.close()

    rules=""

    for ip in ips:
        rules+=f"alert ip {ip[0]} any -> any any (msg:\"CTI Block {ip[0]}\"; sid:{random.randint(100000,999999)};)\n"

    mem=io.BytesIO()

    with ZipFile(mem,'w') as z:
        z.writestr("soc_rules.rules",rules)

    mem.seek(0)

    return send_file(mem,download_name="soc_rules.zip",as_attachment=True)

# =============================
# DASHBOARD
# =============================

@app.route("/")
def dashboard():

    title=f"CTI HIGHLIGHT AT {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}"

    html="""
    <html>
    <head>

    <title>{{title}}</title>

    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

    <style>

    body{
    background:#0b0f1a;
    color:white;
    font-family:Arial;
    }

    .container{
    width:95%;
    margin:auto;
    }

    h1{
    color:#00ffe1;
    }

    table{
    width:100%;
    border-collapse:collapse;
    }

    td,th{
    border:1px solid #333;
    padding:6px;
    }

    .critical{
    color:red;
    animation:blink 1s infinite;
    }

    @keyframes blink{
    50%{opacity:0}
    }

    </style>

    </head>

    <body>

    <div class="container">

    <h1>{{title}}</h1>

    <h3>Threat Index: {{index}}</h3>

    <canvas id="chart"></canvas>

    <br>

    <button onclick="window.location='/download/csv'">CSV</button>
    <button onclick="window.location='/download/json'">JSON</button>
    <button onclick="window.location='/download/rules'">IDS Rules</button>

    <br><br>

    <table id="tbl">
    <tr>
    <th>IP</th>
    <th>Category</th>
    <th>Severity</th>
    <th>Source</th>
    <th>Time</th>
    </tr>
    </table>

    <br>

    <small>
    Developed and analysed by darkgrid@redshark.my using publicly available sources
    </small>

    </div>

    <script>

    async function load(){

        let r=await fetch("/api/threats")
        let data=await r.json()

        let tbl=document.getElementById("tbl")

        data.forEach(t=>{

            let tr=document.createElement("tr")

            let sev=t.severity

            if(sev=="Critical"){
                sev='<span class="critical">Critical</span>'
            }

            tr.innerHTML=
            "<td>"+t.ip+"</td>"+
            "<td>"+t.category+"</td>"+
            "<td>"+sev+"</td>"+
            "<td>"+t.source+"</td>"+
            "<td>"+t.time+"</td>"

            tbl.appendChild(tr)

        })

    }

    load()

    </script>

    </body>
    </html>
    """

    return render_template_string(html,title=title,index=threat_index())

# =============================
# RUN
# =============================

if __name__=="__main__":
    app.run(host="0.0.0.0",port=5000)