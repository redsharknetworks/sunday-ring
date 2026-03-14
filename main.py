import os
import io
import csv
import json
import random
import sqlite3
import zipfile
from datetime import datetime, timedelta
from flask import Flask, render_template_string, send_file, jsonify, request
from reportlab.platypus import SimpleDocTemplate, Table
from reportlab.lib.pagesizes import letter
from apscheduler.schedulers.background import BackgroundScheduler

app = Flask(__name__)
DB_FILE = "redshark_v11.db"

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
def threat_score(sev): return {"Low": random.randint(10,30),"Medium": random.randint(40,60),"High": random.randint(70,85),"Critical": random.randint(90,100)}[sev]
def random_location(): return (random.uniform(-90,90), random.uniform(-180,180))

def generate_feed(num_entries=25):
    feeds=["OTX","Talos","AbuseIPDB"]
    data=[]
    for _ in range(num_entries):
        typ=random.choice(["IP","Domain","Hash"])
        indicator=random_ip() if typ=="IP" else random_domain() if typ=="Domain" else random_hash()
        lat, lon = random_location()
        sev=random.choice(["Low","Medium","High","Critical"])
        data.append({
            "indicator":indicator,
            "type":typ,
            "source":random.choice(feeds),
            "severity":sev,
            "mitre":random.choice(mitre_map),
            "score":threat_score(sev),
            "country":"Global",
            "lat":lat,
            "lon":lon,
            "first_seen":datetime.utcnow().isoformat(),
            "last_seen":datetime.utcnow().isoformat()
        })
    return data

def save_iocs(feed):
    conn=sqlite3.connect(DB_FILE)
    c=conn.cursor()
    for f in feed:
        c.execute("""
        INSERT INTO indicators(indicator,type,source,severity,mitre,score,country,lat,lon,first_seen,last_seen)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)
        """,(f["indicator"],f["type"],f["source"],f["severity"],f["mitre"],
             f["score"],f["country"],f["lat"],f["lon"],f["first_seen"],f["last_seen"]))
    conn.commit(); conn.close()

# ---------------- SCHEDULED INGESTION ---------------- #
def scheduled_ingest():
    save_iocs(generate_feed(25))
    print(f"[{datetime.utcnow().isoformat()}] Saved 25 IOCs")
scheduler = BackgroundScheduler()
scheduler.add_job(scheduled_ingest,'interval',minutes=1)
scheduler.start()

# ---------------- DASHBOARD ---------------- #
@app.route("/")
def dashboard():
    search=request.args.get("q","")
    conn=sqlite3.connect(DB_FILE); c=conn.cursor()
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
    rows=c.fetchall(); conn.close()
    
    malaysia_time=(datetime.utcnow()+timedelta(hours=8)).strftime("%Y-%m-%d %H:%M:%S")
    highlight="No major threat detected"
    malaysia_rows=[r for r in rows if -1<r[7]<10 and 100<r[8]<120]
    if malaysia_rows:
        latest=malaysia_rows[0]
        highlight=f"{latest[3]} threat {latest[0]} via {latest[2]} at {malaysia_time}"
    ticker=[f"{r[3]} {r[0]} via {r[2]}" for r in rows[:15]]
    
    html = """..."""  # Same as previous v11.5 dashboard HTML (with global map, MITRE chart, table, download buttons, disclaimer)
    return render_template_string(html, rows=rows, highlight=highlight, ticker=ticker)

# ---------------- EXPORTS ---------------- #
@app.route("/export/json")
def export_json():
    conn=sqlite3.connect(DB_FILE); c=conn.cursor(); c.execute("SELECT * FROM indicators"); rows=c.fetchall(); conn.close()
    return jsonify(rows)

@app.route("/export/csv")
def export_csv():
    conn=sqlite3.connect(DB_FILE); c=conn.cursor(); c.execute("SELECT * FROM indicators"); rows=c.fetchall(); conn.close()
    output=io.StringIO(); csv.writer(output).writerows(rows)
    return send_file(io.BytesIO(output.getvalue().encode()),as_attachment=True,download_name="redshark_cti.csv")

@app.route("/export/pdf")
def export_pdf():
    conn=sqlite3.connect(DB_FILE); c=conn.cursor(); c.execute("SELECT indicator,type,source,severity,mitre FROM indicators LIMIT 100"); rows=c.fetchall(); conn.close()
    buffer=io.BytesIO(); SimpleDocTemplate(buffer,pagesize=letter).build([Table(rows)]); buffer.seek(0)
    return send_file(buffer,as_attachment=True,download_name="redshark_report.pdf")

@app.route("/export/ids")
def export_ids():
    conn=sqlite3.connect(DB_FILE); c=conn.cursor(); c.execute("SELECT indicator FROM indicators WHERE type='IP'"); rows=c.fetchall(); conn.close()
    rules=""; sid=100000
    for r in rows: rules+=f'alert ip {r[0]} any -> any any (msg:"RedShark IOC"; sid:{sid}; rev:1;)\\n'; sid+=1
    return send_file(io.BytesIO(rules.encode()),as_attachment=True,download_name="redshark.rules")

@app.route("/export/zip")
def export_zip():
    conn=sqlite3.connect(DB_FILE); c=conn.cursor(); c.execute("SELECT indicator FROM indicators"); rows=c.fetchall(); conn.close()
    mem=io.BytesIO()
    with zipfile.ZipFile(mem,'w',zipfile.ZIP_DEFLATED) as z: z.writestr("ioc_list.txt","\n".join([r[0] for r in rows]))
    mem.seek(0)
    return send_file(mem,as_attachment=True,download_name="redshark_iocs.zip")

@app.route("/refresh")
def refresh():
    save_iocs(generate_feed(25))
    return f"Threat feed refreshed (25 new entries)"

# ---------------- RUN ---------------- #
if __name__=="__main__":
    app.run(host="0.0.0.0",port=5000)