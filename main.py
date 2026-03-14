import os
import sqlite3
import requests
import json
import csv
import io
import random
import threading
from datetime import datetime
from flask import Flask, render_template_string, send_file
import plotly.graph_objs as go
import plotly
from reportlab.platypus import SimpleDocTemplate, Table
from reportlab.lib.pagesizes import landscape, A4

app = Flask(__name__)

DB = "/tmp/threats.db"
RULE_FILE = "/tmp/redshark.rules"

# ---------------- DATABASE ----------------
def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = db()
    conn.execute("""
    CREATE TABLE IF NOT EXISTS threats(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        indicator TEXT UNIQUE,
        type TEXT,
        mitre TEXT,
        sector TEXT,
        severity INTEGER,
        lat REAL,
        lon REAL,
        created TEXT
    )
    """)
    conn.commit()
init_db()

# ---------------- STATES & SECTORS ----------------
states = {
    "Johor":[1.49,103.74],"Kedah":[6.11,100.36],"Kelantan":[6.12,102.23],
    "Melaka":[2.18,102.25],"Negeri Sembilan":[2.72,101.94],"Pahang":[3.81,103.32],
    "Perak":[4.59,101.09],"Perlis":[6.44,100.20],"Pulau Pinang":[5.41,100.33],
    "Sabah":[5.98,116.07],"Sarawak":[1.55,110.35],"Selangor":[3.07,101.51],
    "Terengganu":[5.33,103.14],"Kuala Lumpur":[3.13,101.68]
}
sectors = ["Government","Banking","Telecommunications","Energy",
           "Healthcare","Education","Manufacturing",
           "Transportation","Retail","Technology"]
mitre = ["Reconnaissance","Initial Access","Execution",
         "Persistence","Privilege Escalation","Defense Evasion",
         "Credential Access","Discovery","Lateral Movement",
         "Collection","Command and Control","Exfiltration","Impact"]

def rand_loc(): return random.choice(list(states.values()))
def rand_sector(): return random.choice(sectors)
def rand_mitre(): return random.choice(mitre)

# ---------------- INSERT THREAT ----------------
def insert_threat(indicator,typ,severity):
    conn = db()
    if conn.execute("SELECT 1 FROM threats WHERE indicator=?", (indicator,)).fetchone():
        return
    lat, lon = rand_loc()
    m = rand_mitre()
    s = rand_sector()
    created = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    conn.execute("""
    INSERT INTO threats(indicator,type,mitre,sector,severity,lat,lon,created)
    VALUES(?,?,?,?,?,?,?,?)
    """, (indicator, typ, m, s, severity, lat, lon, created))
    conn.commit()
    # IPS RULE GENERATION
    rule_sid = 1000000 + random.randint(1,9999)
    if typ=="ip":
        rule_line = f'alert ip any any -> any any (msg:"RedShark IP {indicator} | MITRE: {m}"; sid:{rule_sid}; rev:1;)\n'
    elif typ=="url":
        rule_line = f'alert http any any -> any any (msg:"RedShark URL {indicator} | MITRE: {m}"; content:"{indicator}"; http_uri; sid:{rule_sid}; rev:1;)\n'
    elif typ=="domain":
        rule_line = f'alert http any any -> any any (msg:"RedShark DOMAIN {indicator} | MITRE: {m}"; content:"{indicator}"; http_host; sid:{rule_sid}; rev:1;)\n'
    elif typ=="hash":
        rule_line = f'# Hash {indicator} | MITRE: {m} (requires file inspection)\n'
    else:
        rule_line = f'# Unknown type {typ} {indicator} | MITRE: {m}\n'
    with open(RULE_FILE,"a") as f:
        f.write(rule_line)

# ---------------- FEEDS ----------------
def fetch_threatfox():
    try:
        url="https://threatfox.abuse.ch/export/json/recent/"
        r = requests.get(url, timeout=10).json()
        for i in r.get("data", [])[:30]:
            insert_threat(i.get("ioc","unknown"), i.get("ioc_type","unknown"), 85)
    except: pass

def fetch_feodo():
    try:
        url="https://feodotracker.abuse.ch/downloads/ipblocklist.json"
        data = requests.get(url, timeout=10).json()
        for i in data[:30]:
            insert_threat(i.get("ip_address","0.0.0.0"), "ip", 90)
    except: pass

def fetch_urlhaus():
    try:
        url="https://urlhaus.abuse.ch/downloads/csv_recent/"
        data = requests.get(url, timeout=10).text.splitlines()
        reader = csv.reader(data)
        for row in list(reader)[10:40]:
            if len(row)>2:
                insert_threat(row[2],"url",70)
    except: pass

def fetch_hashes():
    try:
        url="https://mb-api.abuse.ch/api/v1/"
        r = requests.post(url, data={"query":"get_recent"}, timeout=10).json()
        for item in r.get("data", [])[:30]:
            insert_threat(item.get("sha256_hash",""), "hash", 75)
    except: pass

def fetch_feeds():
    fetch_threatfox()
    fetch_feodo()
    fetch_hashes()
    fetch_urlhaus()

# ---------------- SCHEDULER ----------------
def scheduler():
    try:
        fetch_feeds()
    except Exception as e:
        print("Feed fetch error:", e)
    threading.Timer(900, scheduler).start()  # every 15 min

def start_scheduler():
    threading.Thread(target=scheduler, daemon=True).start()

# ---------------- SECURENATION INDEX ----------------
def securenation():
    rows = db().execute("SELECT severity FROM threats ORDER BY id DESC LIMIT 50").fetchall()
    if not rows: return 0,"#00FF99"
    val = round(sum([r["severity"] for r in rows])/len(rows),1)
    if val>=85: color="#FF3C3C"
    elif val>=70: color="#FFA500"
    else: color="#00FF99"
    return val, color

# ---------------- CTI HIGHLIGHT ----------------
def cti_highlight():
    rows=db().execute("""
        SELECT indicator, type, sector, mitre, severity, created 
        FROM threats ORDER BY id DESC LIMIT 5
    """).fetchall()
    highlights=[]
    for r in rows:
        statement = f"A new {r['type']} indicator targeting {r['sector']} sector leveraging {r['mitre']} detected (Severity {r['severity']})."
        highlights.append({"statement": statement, "created": r["created"]})
    latest_time = rows[0]["created"] if rows else datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    return latest_time, highlights

# ---------------- NIKKEI STYLE CHARTS ----------------
def nikkei_chart(x,y,title):
    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=x, y=y, mode='lines+markers',
        line=dict(color="#00FFCC", width=4, shape='spline', smoothing=1.3),
        marker=dict(size=10, color="#FFFFFF", line=dict(width=2, color="#00FFCC"))
    ))
    fig.update_layout(plot_bgcolor="#0b1b2a",
                      paper_bgcolor="#0b1b2a",
                      font_color="#A3B8CC",
                      title=title,
                      xaxis=dict(showgrid=False),
                      yaxis=dict(showgrid=False))
    return json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

# ---------------- MALAYSIA MAP WITH CLUSTERING ----------------
def malaysia_map():
    rows = db().execute("SELECT lat,lon,severity FROM threats ORDER BY id DESC LIMIT 50").fetchall()
    lat, lon, sev = [r["lat"] for r in rows], [r["lon"] for r in rows], [r["severity"] for r in rows]
    cluster = {}
    for i,(la,lo,s) in enumerate(zip(lat, lon, sev)):
        key = (round(la,1), round(lo,1))
        if key not in cluster: cluster[key]=[]
        cluster[key].append(s)
    cluster_lat = [k[0] for k in cluster.keys()]
    cluster_lon = [k[1] for k in cluster.keys()]
    cluster_sev = [max(v) for v in cluster.values()]
    cluster_size = [len(v)*5 for v in cluster.values()]
    colors = ["#FF3C3C" if s>=85 else "#FF9900" if s>=70 else "#FFFF00" for s in cluster_sev]
    fig = go.Figure()
    fig.add_trace(go.Scattermapbox(
        lat=cluster_lat,
        lon=cluster_lon,
        mode="markers",
        marker=dict(size=cluster_size, color=colors, opacity=0.8),
        text=[f"Severity: {s}" for s in cluster_sev],
        hoverinfo="text"
    ))
    fig.update_layout(
        mapbox_style="carto-darkmatter",
        mapbox_center={"lat":4.5,"lon":102},
        mapbox_zoom=4,
        paper_bgcolor="#0b1b2a",
        margin=dict(l=0,r=0,t=0,b=0),
        mapbox=dict(accesstoken=None)
    )
    return json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

# ---------------- TIMELINE / SECTOR / INDICATOR / MITRE ----------------
def timeline_chart():
    rows=db().execute("SELECT substr(created,1,10) d, COUNT(*) c FROM threats GROUP BY d ORDER BY d").fetchall()
    return nikkei_chart([r["d"] for r in rows],[r["c"] for r in rows],"Threat Timeline")

def sector_chart():
    rows=db().execute("SELECT sector, COUNT(*) c FROM threats GROUP BY sector ORDER BY c DESC").fetchall()
    return nikkei_chart([r["sector"] for r in rows],[r["c"] for r in rows],"Sector Targeting")

def indicator_type_chart():
    rows=db().execute("SELECT type, COUNT(*) c FROM threats GROUP BY type").fetchall()
    return nikkei_chart([r["type"] for r in rows],[r["c"] for r in rows],"Indicator Type Distribution")

def mitre_chart():
    rows=db().execute("SELECT mitre, COUNT(*) c FROM threats GROUP BY mitre").fetchall()
    return nikkei_chart([r["mitre"] for r in rows],[r["c"] for r in rows],"MITRE Techniques Trend")

# ---------------- DASHBOARD HTML ----------------
HTML = """(Use your existing HTML template)
<!-- Add JS from previous step for blinking + auto-refresh -->
"""

# ---------------- DASHBOARD ROUTE ----------------
@app.route("/")
def dashboard():
    index, index_color = securenation()
    highlight_time, highlights = cti_highlight()
    rows=db().execute("SELECT * FROM threats ORDER BY id DESC LIMIT 50").fetchall()
    return render_template_string(
        HTML,
        rows=rows,
        index=index,
        index_color=index_color,
        highlight_time=highlight_time,
        highlights=highlights,
        timeline=timeline_chart(),
        mitre=mitre_chart(),
        sector=sector_chart(),
        indicator_type=indicator_type_chart(),
        map=malaysia_map()
    )

# ---------------- EXPORT ROUTES ----------------
@app.route("/csv")
def csv_export():
    rows=db().execute("SELECT * FROM threats").fetchall()
    out=io.StringIO()
    writer=csv.writer(out)
    if rows: writer.writerow(rows[0].keys())
    for r in rows: writer.writerow(list(r))
    mem=io.BytesIO(); mem.write(out.getvalue().encode()); mem.seek(0)
    return send_file(mem,download_name="threats.csv",as_attachment=True)

@app.route("/json")
def json_export():
    rows=db().execute("SELECT * FROM threats").fetchall()
    data=[dict(r) for r in rows]
    mem=io.BytesIO(); mem.write(json.dumps(data,indent=2).encode()); mem.seek(0)
    return send_file(mem,download_name="threats.json",as_attachment=True)

@app.route("/pdf")
def pdf_export():
    rows=db().execute("SELECT indicator,type,sector,severity,mitre,created FROM threats LIMIT 50").fetchall()
    buffer=io.BytesIO()
    data=[["Indicator","Type","Sector","Severity","MITRE","Timestamp"]]
    for r in rows:
        data.append([r["indicator"],r["type"],r["sector"],r["severity"],r["mitre"],r["created"]])
    pdf=SimpleDocTemplate(buffer,pagesize=landscape(A4))
    table=Table(data)
    pdf.build([table])
    buffer.seek(0)
    return send_file(buffer,download_name="redshark-cti-report.pdf",as_attachment=True)

@app.route("/download_ips")
def download_ips():
    if not os.path.exists(RULE_FILE):
        open(RULE_FILE,"w").close()
    return send_file(RULE_FILE, download_name="redshark-ips-signatures.rules", as_attachment=True)

# ---------------- STARTUP ----------------
try:
    fetch_feeds()  # initial fetch
except Exception as e:
    print("Initial fetch failed:", e)
start_scheduler()

if __name__=="__main__":
    app.run(host="0.0.0.0", port=5000)