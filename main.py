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
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table
from reportlab.lib.pagesizes import landscape, A4
from reportlab.lib.styles import getSampleStyleSheet

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
    # ---------------- IPS RULE GENERATION ----------------
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
        for i in r.get("data", [])[:40]:
            insert_threat(i.get("ioc","unknown"), i.get("ioc_type","unknown"), 85)
    except: pass

def fetch_feodo():
    try:
        url="https://feodotracker.abuse.ch/downloads/ipblocklist.json"
        data = requests.get(url, timeout=10).json()
        for i in data[:40]:
            insert_threat(i.get("ip_address","0.0.0.0"), "ip", 90)
    except: pass

def fetch_urlhaus():
    try:
        url="https://urlhaus.abuse.ch/downloads/csv_recent/"
        data = requests.get(url, timeout=10).text.splitlines()
        reader = csv.reader(data)
        for row in list(reader)[10:50]:
            if len(row)>2:
                insert_threat(row[2],"url",70)
    except: pass

def fetch_hashes():
    try:
        url="https://mb-api.abuse.ch/api/v1/"
        r = requests.post(url, data={"query":"get_recent"}, timeout=10).json()
        for item in r.get("data", [])[:40]:
            insert_threat(item.get("sha256_hash",""), "hash", 75)
    except: pass

def fetch_feeds():
    fetch_threatfox()
    fetch_feodo()
    fetch_hashes()
    fetch_urlhaus()

# ---------------- SCHEDULER ----------------
def scheduler():
    fetch_feeds()
    threading.Timer(900, scheduler).start()  # every 15 min

fetch_feeds()
scheduler()

# ---------------- SECURENATION INDEX ----------------
def securenation():
    rows = db().execute("SELECT severity FROM threats ORDER BY id DESC LIMIT 100").fetchall()
    if not rows: return 0
    return round(sum([r["severity"] for r in rows])/len(rows),1)

# ---------------- CHARTS ----------------
def malaysia_map():
    rows = db().execute("SELECT lat,lon,severity FROM threats").fetchall()
    lat, lon, sev = [r["lat"] for r in rows], [r["lon"] for r in rows], [r["severity"] for r in rows]
    colors = []
    for s in sev:
        if s>=85: colors.append("red")
        elif s>=70: colors.append("orange")
        else: colors.append("yellow")
    fig = go.Figure()
    fig.add_trace(go.Scattermapbox(
        lat=lat, lon=lon, mode="markers",
        marker=dict(size=14,color=colors,opacity=0.8),
        text=[f"Severity: {s}" for s in sev],
        hoverinfo="text"
    ))
    fig.update_layout(
        mapbox_style="carto-darkmatter",
        mapbox_center={"lat":4.5,"lon":102},
        mapbox_zoom=4,
        paper_bgcolor="#0b1b2a",
        margin=dict(l=0,r=0,t=0,b=0)
    )
    return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)

def timeline_chart():
    rows=db().execute("SELECT substr(created,1,10) d, COUNT(*) c FROM threats GROUP BY d ORDER BY d").fetchall()
    x=[r["d"] for r in rows]; y=[r["c"] for r in rows]
    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=x, y=y, mode="lines+markers",
        line=dict(color="#00eaff", width=4, shape='spline', smoothing=1.3),
        marker=dict(size=10, color="#00eaff")
    ))
    fig.update_layout(plot_bgcolor="#1a1a1a", paper_bgcolor="#0b1b2a",
                      font_color="#A3B8CC",
                      xaxis=dict(showgrid=False, showline=True, linecolor="#444"),
                      yaxis=dict(showgrid=False, zeroline=False),
                      margin=dict(l=40,r=40,t=60,b=40))
    return json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

def sector_chart():
    rows=db().execute("SELECT sector, COUNT(*) c FROM threats GROUP BY sector ORDER BY c DESC").fetchall()
    labels=[r["sector"] for r in rows]; values=[r["c"] for r in rows]
    fig=go.Figure(go.Bar(x=labels, y=values,
                         marker=dict(color="#3a4a5c", line=dict(color="#6f8fbf",width=2))))
    fig.update_layout(plot_bgcolor="#1a1a1a", paper_bgcolor="#0b1b2a",
                      font_color="#A3B8CC", title="Sector Targeting")
    return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)

def indicator_type_chart():
    rows=db().execute("SELECT type, COUNT(*) c FROM threats GROUP BY type").fetchall()
    labels=[r["type"] for r in rows]; values=[r["c"] for r in rows]
    fig = go.Figure(data=[go.Pie(labels=labels, values=values, hole=0.3,
                                 pull=[0.05]*len(labels))])
    fig.update_layout(plot_bgcolor="#1a1a1a", paper_bgcolor="#0b1b2a",
                      font_color="#A3B8CC", title="Indicator Type Distribution")
    return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)

def mitre_chart():
    rows=db().execute("SELECT mitre, COUNT(*) c FROM threats GROUP BY mitre").fetchall()
    labels=[r["mitre"] for r in rows]; values=[r["c"] for r in rows]
    fig=go.Figure()
    fig.add_trace(go.Scatter(x=labels, y=values, mode='lines',
                             line=dict(color="#ff9900", width=3)))
    fig.update_layout(plot_bgcolor="#1a1a1a", paper_bgcolor="#0b1b2a",
                      font_color="#A3B8CC", title="MITRE Techniques Trend",
                      xaxis=dict(showgrid=False), yaxis=dict(showgrid=False))
    return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)

# ---------------- DASHBOARD HTML, EXPORTS, ROUTES ----------------
# (Keep same as v3.8.1, including PDF, CSV, JSON export)
# Include /download_ips for RULE_FILE download

if __name__=="__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT",5000)))