import os
import sqlite3
import requests
import json
import csv
import io
import random
import threading
import time
from datetime import datetime
from flask import Flask, render_template_string, send_file

import plotly.graph_objs as go
import plotly

from reportlab.platypus import SimpleDocTemplate, Table
from reportlab.lib.pagesizes import landscape, A4

app = Flask(__name__)

# ---------------- PATHS ----------------
DB = "redshark_cti.db"
RULE_FILE = "redshark_ips.rules"

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
        actor TEXT,
        campaign TEXT,
        mitre TEXT,
        sector TEXT,
        severity INTEGER,
        confidence INTEGER,
        lat REAL,
        lon REAL,
        created TEXT
    )
    """)
    conn.commit()

init_db()

# ---------------- INSERT DUMMY DATA ----------------
def insert_threat(indicator,typ,severity):
    conn = db()
    if conn.execute("SELECT 1 FROM threats WHERE indicator=?",(indicator,)).fetchone():
        return
    lat,lon=random.choice([[1.49,103.74],[6.11,100.36],[6.12,102.23],[2.18,102.25],[2.72,101.94],[3.81,103.32],
                           [4.59,101.09],[5.41,100.33],[5.98,116.07],[1.55,110.35],[3.07,101.51],[5.33,103.14],[3.13,101.68]])
    actor=random.choice(["Lazarus","APT29","FIN7","TA505","APT41","Unknown"])
    campaign=random.choice(["Operation Phantom","DarkBanking","Silent Hydra","Shadow Strike","Ghost C2"])
    mitre=random.choice(["Reconnaissance","Initial Access","Execution","Persistence","Privilege Escalation","Defense Evasion",
                         "Credential Access","Discovery","Lateral Movement","Command & Control","Exfiltration","Impact"])
    sector=random.choice(["Government","Banking","Telecom","Energy","Healthcare","Education"])
    confidence=random.randint(60,95)
    created=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    conn.execute("""
    INSERT INTO threats(indicator,type,actor,campaign,mitre,sector,severity,confidence,lat,lon,created)
    VALUES(?,?,?,?,?,?,?,?,?,?,?)
    """,(indicator,typ,actor,campaign,mitre,sector,severity,confidence,lat,lon,created))
    conn.commit()
    generate_rule(indicator,typ)

def seed_dummy_data():
    conn = db()
    if conn.execute("SELECT 1 FROM threats LIMIT 1").fetchone():
        return
    sample_indicators = [
        ("192.168.1.100", "ip", 90),
        ("malicious.com/path", "url", 75),
        ("abcd1234ef5678", "hash", 80)
    ]
    for ind, typ, sev in sample_indicators:
        insert_threat(ind, typ, sev)

seed_dummy_data()

# ---------------- IPS RULE ----------------
def generate_rule(indicator,typ):
    sid=1000000+random.randint(1,9999)
    if typ=="ip":
        rule=f'alert ip any any -> any any (msg:"RedShark IP {indicator}"; sid:{sid}; rev:1;)'
    elif typ=="url":
        rule=f'alert http any any -> any any (msg:"RedShark URL {indicator}"; content:"{indicator}"; http_uri; sid:{sid}; rev:1;)'
    else:
        rule=f'# HASH {indicator}'
    with open(RULE_FILE,"a") as f:
        f.write(rule+"\n")

# ---------------- FEEDS ----------------
def fetch_threatfox():
    try:
        url="https://threatfox.abuse.ch/export/json/recent/"
        r=requests.get(url,timeout=10).json()
        for i in r.get("data",[])[:20]:
            insert_threat(i.get("ioc"),i.get("ioc_type"),85)
    except: pass

def fetch_feodo():
    try:
        url="https://feodotracker.abuse.ch/downloads/ipblocklist.json"
        r=requests.get(url).json()
        for i in r[:20]:
            insert_threat(i.get("ip_address"),"ip",90)
    except: pass

def fetch_urlhaus():
    try:
        url="https://urlhaus.abuse.ch/downloads/csv_recent/"
        data=requests.get(url).text.splitlines()
        reader=csv.reader(data)
        for r in list(reader)[10:30]:
            if len(r)>2:
                insert_threat(r[2],"url",70)
    except: pass

def background_feed_loop():
    while True:
        fetch_threatfox()
        fetch_feodo()
        fetch_urlhaus()
        time.sleep(30)

threading.Thread(target=background_feed_loop,daemon=True).start()

# ---------------- SECURENATION INDEX ----------------
def securenation():
    rows=db().execute("SELECT severity FROM threats ORDER BY id DESC LIMIT 100").fetchall()
    if not rows: return 0
    return round(sum([r["severity"] for r in rows])/len(rows),1)

def progress_color(index):
    if index>=85: return "crimson"
    if index>=70: return "orange"
    return "green"

# ---------------- CHARTS ----------------
def timeline_chart():
    try:
        rows=db().execute("SELECT substr(created,1,10) d,COUNT(*) c FROM threats GROUP BY d").fetchall()
        x=[str(r["d"]) for r in rows] or ["No Data"]
        y=[int(r["c"]) for r in rows] or [0]
        fig=go.Figure()
        fig.add_trace(go.Scatter(x=x,y=y,mode="lines+markers",line=dict(width=3,color="#FFA500")))
        fig.update_layout(plot_bgcolor="#0b1b2a",paper_bgcolor="#0b1b2a",font_color="#A3B8CC",
                          xaxis=dict(showgrid=False),yaxis=dict(showgrid=False))
        return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)
    except:
        return json.dumps({"data":[],"layout":{}})

def actor_chart():
    try:
        rows=db().execute("SELECT actor,COUNT(*) c FROM threats GROUP BY actor").fetchall()
        x=[r["actor"] for r in rows] or ["No Data"]
        y=[r["c"] for r in rows] or [0]
        fig=go.Figure(go.Bar(x=x,y=y,marker_color="#00eaff"))
        fig.update_layout(plot_bgcolor="#0b1b2a",paper_bgcolor="#0b1b2a",font_color="#A3B8CC")
        return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)
    except:
        return json.dumps({"data":[],"layout":{}})

def indicator_chart():
    try:
        rows=db().execute("SELECT type,COUNT(*) c FROM threats GROUP BY type").fetchall()
        labels=[r["type"] for r in rows] or ["No Data"]
        values=[r["c"] for r in rows] or [0]
        fig=go.Figure(go.Pie(labels=labels,values=values,hole=0.4))
        fig.update_layout(plot_bgcolor="#0b1b2a",paper_bgcolor="#0b1b2a",font_color="#A3B8CC")
        return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)
    except:
        return json.dumps({"data":[],"layout":{}})

def mitre_chart():
    try:
        rows=db().execute("SELECT mitre,COUNT(*) c FROM threats GROUP BY mitre").fetchall()
        labels=[r["mitre"] for r in rows] or ["No Data"]
        values=[r["c"] for r in rows] or [0]
        fig=go.Figure(go.Bar(x=labels,y=values,marker_color="#FFA500"))
        fig.update_layout(plot_bgcolor="#0b1b2a",paper_bgcolor="#0b1b2a",font_color="#A3B8CC",xaxis_tickangle=-45)
        return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)
    except:
        return json.dumps({"data":[],"layout":{}})

def sector_chart():
    try:
        rows=db().execute("SELECT sector,COUNT(*) c FROM threats GROUP BY sector").fetchall()
        labels=[r["sector"] for r in rows] or ["No Data"]
        values=[r["c"] for r in rows] or [0]
        fig=go.Figure(go.Bar(x=labels,y=values,marker_color="#00eaff"))
        fig.update_layout(plot_bgcolor="#0b1b2a",paper_bgcolor="#0b1b2a",font_color="#A3B8CC")
        return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)
    except:
        return json.dumps({"data":[],"layout":{}})

def malaysia_map():
    try:
        rows=db().execute("SELECT lat,lon,severity FROM threats").fetchall()
        lat,lon,color,size=[],[],[],[]
        for r in rows:
            lat.append(r["lat"])
            lon.append(r["lon"])
            if r["severity"]>=85:
                color.append("crimson")
                size.append(14)
            elif r["severity"]>=70:
                color.append("orange")
                size.append(10)
            else:
                color.append("yellow")
                size.append(6)
        if not lat: lat,lon,size,color=[0],[0],[0],["grey"]
        fig=go.Figure(go.Scatter3d(x=lon,y=lat,z=[s for s in size],mode="markers",
                                     marker=dict(size=size,color=color,opacity=0.9)))
        fig.update_layout(scene=dict(xaxis=dict(showbackground=False),
                                     yaxis=dict(showbackground=False),
                                     zaxis=dict(showbackground=False)),
                          paper_bgcolor="#0b1b2a",font_color="#A3B8CC")
        return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)
    except:
        return json.dumps({"data":[],"layout":{}})

# ---------------- DASHBOARD HTML ----------------
HTML = """..."""  # Use full HTML from v7.2.4 with slow blinking markers, progress bar dynamic color, Nikkei-style charts

# ---------------- DASHBOARD ----------------
@app.route("/")
def dashboard():
    rows = db().execute("SELECT * FROM threats ORDER BY id DESC LIMIT 50").fetchall() or []
    index=securenation()
    return render_template_string(HTML,
                                  rows=rows,
                                  index=index,
                                  progress_color=progress_color(index),
                                  timeline=timeline_chart(),
                                  actor=actor_chart(),
                                  indicator=indicator_chart(),
                                  mitre=mitre_chart(),
                                  sector=sector_chart(),
                                  map=malaysia_map())

# ---------------- EXPORT ----------------
@app.route("/csv")
def csv_export():
    rows=db().execute("SELECT * FROM threats").fetchall()
    if not rows: return "No data available",404
    out=io.StringIO()
    writer=csv.writer(out)
    writer.writerow(rows[0].keys())
    for r in rows:
        writer.writerow(list(r))
    mem=io.BytesIO()
    mem.write(out.getvalue().encode())
    mem.seek(0)
    return send_file(mem,download_name="threats.csv",as_attachment=True)

@app.route("/json")
def json_export():
    rows=db().execute("SELECT * FROM threats").fetchall()
    if not rows: return "No data available",404
    data=[dict(r) for r in rows]
    mem=io.BytesIO()
    mem.write(json.dumps(data,indent=2).encode())
    mem.seek(0)
    return send_file(mem,download_name="threats.json",as_attachment=True)

@app.route("/pdf")
def pdf_export():
    rows=db().execute("SELECT indicator,type,actor,campaign,severity,confidence FROM threats LIMIT 50").fetchall()
    if not rows: return "No data available",404
    buffer=io.BytesIO()
    data=[["Indicator","Type","Actor","Campaign","Severity","Confidence"]]
    for r in rows:
        data.append([r["indicator"],r["type"],r["actor"],r["campaign"],r["severity"],r["confidence"]])
    pdf=SimpleDocTemplate(buffer,pagesize=landscape(A4))
    table=Table(data)
    pdf.build([table])
    buffer.seek(0)
    return send_file(buffer,download_name="report.pdf",as_attachment=True)

@app.route("/ips")
def ips_export():
    if not os.path.exists(RULE_FILE):
        return "No IPS rules available",404
    return send_file(RULE_FILE,download_name="redshark_ips.rules",as_attachment=True)

# ---------------- RUN ----------------
if __name__=="__main__":
    app.run(host="0.0.0.0",port=int(os.environ.get("PORT",5000)))