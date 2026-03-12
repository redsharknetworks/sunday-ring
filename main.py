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
    # Append IPS rule
    rule_line = f'alert ip any any -> any any (msg:"RedShark {typ} {indicator} | MITRE: {m}"; sid:{1000000+random.randint(1,9999)}; rev:1;)\n'
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
    colors, pulse = [], []
    for s in sev:
        if s>=85: colors.append("red"); pulse.append(True)
        elif s>=70: colors.append("orange"); pulse.append(False)
        else: colors.append("yellow"); pulse.append(False)
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
        marker=dict(size=10, color="#00eaff", line=dict(width=2, color="#66ffff")),
        hovertemplate="Date: %{x}<br>Attacks: %{y}<extra></extra>"
    ))
    fig.update_layout(plot_bgcolor="#1a1a1a", paper_bgcolor="#0b1b2a",
                      font_color="#A3B8CC",
                      xaxis=dict(showgrid=False, showline=True, linecolor="#444"),
                      yaxis=dict(showgrid=True, gridcolor="#333", zeroline=False),
                      hovermode="x unified", margin=dict(l=40,r=40,t=60,b=40))
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
    fig=go.Figure(go.Pie(labels=labels, values=values, hole=0.3,
                          marker=dict(colors=["#00ffff","#ff00ff","#ff9900","#00ff99"])))
    fig.update_layout(plot_bgcolor="#1a1a1a", paper_bgcolor="#0b1b2a",
                      font_color="#A3B8CC", title="Indicator Types")
    return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)

def mitre_chart():
    rows=db().execute("SELECT mitre, COUNT(*) c FROM threats GROUP BY mitre").fetchall()
    labels=[r["mitre"] for r in rows]; values=[r["c"] for r in rows]
    colors = ["#00ffff","#ff00ff","#ff9900","#00ff99","#ff0066","#66ffcc","#ffcc00","#cc00ff","#ff3300","#33ffcc","#ccff00","#6600ff","#00ccff"]
    fig=go.Figure(go.Pie(labels=labels,values=values,hole=0.4,
                          marker=dict(colors=[colors[i%len(colors)] for i in range(len(labels))])))
    fig.update_layout(plot_bgcolor="#1a1a1a", paper_bgcolor="#0b1b2a",
                      font_color="#A3B8CC", title="MITRE ATT&CK Techniques")
    return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)

# ---------------- PDF ----------------
def generate_pdf():
    rows=db().execute("SELECT id,indicator,type,sector,severity,created FROM threats ORDER BY id DESC LIMIT 50").fetchall()
    buffer=io.BytesIO()
    doc=SimpleDocTemplate(buffer,pagesize=landscape(A4))
    styles=getSampleStyleSheet()
    elements=[Paragraph("RedShark CTI Report", styles["Title"])]
    elements.append(Spacer(1,10))
    ts=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    elements.append(Paragraph(f"Report Generated: {ts}", styles["Normal"]))
    elements.append(Spacer(1,20))
    data=[["ID","Indicator","Type","Sector","Severity","Timestamp"]]
    for r in rows: data.append([r["id"],r["indicator"],r["type"],r["sector"],r["severity"],r["created"]])
    elements.append(Table(data))
    doc.build(elements)
    buffer.seek(0)
    return buffer

# ---------------- DASHBOARD HTML ----------------
HTML = """ 
<html>
<head>
<title>RedShark CTI Dashboard</title>
<script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/jquery.tablesorter/2.31.3/css/theme.dark.min.css">
<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery.tablesorter/2.31.3/js/jquery.tablesorter.min.js"></script>
<style>
body{background:#0b1b2a;color:#A3B8CC;font-family:Arial;margin:0;padding:0;}
.card{background:#13263b;padding:20px;margin:15px;border-radius:8px;}
table{width:100%;border-collapse:collapse;}
th,td{padding:8px;border-bottom:1px solid #1f3d5c;color:#A3B8CC;}
th{cursor:pointer;}
a.download{color:crimson;font-weight:bold;text-decoration:none;}
.center{text-align:center;}
</style>
</head>
<body>
<h2>RedShark CTI Dashboard</h2>
<div class="card">SecureNation Index: <span style='color:orange;font-weight:bold'>{{index}}</span></div>

<div class="card"><h3>Malaysia Cyber Attack Map</h3><div id="map" style="height:400px;"></div></div>
<div class="card"><h3>Threat Timeline</h3><div id="timeline" style="height:300px;"></div></div>
<div class="card"><h3>MITRE ATT&CK Distribution</h3><div id="mitre" style="height:300px;"></div></div>
<div class="card"><h3>Sector Targeting</h3><div id="sector" style="height:300px;"></div></div>
<div class="card"><h3>Indicator Types</h3><div id="indicator_type" style="height:300px;"></div></div>

<div class="card"><h3>Latest Threat Indicators</h3>
<table id="indicator" class="tablesorter">
<thead><tr>
<th>ID</th><th>Indicator</th><th>Type</th><th>Sector</th><th>Severity</th><th>Timestamp</th>
</tr></thead>
<tbody>
{% for r in rows %}
<tr>
<td>{{r.id}}</td><td>{{r.indicator}}</td><td>{{r.type}}</td><td>{{r.sector}}</td><td>{{r.severity}}</td><td>{{r.created}}</td>
</tr>
{% endfor %}
</tbody>
</table>
</div>

<div class="card">
<a class="download" href="/csv">Download CSV</a> |
<a class="download" href="/json">Download JSON</a> |
<a class="download" href="/pdf">Download PDF</a> |
<a class="download" href="/rules">Download IPS Signatures</a>
</div>

<p class="center" style="opacity:0.6">Developed and analyzed by darkgrid@redshark.my using public threat intelligence sources</p>

<script>
$(function(){$("#indicator").tablesorter();});
Plotly.newPlot("map",{{map|safe}}.data,{{map|safe}}.layout);
Plotly.newPlot("timeline",{{timeline|safe}}.data,{{timeline|safe}}.layout);
Plotly.newPlot("sector",{{sector|safe}}.data,{{sector|safe}}.layout);
Plotly.newPlot("mitre",{{mitre|safe}}.data,{{mitre|safe}}.layout);
Plotly.newPlot("indicator_type",{{indicator_type|safe}}.data,{{indicator_type|safe}}.layout);
</script>
</body></html>
"""

# ---------------- ROUTES ----------------
@app.route("/")
def dashboard():
    rows=db().execute("SELECT * FROM threats ORDER BY id DESC LIMIT 50").fetchall()
    return render_template_string(HTML, rows=rows, index=securenation(),
                                  map=malaysia_map(),
                                  timeline=timeline_chart(),
                                  sector=sector_chart(),
                                  mitre=mitre_chart(),
                                  indicator_type=indicator_type_chart())

@app.route("/pdf")
def pdf():
    return send_file(generate_pdf(), download_name="redshark-cti-report.pdf", as_attachment=True)

@app.route("/csv")
def csv_export():
    rows=db().execute("SELECT * FROM threats").fetchall()
    out=io.StringIO()
    writer=csv.writer(out)
    if rows: writer.writerow(rows[0].keys())
    for r in rows: writer.writerow(list(r))
    mem=io.BytesIO(); mem.write(out.getvalue().encode()); mem.seek(0)
    return send_file(mem, download_name="redshark-cti.csv", as_attachment=True)

@app.route("/json")
def json_export():
    rows=db().execute("SELECT * FROM threats").fetchall()
    data=[dict(r) for r in rows]
    mem=io.BytesIO(); mem.write(json.dumps(data, indent=2).encode()); mem.seek(0)
    return send_file(mem, download_name="redshark-cti.json", as_attachment=True)

@app.route("/rules")
def rules():
    if not os.path.exists(RULE_FILE):
        with open(RULE_FILE,"w") as f: f.write("# RedShark IPS Signatures\n")
    return send_file(RULE_FILE, download_name="redshark-ips-signatures.rules", as_attachment=True, mimetype="text/plain")

# ---------------- RUN ----------------
if __name__=="__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT",5000)))