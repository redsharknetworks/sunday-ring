import os, sqlite3, requests, json, csv, io, random, threading
from datetime import datetime
from flask import Flask, render_template_string, send_file
import plotly.graph_objs as go
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
from reportlab.lib.pagesizes import landscape, A4
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle

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
def fetch_feeds():
    try:
        # ThreatFox
        r = requests.get("https://threatfox.abuse.ch/export/json/recent/", timeout=10).json()
        for i in r.get("data", [])[:40]:
            insert_threat(i.get("ioc","unknown"), i.get("ioc_type","unknown"), 85)
    except: pass

    try:
        # FeodoTracker
        r = requests.get("https://feodotracker.abuse.ch/downloads/ipblocklist.json", timeout=10).json()
        for i in r[:40]:
            insert_threat(i.get("ip_address","0.0.0.0"), "ip", 90)
    except: pass

    try:
        # URLHaus
        r = requests.get("https://urlhaus.abuse.ch/downloads/csv_recent/", timeout=10).text.splitlines()
        reader = csv.reader(r)
        for row in list(reader)[10:50]:
            if len(row)>2:
                insert_threat(row[2],"url",70)
    except: pass

    try:
        # MalwareBazaar hashes
        r = requests.post("https://mb-api.abuse.ch/api/v1/", data={"query":"get_recent"}, timeout=10).json()
        for item in r.get("data", [])[:40]:
            insert_threat(item.get("sha256_hash",""), "hash", 75)
    except: pass

def scheduler():
    fetch_feeds()
    threading.Timer(900, scheduler).start()  # every 15 minutes

fetch_feeds()
scheduler()

# ---------------- SECURENATION INDEX ----------------
def securenation():
    rows = db().execute("SELECT severity FROM threats ORDER BY id DESC LIMIT 100").fetchall()
    if not rows: return 0
    return round(sum(r["severity"] for r in rows)/len(rows),1)

# ---------------- CHART STYLES ----------------
def nikkei_layout(title=None):
    return dict(
        plot_bgcolor="#0b0b0b",
        paper_bgcolor="#0b0b0b",
        font=dict(color="#FFFFFF", family="Arial, sans-serif"),
        title=dict(text=title, font=dict(size=18, color="#00FFCC") if title else None),
        xaxis=dict(showgrid=False, zeroline=False, color="#AAAAAA"),
        yaxis=dict(showgrid=False, zeroline=False, color="#AAAAAA"),
        margin=dict(l=40,r=40,t=60,b=40)
    )

def timeline_chart():
    rows=db().execute("SELECT substr(created,1,10) d, COUNT(*) c FROM threats GROUP BY d ORDER BY d").fetchall()
    x=[r["d"] for r in rows]; y=[r["c"] for r in rows]
    fig=go.Figure()
    fig.add_trace(go.Scatter(x=x, y=y, mode="lines+markers",
                             line=dict(color="#00FFCC", width=4, shape='spline', smoothing=1.3),
                             marker=dict(size=10, color="#00FFCC", line=dict(width=2,color="#FFFFFF"))))
    fig.update_layout(nikkei_layout("Threat Timeline"))
    return json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

def mitre_chart():
    rows=db().execute("SELECT mitre, COUNT(*) c FROM threats GROUP BY mitre").fetchall()
    x=[r["mitre"] for r in rows]; y=[r["c"] for r in rows]
    fig=go.Figure(go.Scatter(x=x, y=y, mode='lines+markers',
                             line=dict(color="#FF9900", width=3),
                             marker=dict(size=8,color="#FF9900")))
    fig.update_layout(nikkei_layout("MITRE Techniques Trend"))
    return json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

def sector_chart():
    rows=db().execute("SELECT sector, COUNT(*) c FROM threats GROUP BY sector ORDER BY c DESC").fetchall()
    x=[r["sector"] for r in rows]; y=[r["c"] for r in rows]
    fig=go.Figure(go.Bar(x=x, y=y, marker=dict(color="#1DB954", line=dict(color="#FFFFFF",width=1))))
    fig.update_layout(nikkei_layout("Sector Targeting"))
    return json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

def indicator_type_chart():
    rows=db().execute("SELECT type, COUNT(*) c FROM threats GROUP BY type").fetchall()
    labels=[r["type"] for r in rows]; values=[r["c"] for r in rows]
    colors=["#00FF00","#FF9900","#1DB954","#00E5FF","#FF3366"][:len(labels)]
    fig=go.Figure(go.Pie(labels=labels, values=values, hole=0.3,
                         pull=[0.05]*len(labels), marker=dict(colors=colors)))
    fig.update_layout(nikkei_layout("Indicator Type Distribution"))
    return json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

def malaysia_map():
    rows=db().execute("SELECT lat,lon,severity FROM threats").fetchall()
    lat, lon, sev = [r["lat"] for r in rows],[r["lon"] for r in rows],[r["severity"] for r in rows]
    colors,sizes=[],[]
    for s in sev:
        if s>=85: colors.append("#FF0000"); sizes.append(18)
        elif s>=70: colors.append("#FFA500"); sizes.append(12)
        else: colors.append("#00FF00"); sizes.append(8)
    fig=go.Figure(go.Scattermapbox(lat=lat, lon=lon, mode="markers",
                                   marker=dict(size=sizes, color=colors, opacity=0.9),
                                   text=[f"Severity: {s}" for s in sev],
                                   hoverinfo="text"))
    fig.update_layout(mapbox_style="carto-darkmatter", mapbox_center={"lat":4.5,"lon":102},
                      mapbox_zoom=4, paper_bgcolor="#0b0b0b", margin=dict(l=0,r=0,t=0,b=0),
                      mapbox=dict(accesstoken=None))
    return json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

# ---------------- BULLETIN & TOP10 ----------------
def bulletin_summary():
    conn = db()
    top_sector = conn.execute("SELECT sector,COUNT(*) c FROM threats GROUP BY sector ORDER BY c DESC LIMIT 1").fetchone()
    top_sector = top_sector["sector"] if top_sector else "N/A"
    top_threat = conn.execute("SELECT indicator,severity FROM threats ORDER BY severity DESC LIMIT 1").fetchone()
    top_threat = f"{top_threat['indicator']} ({top_threat['severity']})" if top_threat else "N/A"
    top_mitre = conn.execute("SELECT mitre,COUNT(*) c FROM threats GROUP BY mitre ORDER BY c DESC LIMIT 1").fetchone()
    top_mitre = top_mitre["mitre"] if top_mitre else "N/A"
    return {"top_sector": top_sector,"top_threat": top_threat,"top_mitre": top_mitre}

def top_indicators(limit=10):
    rows=db().execute("SELECT indicator, COUNT(*) c FROM threats GROUP BY indicator ORDER BY c DESC LIMIT ?", (limit,)).fetchall()
    return [{"indicator": r["indicator"],"count": r["c"]} for r in rows]

# ---------------- DASHBOARD HTML ----------------
HTML = """<html>
<head>
<title>RedShark Threat Intelligence Dashboard</title>
<script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
<link rel="stylesheet" href="https://cdn.datatables.net/1.13.4/css/jquery.dataTables.min.css">
<script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
<script src="https://cdn.datatables.net/1.13.4/js/jquery.dataTables.min.js"></script>
<style>
body{background:#0b0b0b;color:#FFFFFF;font-family:Arial;}
.card{background:#13263b;padding:20px;margin:15px;border-radius:8px;}
table{width:100%;border-collapse:collapse;}
td,th{padding:8px;border-bottom:1px solid #1f3d5c;text-align:center;}
a.download-link{color:#00FFCC;font-weight:bold;text-decoration:none;}
.center{text-align:center;}
.blink {animation: blink-animation 1s infinite;color:#FF0000;font-weight:bold;}
@keyframes blink-animation {0% {opacity:1;}50% {opacity:0;}100% {opacity:1;}}
.card table {width:100%;border-collapse:collapse;margin-top:10px;}
.card th, .card td {border:1px solid #1f3d5c;padding:6px;text-align:center;}
</style>
</head>
<body>
<h2>RedShark Threat Intelligence Dashboard</h2>

<div class="card">
SecureNation Index: <b>{{index}}</b>
</div>

<div class="card">
<h3>Bulletin Summary</h3>
<ul>
<li><b>Most Targeted Sector:</b> {{bulletin.top_sector}}</li>
<li><b>Highest Severity Threat:</b> {{bulletin.top_threat}}</li>
<li><b>Most Observed MITRE Technique:</b> {{bulletin.top_mitre}}</li>
</ul>
</div>

<div class="card">
<h3>Top 10 Threat Indicators</h3>
<table>
<thead><tr><th>Indicator</th><th>Occurrences</th></tr></thead>
<tbody>
{% for t in top10 %}
<tr><td>{{t.indicator}}</td><td>{{t.count}}</td></tr>
{% endfor %}
</tbody>
</table>
</div>

<div class="card">
<h3>Malaysia Cyber Attack Map</h3>
<div id="map" style="height:400px;"></div>
</div>

<div class="card">
<h3>Threat Timeline</h3>
<div id="timeline" style="height:300px;"></div>
</div>

<div class="card">
<h3>MITRE ATT&CK Techniques</h3>
<div id="mitre" style="height:300px;"></div>
</div>

<div class="card">
<h3>Sector Targeting</h3>
<div id="sector" style="height:300px;"></div>
</div>

<div class="card">
<h3>Indicator Type Distribution</h3>
<div id="indicator_type" style="height:300px;"></div>
</div>

<div class="card">
<h3>Latest Threat Indicators</h3>
<table id="threat_table">
<thead><tr><th>ID</th><th>Indicator</th><th>Type</th><th>Sector</th><th>Severity</th></tr></thead>
<tbody>
{% for r in rows %}
<tr class="{{'blink' if r.severity>=85 else ''}}">
<td>{{r.id}}</td><td>{{r.indicator}}</td><td>{{r.type}}</td><td>{{r.sector}}</td><td>{{r.severity}}</td>
</tr>
{% endfor %}
</tbody>
</table>
</div>

<div class="card center">
<a class="download-link" href="/csv">Download CSV</a> |
<a class="download-link" href="/json">Download JSON</a> |
<a class="download-link" href="/pdf">Download PDF</a> |
<a class="download-link" href="/download_ips">Download IPS Signatures</a>
</div>

<p class="center" style="opacity:0.6;">
Developed and analyzed by darkgrid@redshark.my using publicly available threat intelligence sources
</p>

<script>
var timeline={{timeline|safe}};
var mitre={{mitre|safe}};
var sector={{sector|safe}};
var indicator_type={{indicator_type|safe}};
var map={{map|safe}};
Plotly.newPlot("timeline",timeline.data,timeline.layout);
Plotly.newPlot("mitre",mitre.data,mitre.layout);
Plotly.newPlot("sector",sector.data,sector.layout);
Plotly.newPlot("indicator_type",indicator_type.data,indicator_type.layout);
Plotly.newPlot("map",map.data,map.layout);

var mapData = map.data[0]; var sizes = mapData.marker.size; var growing = true;
setInterval(function(){
    for(var i=0;i<sizes.length;i++){
        if(mapData.marker.color[i]=="#FF0000"){ sizes[i] = growing?25:18; }
    }
    mapData.marker.size = sizes; Plotly.redraw("map"); growing = !growing;
}, 800);

$(document).ready(function(){ $('#threat_table').DataTable(); });
</script>
</body>
</html>
"""

# ---------------- ROUTES ----------------
@app.route("/")
def dashboard():
    rows=db().execute("SELECT * FROM threats ORDER BY id DESC LIMIT 50").fetchall()
    return render_template_string(HTML,
                                  rows=rows,
                                  index=securenation(),
                                  timeline=timeline_chart(),
                                  mitre=mitre_chart(),
                                  sector=sector_chart(),
                                  indicator_type=indicator_type_chart(),
                                  map=malaysia_map(),
                                  bulletin=bulletin_summary(),
                                  top10=top_indicators())

@app.route("/csv")
def csv_export():
    rows=db().execute("SELECT * FROM threats").fetchall()
    out=io.StringIO(); writer=csv.writer(out)
    writer.writerow(rows[0].keys())
    for r in rows: writer.writerow(list(r))
    mem=io.BytesIO(); mem.write(out.getvalue().encode()); mem.seek(0)
    return send_file(mem,download_name="threats.csv",as_attachment=True)

@app.route("/json")
def json_export():
    rows=db().execute("SELECT * FROM threats").fetchall()
    mem=io.BytesIO(); mem.write(json.dumps([dict(r) for r in rows], indent=2).encode()); mem.seek(0)
    return send_file(mem,download_name="threats.json",as_attachment=True)

@app.route("/pdf")
def pdf_export():
    rows=db().execute("SELECT indicator,type,sector,severity,created FROM threats LIMIT 50").fetchall()
    buffer=io.BytesIO()
    data=[["Indicator","Type","Sector","Severity","Timestamp"]]
    style=Paragraph