import os
import sqlite3
import requests
import json
import csv
import io
import random
from datetime import datetime
from flask import Flask, render_template_string, send_file
import plotly.graph_objs as go
import plotly
from reportlab.platypus import SimpleDocTemplate, Table
from reportlab.lib.pagesizes import landscape, A4

app = Flask(__name__)
DB = "threats.db"  # relative path

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
        indicator TEXT,
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

with app.app_context():
    init_db()

# ---------------- MALAYSIA STATES ----------------
states = {
    "Johor":[1.4927,103.7414],"Kedah":[6.1184,100.3685],"Kelantan":[6.1254,102.2381],
    "Melaka":[2.1896,102.2501],"Negeri Sembilan":[2.7258,101.9424],"Pahang":[3.8126,103.3256],
    "Perak":[4.5921,101.0901],"Perlis":[6.4449,100.2048],"Pulau Pinang":[5.4164,100.3327],
    "Sabah":[5.9804,116.0735],"Sarawak":[1.5533,110.3592],"Selangor":[3.0738,101.5183],
    "Terengganu":[5.3302,103.1408],"Kuala Lumpur":[3.1390,101.6869],
    "Putrajaya":[2.9264,101.6964],"Labuan":[5.2831,115.2308]
}

# ---------------- SECTORS ----------------
sectors = [
    "Government","Banking & Finance","Telecommunications","Energy","Healthcare",
    "Education","Manufacturing","Transportation","Retail","Media","Hospitality",
    "Agriculture","Technology","Logistics","Utilities"
]

# ---------------- ATTACK SOURCES ----------------
attack_sources = [
    [35.6895,139.6917],[55.7558,37.6173],[37.7749,-122.4194],
    [39.9042,116.4074],[28.6139,77.2090],[51.5074,-0.1278],
    [48.8566,2.3522],[52.52,13.4050]
]

# ---------------- MITRE ATT&CK TECHNIQUES ----------------
mitre_techniques = [
"T1003 Credential Dumping","T1059 Command and Scripting Interpreter",
"T1047 Windows Management Instrumentation","T1027 Obfuscated Files or Information",
"T1566 Phishing","T1105 Ingress Tool Transfer","T1071 Application Layer Protocol",
"T1090 Proxy","T1078 Valid Accounts","T1055 Process Injection","T1496 Resource Hijacking",
"T1486 Data Encrypted for Impact","T1041 Exfiltration Over C2 Channel","T1204 User Execution",
"T1036 Masquerading","T1082 System Information Discovery","T1083 File and Directory Discovery",
"T1018 Remote System Discovery","T1053 Scheduled Task","T1547 Boot or Logon Autostart",
"T1190 Exploit Public Facing Application","T1133 External Remote Services",
"T1110 Brute Force","T1098 Account Manipulation"
]

# ---------------- HELPER FUNCTIONS ----------------
def random_location(): return random.choice(list(states.values()))
def random_sector(): return random.choice(sectors)
def random_mitre(): return random.choice(mitre_techniques)

def insert_threat(indicator,typ,severity):
    lat,lon = random_location()
    conn = db()
    conn.execute(
        "INSERT INTO threats(indicator,type,mitre,sector,severity,lat,lon,created) VALUES(?,?,?,?,?,?,?,?)",
        (indicator,typ,random_mitre(),random_sector(),severity,lat,lon,datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"))
    )
    conn.commit()

# ---------------- FETCH EXTERNAL FEEDS ----------------
def safe_fetch(fetch_func):
    try: fetch_func()
    except Exception as e: print(f"Feed fetch failed: {e}")

def fetch_threatfox():
    url="https://threatfox.abuse.ch/export/json/recent/"
    r=requests.get(url,timeout=10).json()
    for i in r.get("data",[])[:20]: insert_threat(i.get("ioc",""),i.get("ioc_type",""),85)

def fetch_urlhaus():
    url="https://urlhaus.abuse.ch/downloads/csv_recent/"
    data=requests.get(url,timeout=10).text.splitlines()
    reader=csv.reader(data)
    for row in list(reader)[10:30]:
        if len(row)>2: insert_threat(row[2],"malware_url",70)

def fetch_feodo():
    url="https://feodotracker.abuse.ch/downloads/ipblocklist.json"
    data=requests.get(url,timeout=10).json()
    for item in data[:20]: insert_threat(item.get("ip_address",""),"ip",90)

def fetch_hashes():
    url="https://mb-api.abuse.ch/api/v1/"
    r=requests.post(url,data={"query":"get_recent"},timeout=10).json()
    for item in r.get("data",[])[:20]: insert_threat(item.get("sha256_hash",""),"hash",75)

def fetch_feeds():
    for f in [fetch_threatfox, fetch_urlhaus, fetch_feodo, fetch_hashes]:
        safe_fetch(f)

fetch_feeds()

# ---------------- METRICS ----------------
def securenation_score():
    rows=db().execute("SELECT severity FROM threats ORDER BY id DESC LIMIT 100").fetchall()
    if not rows: return 0
    score=sum([r["severity"] for r in rows])/len(rows)
    return round(score,1)

def securenation_color(score):
    if score>=85: return 'red'
    elif score>=70: return 'orange'
    else: return 'lime'

def state_threat_score():
    rows=db().execute("SELECT severity FROM threats").fetchall()
    if len(rows)<50: return "LOW"
    elif len(rows)<150: return "ELEVATED"
    else: return "CRITICAL"

# ---------------- CHARTS ----------------
def timeline_chart():
    rows=db().execute("SELECT substr(created,1,10) d,count(*) c FROM threats GROUP BY d").fetchall()
    if not rows: return json.dumps({"data":[],"layout":{}})
    x=[r["d"] for r in rows]; y=[r["c"] for r in rows]
    fig=go.Figure(go.Scatter(x=x,y=y,mode="lines+markers",line=dict(color='#00FFFF')))
    fig.update_layout(plot_bgcolor='#0b1b2a',paper_bgcolor='#0b1b2a',font=dict(color='#00FFFF'),title="Threat Timeline")
    return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)

def mitre_chart():
    rows=db().execute("SELECT mitre,count(*) c FROM threats GROUP BY mitre").fetchall()
    if not rows: return json.dumps({"data":[],"layout":{}})
    labels=[r["mitre"] for r in rows]; values=[r["c"] for r in rows]
    fig=go.Figure(data=[go.Pie(labels=labels,values=values,hole=.4)])
    fig.update_layout(plot_bgcolor='#0b1b2a',paper_bgcolor='#0b1b2a',font=dict(color='#00FFFF'))
    return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)

def sector_chart():
    rows=db().execute("SELECT sector,count(*) c FROM threats GROUP BY sector").fetchall()
    if not rows: return json.dumps({"data":[],"layout":{}})
    labels=[r["sector"] for r in rows]; values=[r["c"] for r in rows]
    fig=go.Figure(go.Bar(
        x=labels,y=values,
        marker=dict(color='rgb(25,25,112)',line=dict(color='rgba(0,191,255,0.6)',width=3)),
        hovertemplate='%{x}: %{y}<extra></extra>'
    ))
    fig.update_layout(plot_bgcolor='#0b1b2a',paper_bgcolor='#0b1b2a',font=dict(color='white'),
                      title="Sector Targeting (Critical Sectors Under Attack)",xaxis_tickangle=-45)
    return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)

def malaysia_map():
    rows=db().execute("SELECT lat,lon,severity FROM threats ORDER BY id DESC LIMIT 50").fetchall()
    if not rows: return json.dumps({"data":[],"layout":{}})
    victim_lat,victim_lon,colors,sizes=[],[],[],[]
    for r in rows:
        victim_lat.append(r["lat"]); victim_lon.append(r["lon"])
        if r["severity"]>=85: colors.append("red"); sizes.append(16)
        elif r["severity"]>=70: colors.append("orange"); sizes.append(12)
        else: colors.append("yellow"); sizes.append(8)
    fig=go.Figure()
    fig.add_trace(go.Scattergeo(lat=victim_lat,lon=victim_lon,mode="markers",
        marker=dict(size=sizes,color=colors,opacity=0.9,line=dict(width=2,color="rgba(255,0,0,0.7)"))))
    for vlat,vlon in zip(victim_lat,victim_lon):
        src=random.choice(attack_sources)
        fig.add_trace(go.Scattergeo(lat=[src[0],vlat],lon=[src[1],vlon],mode="lines",
            line=dict(width=1,color="rgba(255,50,50,0.5)"),opacity=0.5))
    fig.update_layout(geo=dict(scope="asia",center=dict(lat=4.5,lon=102),
                               projection_type="natural earth",bgcolor="#0b1b2a"),
                      margin=dict(l=0,r=0,t=0,b=0))
    return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)

# ---------------- DASHBOARD STATUS ----------------
def dashboard_status():
    status={}
    rows=db().execute("SELECT substr(created,1,10) d,count(*) c FROM threats GROUP BY d").fetchall()
    status["Timeline"]="OK" if rows else "No Data"
    rows=db().execute("SELECT lat,lon FROM threats LIMIT 1").fetchall()
    status["Heatmap"]="OK" if rows else "No Data"
    rows=db().execute("SELECT mitre FROM threats LIMIT 1").fetchall()
    status["MITRE ATT&CK"]="OK" if rows else "No Data"
    rows=db().execute("SELECT sector FROM threats LIMIT 1").fetchall()
    status["Sector Targeting"]="OK" if rows else "No Data"
    score=securenation_score()
    status["SecureNation Index"]=f"{score} - OK" if score>0 else "No Data"
    rows=db().execute("SELECT * FROM threats LIMIT 1").fetchall()
    status["Download CSV/JSON/PDF"]="OK" if rows else "No Data"
    return status

# ---------------- HTML TEMPLATE ----------------
HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>RedShark CTI Dashboard</title>
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
    <style>
        body { background-color:#0b1b2a; color:#ffffff; font-family:Arial, sans-serif; }
        table { border-collapse: collapse; width: 100%; }
        th, td { padding: 8px; border: 1px solid #ccc; color:#ffffff; }
        th { cursor:pointer; background-color:#1b2b3a; }
        .disclaimer { color:grey; font-weight:bold; text-align:center; margin-top:10px; }
        .btn { padding:8px 12px; margin:5px; background-color:orange; color:white; border:none; cursor:pointer; }
    </style>
</head>
<body>
    <h1 style="text-align:center; color:#ffffff;">RedShark CTI Dashboard</h1>

    <!-- Charts -->
    <div id="timeline" style="width:100%;height:400px;"></div>
    <div id="mitre" style="width:100%;height:400px;"></div>
    <div id="sector" style="width:100%;height:400px;"></div>
    <div id="map" style="width:100%;height:500px;"></div>

    <!-- Threat table -->
    <h2>Recent Threats</h2>
    <table id="threatTable">
        <thead>
            <tr>
                <th>Indicator</th><th>Type</th><th>MITRE</th><th>Sector</th><th>Severity</th><th>Created</th>
            </tr>
        </thead>
        <tbody>
            {% for row in rows %}
            <tr>
                <td>{{row['indicator']}}</td>
                <td>{{row['type']}}</td>
                <td>{{row['mitre']}}</td>
                <td>{{row['sector']}}</td>
                <td>{{row['severity']}}</td>
                <td>{{row['created']}}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>

    <!-- Downloads -->
    <h2>Download RedShark CTI Reports</h2>
    <a href="/csv"><button class="btn">CSV</button></a>
    <a href="/json"><button class="btn">JSON</button></a>
    <a href="/pdf"><button class="btn">PDF</button></a>

    <p class="disclaimer">Developed and analyzed by darkgrid@redshark.my using publicly available sources.</p>

    <script>
        var timeline_data = {{timeline|safe}};
        Plotly.newPlot('timeline', timeline_data.data, timeline_data.layout);

        var mitre_data = {{mitre|safe}};
        Plotly.newPlot('mitre', mitre_data.data, mitre_data.layout);

        var sector_data = {{sector|safe}};
        Plotly.newPlot('sector', sector_data.data, sector_data.layout);

        var map_data = {{map|safe}};
        Plotly.newPlot('map', map_data.data, map_data.layout);
    </script>
</body>
</html>
"""

# ---------------- DASHBOARD ROUTE ----------------
@app.route("/")
def dashboard():
    index_score = securenation_score()
    return render_template_string(HTML,
        rows=db().execute("SELECT * FROM threats ORDER BY id DESC LIMIT 50").fetchall(),
        index=index_score,
        securenation_color=securenation_color(index_score),
        state_score=state_threat_score(),
        timeline=json.loads(timeline_chart()),
        mitre=json.loads(mitre_chart()),
        sector=json.loads(sector_chart()),
        map=json.loads(malaysia_map()),
        status=dashboard_status()
    )

# ---------------- EXPORT ----------------
@app.route("/csv")
def csv_export():
    rows=db().execute("SELECT * FROM threats").fetchall()
    if not rows: return "No data to export",200
    out=io.StringIO()
    writer=csv.writer(out)
    writer.writerow(rows[0].keys())
    for r in rows: writer.writerow(list(r))
    mem=io.BytesIO(); mem.write(out.getvalue().encode()); mem.seek(0)
    return send_file(mem,download_name="threats.csv",as_attachment=True)

@app.route("/json")
def json_export():
    rows=db().execute("SELECT * FROM threats").fetchall()
    if not rows: return "No data to export",200
    data=[dict(r) for r in rows]
    mem=io.BytesIO(); mem.write(json.dumps(data,indent=2).encode()); mem.seek(0)
    return send_file(mem,download_name="threats.json",as_attachment=True)

@app.route("/pdf")
def pdf_export():
    rows=db().execute("SELECT indicator,type,sector,severity FROM threats LIMIT 50").fetchall()
    if not rows: return "No data to export",200
    buffer=io.BytesIO()
    data=[["Indicator","Type","Sector","Severity"]]
    for r in rows: data.append([r["indicator"],r["type"],r["sector"],r["severity"]])
    pdf=SimpleDocTemplate(buffer,pagesize=landscape(A4))
    table=Table(data)
    pdf.build([table])
    buffer.seek(0)
    return send_file(buffer,download_name="redshark-cti-report.pdf",as_attachment=True)

if __name__=="__main__":
    app.run(host="0.0.0.0",port=int(os.environ.get("PORT",5000)))