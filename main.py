import os
import sqlite3
import requests
import csv
import io
import json
import random
from datetime import datetime
from flask import Flask, render_template_string, send_file
import plotly.graph_objs as go
import plotly
from reportlab.platypus import SimpleDocTemplate, Table
from reportlab.lib.pagesizes import landscape, A4

app = Flask(__name__)
DB = "threats.db"

# ---------------- Database ----------------
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

# ---------------- Malaysia States ----------------
states = {
    "Johor":[1.4927,103.7414],"Kedah":[6.1184,100.3685],"Kelantan":[6.1254,102.2381],
    "Melaka":[2.1896,102.2501],"Negeri Sembilan":[2.7258,101.9424],"Pahang":[3.8126,103.3256],
    "Perak":[4.5921,101.0901],"Perlis":[6.4449,100.2048],"Pulau Pinang":[5.4164,100.3327],
    "Sabah":[5.9804,116.0735],"Sarawak":[1.5533,110.3592],"Selangor":[3.0738,101.5183],
    "Terengganu":[5.3302,103.1408],"Kuala Lumpur":[3.1390,101.6869],
    "Putrajaya":[2.9264,101.6964],"Labuan":[5.2831,115.2308]
}

# ---------------- Sectors ----------------
sectors = [
    "Government","Banking & Finance","Telecommunications","Energy","Healthcare",
    "Education","Manufacturing","Transportation","Retail","Media","Hospitality",
    "Agriculture","Technology","Logistics","Utilities"
]

# ---------------- MITRE Techniques ----------------
mitre_techniques = [
"T1003 Credential Dumping","T1059 Command and Scripting Interpreter",
"T1047 Windows Management Instrumentation","T1027 Obfuscated Files or Information",
"T1566 Phishing","T1105 Ingress Tool Transfer","T1071 Application Layer Protocol",
"T1090 Proxy","T1078 Valid Accounts"
]

# ---------------- Helpers ----------------
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

# ---------------- Fetch Sample Feeds ----------------
def fetch_sample():
    for _ in range(20):
        insert_threat(f"sample{i}", "malware", random.randint(50,100))

fetch_sample()

# ---------------- Charts ----------------
def timeline_chart():
    rows=db().execute("SELECT substr(created,1,10) d,count(*) c FROM threats GROUP BY d").fetchall()
    x=[r["d"] for r in rows]; y=[r["c"] for r in rows]
    fig=go.Figure(go.Scatter(x=x,y=y,mode="lines+markers",line=dict(color='#00FFFF')))
    return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)

def mitre_chart():
    rows=db().execute("SELECT mitre,count(*) c FROM threats GROUP BY mitre").fetchall()
    labels=[r["mitre"] for r in rows]; values=[r["c"] for r in rows]
    fig=go.Figure(data=[go.Pie(labels=labels,values=values,hole=.4)])
    return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)

def sector_chart():
    rows=db().execute("SELECT sector,count(*) c FROM threats GROUP BY sector").fetchall()
    labels=[r["sector"] for r in rows]; values=[r["c"] for r in rows]
    fig=go.Figure(go.Bar(x=labels,y=values,marker=dict(color='darkgrey')))
    return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)

# ---------------- Map ----------------
def malaysia_map():
    rows=db().execute("SELECT lat,lon,severity FROM threats ORDER BY id DESC LIMIT 50").fetchall()
    victim_lat,victim_lon=[],[]
    for r in rows:
        victim_lat.append(r["lat"]); victim_lon.append(r["lon"])
    fig=go.Figure(go.Scattergeo(lat=victim_lat,lon=victim_lon,mode="markers"))
    fig.update_layout(geo=dict(scope="asia",center=dict(lat=4.5,lon=102)))
    return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)

# ---------------- Dashboard ----------------
HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>RedShark CTI Dashboard v2.5</title>
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
</head>
<body>
    <h1>RedShark CTI Dashboard v2.5</h1>
    <div id="timeline" style="width:100%;height:400px;"></div>
    <div id="mitre" style="width:100%;height:400px;"></div>
    <div id="sector" style="width:100%;height:400px;"></div>
    <div id="map" style="width:100%;height:500px;"></div>

    <h2>Recent Threats</h2>
    <table border="1">
        <tr><th>Indicator</th><th>Type</th><th>MITRE</th><th>Sector</th><th>Severity</th><th>Created</th></tr>
        {% for row in rows %}
        <tr>
            <td>{{row['indicator']}}</td><td>{{row['type']}}</td><td>{{row['mitre']}}</td>
            <td>{{row['sector']}}</td><td>{{row['severity']}}</td><td>{{row['created']}}</td>
        </tr>
        {% endfor %}
    </table>

    <h2>Download RedShark CTI Reports</h2>
    <a href="/csv">CSV</a> | <a href="/json">JSON</a> | <a href="/pdf">PDF</a>
</body>
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
</html>
"""

@app.route("/")
def dashboard():
    return render_template_string(HTML,
        rows=db().execute("SELECT * FROM threats ORDER BY id DESC LIMIT 50").fetchall(),
        timeline=json.loads(timeline_chart()),
        mitre=json.loads(mitre_chart()),
        sector=json.loads(sector_chart()),
        map=json.loads(malaysia_map())
    )

# ---------------- Export ----------------
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
    data=[dict(r) for r in rows]
    mem=io.BytesIO(); mem.write(json.dumps(data,indent=2).encode()); mem.seek(0)
    return send_file(mem,download_name="threats.json",as_attachment=True)

@app.route("/pdf")
def pdf_export():
    rows=db().execute("SELECT indicator,type,sector,severity FROM threats LIMIT 50").fetchall()
    data=[["Indicator","Type","Sector","Severity"]]
    for r in rows: data.append([r["indicator"],r["type"],r["sector"],r["severity"]])
    buffer=io.BytesIO()
    pdf=SimpleDocTemplate(buffer,pagesize=landscape(A4))
    table=Table(data)
    pdf.build([table])
    buffer.seek(0)
    return send_file(buffer,download_name="redshark-cti-report.pdf",as_attachment=True)

if __name__=="__main__":
    app.run(host="0.0.0.0",port=int(os.environ.get("PORT",5000)))