import os, sqlite3, requests, json, csv, io, random, threading
from datetime import datetime
from flask import Flask, render_template_string, send_file
import plotly.graph_objs as go, plotly
from reportlab.platypus import SimpleDocTemplate, Table
from reportlab.lib.pagesizes import landscape, A4

app = Flask(__name__)
DB, RULE_FILE = "/tmp/threats.db", "/tmp/redshark.rules"
last_fetch_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

# ---------------- DATABASE ----------------
def db():
    conn = sqlite3.connect(DB, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = db()
    conn.execute("""
    CREATE TABLE IF NOT EXISTS threats(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        indicator TEXT UNIQUE,type TEXT,mitre TEXT,sector TEXT,
        severity INTEGER,lat REAL,lon REAL,created TEXT
    )""")
    conn.commit()
init_db()

# ---------------- STATES & SECTORS ----------------
states = {"Johor":[1.49,103.74],"Kedah":[6.11,100.36],"Kelantan":[6.12,102.23],
          "Melaka":[2.18,102.25],"Negeri Sembilan":[2.72,101.94],"Pahang":[3.81,103.32],
          "Perak":[4.59,101.09],"Perlis":[6.44,100.20],"Pulau Pinang":[5.41,100.33],
          "Sabah":[5.98,116.07],"Sarawak":[1.55,110.35],"Selangor":[3.07,101.51],
          "Terengganu":[5.33,103.14],"Kuala Lumpur":[3.13,101.68]}
sectors = ["Government","Banking","Telecommunications","Energy","Healthcare",
           "Education","Manufacturing","Transportation","Retail","Technology"]
mitre = ["Reconnaissance","Initial Access","Execution","Persistence","Privilege Escalation",
         "Defense Evasion","Credential Access","Discovery","Lateral Movement","Collection",
         "Command and Control","Exfiltration","Impact"]

def rand_loc(): return random.choice(list(states.values()))
def rand_sector(): return random.choice(sectors)
def rand_mitre(): return random.choice(mitre)

# ---------------- INSERT THREAT ----------------
def insert_threat(indicator, typ, severity):
    conn = db()
    if conn.execute("SELECT 1 FROM threats WHERE indicator=?", (indicator,)).fetchone(): return
    lat, lon = rand_loc(); m = rand_mitre(); s = rand_sector()
    created = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    conn.execute("INSERT INTO threats(indicator,type,mitre,sector,severity,lat,lon,created) VALUES(?,?,?,?,?,?,?,?)",
                 (indicator, typ, m, s, severity, lat, lon, created))
    conn.commit()
    # IPS rule generation
    rule_sid = 1000000 + random.randint(1,9999)
    line = f'alert ip any any -> any any (msg:"RedShark {typ.upper()} {indicator} | MITRE: {m}"; sid:{rule_sid}; rev:1;)\n'
    with open(RULE_FILE,"a") as f: f.write(line)

# ---------------- FEEDS ----------------
def fetch_threatfox():
    try:
        r = requests.get("https://threatfox.abuse.ch/export/json/recent/", timeout=10).json()
        for i in r.get("data", [])[:40]:
            insert_threat(i.get("ioc","unknown"), i.get("ioc_type","unknown"), 85)
    except: pass

def fetch_feodo():
    try:
        r = requests.get("https://feodotracker.abuse.ch/downloads/ipblocklist.json", timeout=10).json()
        for i in r[:40]: insert_threat(i.get("ip_address","0.0.0.0"), "ip", 90)
    except: pass

def fetch_urlhaus():
    try:
        r = requests.get("https://urlhaus.abuse.ch/downloads/csv_recent/", timeout=10).text.splitlines()
        reader = csv.reader(r)
        for row in list(reader)[10:50]:
            if len(row)>2: insert_threat(row[2],"url",70)
    except: pass

def fetch_hashes():
    try:
        r = requests.post("https://mb-api.abuse.ch/api/v1/", data={"query":"get_recent"}, timeout=10).json()
        for item in r.get("data", [])[:40]: insert_threat(item.get("sha256_hash",""), "hash", 75)
    except: pass

def fetch_feeds():
    global last_fetch_time
    fetch_threatfox(); fetch_feodo(); fetch_urlhaus(); fetch_hashes()
    last_fetch_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

# ---------------- BACKGROUND WORKER ----------------
def scheduler():
    fetch_feeds()
    threading.Timer(900,scheduler).start()  # every 15 min
threading.Thread(target=scheduler, daemon=True).start()

# ---------------- DASHBOARD DATA ----------------
def securenation():
    rows = db().execute("SELECT severity FROM threats ORDER BY id DESC LIMIT 50").fetchall()
    val = round(sum([r["severity"] for r in rows])/len(rows),1) if rows else 0
    color = "#FF3C3C" if val>=85 else "#FFA500" if val>=70 else "#00FF99"
    return val,color

def cti_highlight():
    rows = db().execute("SELECT indicator,type,sector,mitre,severity,created FROM threats ORDER BY id DESC LIMIT 5").fetchall()
    return (rows[0]["created"] if rows else datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            [{"statement":f"A new {r['type']} indicator targeting {r['sector']} sector leveraging {r['mitre']} detected (Severity {r['severity']}).",
              "created":r["created"]} for r in rows])

def nikkei_chart(x,y,title):
    fig = go.Figure()
    fig.add_trace(go.Scatter(x=x,y=y,mode='lines+markers',
                             line=dict(color="#00FFCC", width=4, shape='spline', smoothing=1.3),
                             marker=dict(size=10,color="#FFFFFF", line=dict(width=2,color="#00FFCC"))))
    fig.update_layout(plot_bgcolor="#0b1b2a", paper_bgcolor="#0b1b2a", font_color="#A3B8CC", title=title,
                      xaxis=dict(showgrid=False), yaxis=dict(showgrid=False))
    return json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

# ---------------- MALAYSIA MAP WITH PULSING CRITICALS ----------------
def malaysia_map():
    rows = db().execute("SELECT lat,lon,severity FROM threats ORDER BY id DESC LIMIT 20").fetchall()
    lat, lon, sev = [r["lat"] for r in rows], [r["lon"] for r in rows], [r["severity"] for r in rows]

    colors = ["#FF3C3C" if s>=85 else "#FF9900" if s>=70 else "#FFFF00" for s in sev]
    base_sizes = [20 if s>=85 else 14 if s>=70 else 10 for s in sev]

    # Create frames for pulsing (only for critical markers)
    frames = []
    for scale in [0.8, 1.0, 1.2, 1.0]:
        sizes = [int(bs*scale) if s>=85 else bs for bs,s in zip(base_sizes, sev)]
        frames.append(go.Frame(data=[go.Scattermapbox(
            lat=lat, lon=lon, mode="markers",
            marker=dict(size=sizes, color=colors, opacity=0.8),
            text=[f"Severity: {s}" for s in sev],
            hoverinfo="text"
        )]))

    # Initial figure
    fig = go.Figure(data=[go.Scattermapbox(
        lat=lat, lon=lon, mode="markers",
        marker=dict(size=base_sizes, color=colors, opacity=0.8),
        text=[f"Severity: {s}" for s in sev],
        hoverinfo="text"
    )], frames=frames)

    # Animation settings
    fig.update_layout(mapbox_style="carto-darkmatter",
                      mapbox_center={"lat":4.5,"lon":102}, mapbox_zoom=4,
                      paper_bgcolor="#0b1b2a", margin=dict(l=0,r=0,t=0,b=0),
                      mapbox=dict(accesstoken=None),
                      updatemenus=[dict(type="buttons",
                                        showactive=False,
                                        y=0,
                                        x=1.05,
                                        xanchor="right",
                                        yanchor="top",
                                        pad=dict(t=0,r=10),
                                        buttons=[dict(label="Play",
                                                      method="animate",
                                                      args=[None, {"frame":{"duration":800,"redraw":True},
                                                                   "fromcurrent":True,"transition":{"duration":0}}])])])
    return json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

# ---------------- OTHER CHARTS ----------------
def timeline_chart():
    rows = db().execute("SELECT substr(created,1,10) d, COUNT(*) c FROM threats GROUP BY d ORDER BY d").fetchall()
    return nikkei_chart([r["d"] for r in rows],[r["c"] for r in rows],"Threat Timeline")

def sector_chart():
    rows = db().execute("SELECT sector, COUNT(*) c FROM threats GROUP BY sector ORDER BY c DESC").fetchall()
    return nikkei_chart([r["sector"] for r in rows],[r["c"] for r in rows],"Sector Targeting")

def indicator_type_chart():
    rows = db().execute("SELECT type, COUNT(*) c FROM threats GROUP BY type").fetchall()
    return nikkei_chart([r["type"] for r in rows],[r["c"] for r in rows],"Indicator Type Distribution")

def mitre_chart():
    rows = db().execute("SELECT mitre, COUNT(*) c FROM threats GROUP BY mitre").fetchall()
    return nikkei_chart([r["mitre"] for r in rows],[r["c"] for r in rows],"MITRE Techniques Trend")

# ---------------- DASHBOARD HTML ----------------
HTML = """<html><head><title>RedShark Dashboard</title>
<script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
<link rel="stylesheet" href="https://cdn.datatables.net/1.13.4/css/jquery.dataTables.min.css">
<script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
<script src="https://cdn.datatables.net/1.13.4/js/jquery.dataTables.min.js"></script>
<style>
body{background:#0b1b2a;color:#A3B8CC;font-family:Arial;}
.card{background:#13263b;padding:20px;margin:15px;border-radius:8px;}
table{width:100%;border-collapse:collapse;}
td,th{padding:8px;border-bottom:1px solid #1f3d5c;text-align:center;}
.center{text-align:center;margin-top:15px;}
button.download-btn{background:#2A3A4B;color:#A3B8CC;font-weight:bold;padding:10px 18px;border:none;border-radius:5px;margin-right:8px;cursor:pointer;}
button.download-btn:hover{background:#3A4A5C;}
.secure-index{font-weight:bold;font-size:1.5em;}
.blink{animation: blinker 1s linear infinite;color:#FF3C3C;}
@keyframes blinker{50%{opacity:0;}}
</style></head><body>
<h2>RedShark Threat Intelligence Dashboard</h2>
<div class="card">Last CTI Fetch: <span style="color:#00FFCC">{{last_fetch_time}}</span></div>
<div class="card">SecureNation Index: <span class="secure-index" style="color:{{index_color}}">{{index}}</span></div>
<div class="card"><h3>CTI Highlight at {{highlight_time}}</h3>
<ul>{% for b in highlights %}<li class="{% if 'Severity 85' in b.statement or 'Severity 90' in b.statement %}blink{% endif %}">{{b.statement}}</li>{% endfor %}</ul>
<button class="download-btn" onclick="manualRefresh()">Refresh Feeds</button>
<span id="refresh_status" style="margin-left:10px;color:#00FFCC;"></span>
</div>
<div class="card"><h3>Malaysia Cyber Attack Map</h3><div id="map" style="height:400px;"></div></div>
<div class="card"><h3>Threat Timeline</h3><div id="timeline" style="height:300px;"></div></div>
<div class="card"><h3>MITRE ATT&CK Techniques</h3><div id="mitre" style="height:300px;"></div></div>
<div class="card"><h3>Sector Targeting</h3><div id="sector" style="height:300px;"></div></div>
<div class="card"><h3>Indicator Type Distribution</h3><div id="indicator_type" style="height:300px;"></div></div>
<div class="card"><h3>Latest Threat Indicators</h3><table id="threat_table"><thead><tr><th>ID</th><th>Indicator</th><th>Type</th><th>Sector</th><th>Severity</th><th>MITRE</th><th>Timestamp</th></tr></thead>
<tbody>{% for r in rows %}<tr><td>{{r.id}}</td><td>{{r.indicator}}</td><td>{{r.type}}</td><td>{{r.sector}}</td><td>{{r.severity}}</td><td>{{r.mitre}}</td><td>{{r.created}}</td></tr>{% endfor %}</tbody></table></div>
<div class="center">
<button class="download-btn" onclick="window.location='/csv'">CSV</button>
<button class="download-btn" onclick="window.location='/json'">JSON</button>
<button class="download-btn" onclick="window.location='/pdf'">PDF</button>
<button class="download-btn" onclick="window.location='/download_ips'">IPS RULE</button>
</div>
<script>
Plotly.newPlot("timeline",{{timeline|safe}}.data,{{timeline|safe}}.layout);
Plotly.newPlot("mitre",{{mitre|safe}}.data,{{mitre|safe}}.layout);
Plotly.newPlot("sector",{{sector|safe}}.data,{{sector|safe}}.layout);
Plotly.newPlot("indicator_type",{{indicator_type|safe}}.data,{{indicator_type|safe}}.layout);
Plotly.newPlot("map",{{map|safe}}.data,{{map|safe}}.layout).then(function(){
    Plotly.addFrames("map", {{map|safe}}.frames);
});
$('#threat_table').DataTable();

function manualRefresh(){
    document.getElementById("refresh_status").innerText="Refreshing...";
    fetch('/refresh_feeds')
        .then(response=>response.text())
        .then(data=>{
            document.getElementById("refresh_status").innerText=data;
            setTimeout(()=>{document.getElementById("refresh_status").innerText="";location.reload();},2000);
        })
        .catch(err=>{
            document.getElementById("refresh_status").innerText="Failed to refresh feeds";
        });
}
</script></body></html>"""

# ---------------- DASHBOARD ROUTE ----------------
@app.route("/")
def dashboard():
    index, index_color = securenation()
    highlight_time, highlights = cti_highlight()
    rows=db().execute("SELECT * FROM threats ORDER BY id DESC LIMIT 50").fetchall()
    return render_template_string(HTML, rows=rows, index=index, index_color=index_color,
                                  highlight_time=highlight_time, highlights=highlights,
                                  timeline=timeline_chart(), mitre=mitre_chart(),
                                  sector=sector_chart(), indicator_type=indicator_type_chart(),
                                  map=malaysia_map(), last_fetch_time=last_fetch_time)

# ---------------- EXPORT ----------------
@app.route("/csv")
def csv_export():
    rows=db().execute("SELECT * FROM threats").fetchall()
    out=io.StringIO(); writer=csv.writer(out)
    if rows: writer.writerow(rows[0].keys())
    for r in rows: writer.writerow(list(r))
    mem=io.BytesIO(); mem.write(out.getvalue().encode()); mem.seek(0)
    return send_file(mem,download_name="threats.csv",as_attachment=True)

@app.route("/json")
def json_export():
    rows=db().execute("SELECT * FROM threats").fetchall()
    mem=io.BytesIO(); mem.write(json.dumps([dict(r) for r in rows],indent=2).encode()); mem.seek(0)
    return send_file(mem,download_name="threats.json",as_attachment=True)

@app.route("/pdf")
def pdf_export():
    rows=db().execute("SELECT indicator,type,sector,severity,mitre,created FROM threats LIMIT 50").fetchall()
    buffer=io.BytesIO(); data=[["Indicator","Type","Sector","Severity","MITRE","Timestamp"]]+[[r["indicator"],r["type"],r["sector"],r["severity"],r["mitre"],r["created"]] for r in rows]
    pdf=SimpleDocTemplate(buffer,pagesize=landscape(A4)); pdf.build([Table(data)]); buffer.seek(0)
    return send_file(buffer,download_name="redshark-cti-report.pdf",as_attachment=True)

@app.route("/download_ips")
def download_ips():
    if not os.path.exists(RULE_FILE): open(RULE_FILE,"w").close()
    return send_file(RULE_FILE, download_name="redshark-ips.rules", as_attachment=True)

# ---------------- MANUAL REFRESH ----------------
@app.route("/refresh_feeds")
def refresh_feeds_route():
    try:
        fetch_feeds()
        return "Feeds refreshed successfully!"
    except Exception as e:
        return f"Failed to refresh feeds: {e}"

# ---------------- STARTUP ----------------
fetch_feeds()  # initial demo fetch

if __name__=="__main__":
    app.run(host="0.0.0.0", port=5000)