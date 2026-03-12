import os, sqlite3, csv, json, random, threading
from datetime import datetime
from flask import Flask, render_template_string, request, send_file
import io
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
import plotly.graph_objs as go
from plotly.utils import PlotlyJSONEncoder

app = Flask(__name__)
DB = "/tmp/soc.db"

# ---------------- Malaysia States ----------------
MALAYSIA = {
    "Johor": (1.48,103.76),"Kedah": (6.12,100.36),"Kelantan": (6.12,102.23),
    "Melaka": (2.18,102.25),"Negeri Sembilan": (2.72,101.94),"Pahang": (3.81,103.32),
    "Perak": (4.59,101.09),"Perlis": (6.44,100.20),"Penang": (5.41,100.33),
    "Sabah": (5.98,116.07),"Sarawak": (1.55,110.35),"Selangor": (3.07,101.52),
    "Terengganu": (5.31,103.13),"Kuala Lumpur": (3.13,101.69),"Putrajaya": (2.92,101.69),
    "Labuan": (5.27,115.24)
}

# ---------------- Database ----------------
def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS threats(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        indicator TEXT,
        type TEXT,
        source TEXT,
        risk_score INTEGER,
        classification TEXT,
        state TEXT,
        created_at TEXT
    )
    """)
    conn.commit()
    conn.close()

def classify(score):
    return "High" if score>=70 else "Medium" if score>=40 else "Low"

def insert_dummy():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM threats")
    if c.fetchone()[0] == 0:
        for i in range(5):
            state = random.choice(list(MALAYSIA.keys()))
            score = random.randint(40,90)
            classification = classify(score)
            c.execute("""
            INSERT INTO threats(indicator,type,source,risk_score,classification,state,created_at)
            VALUES(?,?,?,?,?,?,?)
            """, (f"dummy{i}.malicious.com","domain","dummy",score,classification,state,datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()

def insert_threat(indicator,type_,source):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    score = random.randint(60,95)
    state = random.choice(list(MALAYSIA.keys()))
    c.execute("""
    INSERT INTO threats(indicator,type,source,risk_score,classification,state,created_at)
    VALUES(?,?,?,?,?,?,?)
    """,(indicator,type_,source,score,classify(score),state,datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()

# ---------------- External Feeds ----------------
def ingest_feeds():
    headers={"User-Agent":"SundayRingSOC"}

    # Spamhaus DROP
    try:
        r=requests.get("https://www.spamhaus.org/drop/drop.txt",headers=headers,timeout=10)
        for line in r.text.splitlines()[:30]:
            if line.startswith(";") or not line.strip(): continue
            ip=line.split(";")[0].strip()
            insert_threat(ip,"ip","Spamhaus")
    except: pass

    # URLHaus
    try:
        r=requests.get("https://urlhaus.abuse.ch/downloads/csv_online/",headers=headers,timeout=10)
        reader=csv.reader(r.text.splitlines())
        rows=list(reader)
        for row in rows[9:40]:
            if len(row)<3: continue
            url=row[2].strip()
            if url=="": continue
            insert_threat(url,"url","URLHaus")
    except: pass

    # PhishTank
    try:
        r=requests.get("https://data.phishtank.com/data/online-valid.csv",headers=headers,timeout=10)
        reader=csv.reader(r.text.splitlines())
        for row in list(reader)[1:20]:
            url=row[1].strip()
            if url=="": continue
            insert_threat(url,"url","PhishTank")
    except: pass

# ---------------- Charts ----------------
def malaysia_heatmap():
    conn=sqlite3.connect(DB)
    conn.row_factory=sqlite3.Row
    c=conn.cursor()
    rows=c.execute("SELECT state,COUNT(*) c FROM threats GROUP BY state").fetchall()
    conn.close()
    if not rows: rows=[{"state":"Kuala Lumpur","c":1}]
    lat,lon,size,text=[],[],[],[]
    for r in rows:
        if r["state"] not in MALAYSIA: continue
        la,lo=MALAYSIA[r["state"]]
        lat.append(la)
        lon.append(lo)
        size.append(r["c"]*2)
        text.append(f"{r['state']}: {r['c']}")
    fig=go.Figure(go.Scattergeo(lat=lat,lon=lon,text=text,
        marker=dict(size=size,color="red",opacity=0.7)
    ))
    fig.update_layout(
        geo=dict(scope="asia",center=dict(lat=4.5,lon=102),projection_scale=7,bgcolor="#0b1b2a"),
        paper_bgcolor="#0b1b2a"
    )
    return json.dumps(fig,cls=PlotlyJSONEncoder)

def trend_chart():
    conn=sqlite3.connect(DB)
    conn.row_factory=sqlite3.Row
    c=conn.cursor()
    rows=c.execute("SELECT substr(created_at,1,10) d, COUNT(*) c FROM threats GROUP BY d").fetchall()
    conn.close()
    if not rows: rows=[{"d":"2026-03-12","c":0}]
    x=[r["d"] for r in rows]
    y=[r["c"] for r in rows]
    fig=go.Figure(go.Scatter(x=x,y=y,mode="lines+markers"))
    fig.update_layout(title="Threat Timeline",paper_bgcolor="#0b1b2a",font=dict(color="cyan"))
    return json.dumps(fig,cls=PlotlyJSONEncoder)

def source_chart():
    conn=sqlite3.connect(DB)
    conn.row_factory=sqlite3.Row
    c=conn.cursor()
    rows=c.execute("SELECT source,COUNT(*) c FROM threats GROUP BY source").fetchall()
    conn.close()
    if not rows: rows=[{"source":"dummy","c":1}]
    labels=[r["source"] for r in rows]
    values=[r["c"] for r in rows]
    fig=go.Figure([go.Pie(labels=labels,values=values)])
    fig.update_layout(paper_bgcolor="#0b1b2a",font=dict(color="cyan"))
    return json.dumps(fig,cls=PlotlyJSONEncoder)

# ---------------- Dashboard Template ----------------
DASHBOARD_TEMPLATE = """
<html>
<head>
<title>Sunday-Ring SOC Dashboard</title>
<script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
<style>
body {background:#0b1b2a;color:#00FFFF;font-family:sans-serif;margin:0;padding:10px;}
h2 {color:#00FFFF;}
table {border-collapse:collapse;width:100%;word-wrap:break-word;margin-top:20px;}
th,td {padding:6px;text-align:left;}
th {background:#00274d;color:#00FFFF;}
tr:nth-child(even){background:#0c2a4a;}
tr:nth-child(odd){background:#0b1b2a;}
</style>
</head>
<body>
<h2>Sunday-Ring SOC Dashboard</h2>

<div id="heatmap" style="height:400px;"></div>
<div id="trend" style="height:300px;"></div>
<div id="source" style="height:300px;"></div>

<h3>Latest Indicators</h3>
<table>
<thead><tr>
<th>ID</th><th>Indicator</th><th>Type</th><th>Source</th><th>Risk</th><th>Class</th><th>State</th><th>Time</th>
</tr></thead>
<tbody>
{% for r in rows %}
<tr>
<td>{{r.id}}</td>
<td>{{r.indicator}}</td>
<td>{{r.type}}</td>
<td>{{r.source}}</td>
<td>{{r.risk_score}}</td>
<td>{{r.classification}}</td>
<td>{{r.state}}</td>
<td>{{r.created_at}}</td>
</tr>
{% endfor %}
</tbody>
</table>

<script>
var heatmap = {{ heatmap | safe }};
var trend = {{ trend | safe }};
var source = {{ source | safe }};
Plotly.newPlot('heatmap', heatmap.data, heatmap.layout);
Plotly.newPlot('trend', trend.data, trend.layout);
Plotly.newPlot('source', source.data, source.layout);
</script>
</body>
</html>
"""

# ---------------- Scheduler ----------------
def scheduler():
    while True:
        ingest_feeds()
        threading.Event().wait(3600)

threading.Thread(target=scheduler,daemon=True).start()

# ---------------- Dashboard Route ----------------
@app.route("/")
def dashboard():
    try:
        heatmap = malaysia_heatmap()
        trend = trend_chart()
        source = source_chart()
        conn=sqlite3.connect(DB)
        conn.row_factory=sqlite3.Row
        rows=conn.cursor().execute("SELECT * FROM threats ORDER BY created_at DESC LIMIT 50").fetchall()
        conn.close()
        return render_template_string(DASHBOARD_TEMPLATE, rows=rows, heatmap=heatmap, trend=trend, source=source)
    except Exception as e:
        return f"<h1>Internal Server Error</h1><pre>{e}</pre>"

# ---------------- Run ----------------
if __name__=="__main__":
    init_db()
    insert_dummy()
    ingest_feeds()
    port=int(os.environ.get("PORT",5000))
    app.run(host="0.0.0.0",port=port)