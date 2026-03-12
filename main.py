import os, sqlite3, random, threading, csv, io, json
from datetime import datetime
from flask import Flask, render_template_string, send_file
import plotly.graph_objs as go
from plotly.utils import PlotlyJSONEncoder
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet

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

# ---------------- Feeds ----------------
def ingest_feeds():
    try:
        insert_threat("8.8.8.8","ip","DummyFeed")
        insert_threat("malicious.com","domain","DummyFeed")
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
        size.append(r["c"]*5)
        text.append(f"{r['state']}: {r['c']}")
    fig=go.Figure()
    fig.add_trace(go.Scattergeo(lat=lat,lon=lon,text=text,
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
    fig=go.Figure(go.Scatter(x=x,y=y,mode="lines+markers",line=dict(color="cyan")))
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
    colors_list=[]
    for v in labels:
        if v.lower()=="dummy": colors_list.append("red")
        else: colors_list.append("cyan")
    fig=go.Figure([go.Pie(labels=labels,values=values,marker=dict(colors=colors_list))])
    fig.update_layout(paper_bgcolor="#0b1b2a",font=dict(color="cyan"))
    return json.dumps(fig,cls=PlotlyJSONEncoder)

# ---------------- PDF Export ----------------
def generate_pdf(rows):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4)
    styles = getSampleStyleSheet()
    elements = []
    elements.append(Paragraph("Sunday-Ring SOC Dashboard Report", styles['Title']))
    elements.append(Paragraph(f"Generated at: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC", styles['Normal']))
    elements.append(Paragraph(" ", styles['Normal']))

    data = [["ID","Indicator","Type","Source","Risk","Class","State","Time"]]
    for r in rows:
        data.append([r["id"], r["indicator"], r["type"], r["source"], r["risk_score"], r["classification"], r["state"], r["created_at"]])
    
    table = Table(data, repeatRows=1)
    table.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,0),colors.darkblue),
        ('TEXTCOLOR',(0,0),(-1,0),colors.cyan),
        ('GRID',(0,0),(-1,-1),0.5,colors.white),
        ('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'),
        ('FONTSIZE',(0,0),(-1,-1),8),
        ('ALIGN',(0,0),(-1,-1),'LEFT')
    ]))
    elements.append(table)
    doc.build(elements)
    buffer.seek(0)
    return buffer

# ---------------- Routes ----------------
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

@app.route("/download/csv")
def download_csv():
    conn=sqlite3.connect(DB)
    conn.row_factory=sqlite3.Row
    rows=conn.cursor().execute("SELECT * FROM threats ORDER BY created_at DESC LIMIT 50").fetchall()
    conn.close()
    si = io.StringIO()
    writer = csv.writer(si)
    writer.writerow(["ID","Indicator","Type","Source","Risk","Class","State","Time"])
    for r in rows:
        writer.writerow([r["id"],r["indicator"],r["type"],r["source"],r["risk_score"],r["classification"],r["state"],r["created_at"]])
    output=io.BytesIO()
    output.write(si.getvalue().encode("utf-8"))
    output.seek(0)
    return send_file(output, mimetype="text/csv", download_name="soc_dashboard.csv", as_attachment=True)

@app.route("/download/json")
def download_json():
    conn=sqlite3.connect(DB)
    conn.row_factory=sqlite3.Row
    rows=conn.cursor().execute("SELECT * FROM threats ORDER BY created_at DESC LIMIT 50").fetchall()
    conn.close()
    data=[dict(r) for r in rows]
    output=io.BytesIO()
    output.write(json.dumps(data, indent=2).encode("utf-8"))
    output.seek(0)
    return send_file(output, mimetype="application/json", download_name="soc_dashboard.json", as_attachment=True)

@app.route("/download/pdf")
def download_pdf():
    conn=sqlite3.connect(DB)
    conn.row_factory=sqlite3.Row
    rows=conn.cursor().execute("SELECT * FROM threats ORDER BY created_at DESC LIMIT 50").fetchall()
    conn.close()
    buffer = generate_pdf(rows)
    return send_file(buffer, mimetype="application/pdf", download_name="soc_dashboard.pdf", as_attachment=True)

# ---------------- Scheduler ----------------
def scheduler():
    while True:
        ingest_feeds()
        threading.Event().wait(3600)
threading.Thread(target=scheduler,daemon=True).start()

# ---------------- Template ----------------
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
a.button {background:#00FFFF;color:#0b1b2a;padding:6px 12px;text-decoration:none;border-radius:4px;margin-right:5px;}
.high{color:red;font-weight:bold;}
.medium{color:orange;font-weight:bold;}
.low{color:green;font-weight:bold;}
</style>
</head>
<body>
<h2>Sunday-Ring SOC Dashboard</h2>

<a href="/download/csv" class="button">Download CSV</a>
<a href="/download/json" class="button">Download JSON</a>
<a href="/download/pdf" class="button">Download PDF</a>

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
<td class="{{r.classification|lower}}">{{r.classification}}</td>
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

# ---------------- Run ----------------
if __name__=="__main__":
    init_db()
    insert_dummy()
    ingest_feeds()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT",5000)), debug=False)