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
import requests

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

def insert_dummy():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM threats")
    if c.fetchone()[0] == 0:
        for i in range(5):
            state = random.choice(list(MALAYSIA.keys()))
            score = random.randint(40,90)
            classification = "High" if score>=70 else "Medium" if score>=40 else "Low"
            c.execute("""
            INSERT INTO threats(indicator,type,source,risk_score,classification,state,created_at)
            VALUES(?,?,?,?,?,?,?)
            """, (f"dummy{i}.malicious.com","domain","dummy",score,classification,state,datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()

def classify(score):
    return "High" if score>=70 else "Medium" if score>=40 else "Low"

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

def top_indicators():
    conn=sqlite3.connect(DB)
    conn.row_factory=sqlite3.Row
    c=conn.cursor()
    rows=c.execute("SELECT indicator,COUNT(*) c FROM threats GROUP BY indicator ORDER BY c DESC LIMIT 10").fetchall()
    conn.close()
    return rows

def secure_index():
    conn=sqlite3.connect(DB)
    c=conn.cursor()
    high=c.execute("SELECT COUNT(*) FROM threats WHERE classification='High'").fetchone()[0]
    medium=c.execute("SELECT COUNT(*) FROM threats WHERE classification='Medium'").fetchone()[0]
    conn.close()
    score=100-(high*2+medium)
    return max(score,0)

# ---------------- Scheduler ----------------
def scheduler():
    while True:
        ingest_feeds()
        threading.Event().wait(3600)  # every hour

threading.Thread(target=scheduler,daemon=True).start()

# ---------------- Dashboard ----------------
@app.route("/")
def dashboard():
    try:
        heatmap = malaysia_heatmap()
        trend = trend_chart()
        source = source_chart()
        top = top_indicators()
        index = secure_index()

        conn=sqlite3.connect(DB)
        conn.row_factory=sqlite3.Row
        c=conn.cursor()
        rows=c.execute("SELECT * FROM threats ORDER BY created_at DESC LIMIT 50").fetchall()
        conn.close()

        template=open("templates/dashboard.html").read()
        return render_template_string(template, rows=rows, heatmap=heatmap, trend=trend, source=source, top=top, index=index)
    except Exception as e:
        return f"<h1>Internal Server Error</h1><pre>{e}</pre>"

# ---------------- IOC Search ----------------
@app.route("/search")
def ioc_search():
    query=request.args.get("ioc","")
    conn=sqlite3.connect(DB)
    conn.row_factory=sqlite3.Row
    c=conn.cursor()
    rows=c.execute("SELECT * FROM threats WHERE indicator LIKE ? LIMIT 50",("%"+query,)).fetchall()
    conn.close()
    return {"results":[dict(r) for r in rows]}

# ---------------- CSV / JSON / PDF ----------------
@app.route("/download/csv")
def download_csv():
    conn=sqlite3.connect(DB)
    conn.row_factory=sqlite3.Row
    c=conn.cursor()
    rows=c.execute("SELECT * FROM threats").fetchall()
    conn.close()
    si=io.StringIO()
    writer=csv.DictWriter(si,fieldnames=rows[0].keys() if rows else ["id","indicator","type","source","risk_score","classification","state","created_at"])
    writer.writeheader()
    for r in rows: writer.writerow(dict(r))
    output=io.BytesIO()
    output.write(si.getvalue().encode())
    output.seek(0)
    return send_file(output,mimetype="text/csv",download_name="threats.csv",as_attachment=True)

@app.route("/download/json")
def download_json():
    conn=sqlite3.connect(DB)
    conn.row_factory=sqlite3.Row
    c=conn.cursor()
    rows=c.execute("SELECT * FROM threats").fetchall()
    conn.close()
    output=io.BytesIO()
    output.write(json.dumps([dict(r) for r in rows],indent=2).encode())
    output.seek(0)
    return send_file(output,mimetype="application/json",download_name="threats.json",as_attachment=True)

@app.route("/download/pdf")
def download_pdf():
    conn=sqlite3.connect(DB)
    conn.row_factory=sqlite3.Row
    c=conn.cursor()
    rows=c.execute("SELECT * FROM threats ORDER BY created_at DESC").fetchall()
    conn.close()

    buffer=io.BytesIO()
    doc=SimpleDocTemplate(buffer,pagesize=A4)
    elements=[]
    styles=getSampleStyleSheet()
    elements.append(Paragraph("Sunday-Ring SOC Threat Report",styles['Title']))
    elements.append(Spacer(1,12))
    data=[["ID","Indicator","Type","Source","Risk","Class","State","Time"]]
    for r in rows:
        data.append([r["id"],r["indicator"],r["type"],r["source"],r["risk_score"],r["classification"],r["state"],r["created_at"]])
    table=Table(data,repeatRows=1)
    table.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,0),colors.darkblue),
        ('TEXTCOLOR',(0,0),(-1,0),colors.white),
        ('GRID',(0,0),(-1,-1),0.5,colors.cyan),
        ('ALIGN',(0,0),(-1,-1),'LEFT')
    ]))
    elements.append(table)
    doc.build(elements)
    buffer.seek(0)
    return send_file(buffer,mimetype="application/pdf",download_name="threats.pdf",as_attachment=True)

# ---------------- Run ----------------
if __name__=="__main__":
    init_db()
    insert_dummy()
    ingest_feeds()
    port=int(os.environ.get("PORT",5000))
    app.run(host="0.0.0.0",port=port)