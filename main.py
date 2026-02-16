import os
import sqlite3
import requests
import io
import csv
import json
from datetime import datetime, timedelta
from flask import Flask, jsonify, request, render_template_string, send_file, abort
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.pagesizes import landscape, A4
from reportlab.pdfgen import canvas
import matplotlib.pyplot as plt
import threading

# ================= CONFIG =================
app = Flask(__name__)
DB_FILE = "cti_platform.db"
REPORTS_DIR = "reports"
os.makedirs(REPORTS_DIR, exist_ok=True)

OTX_API_KEY = os.environ.get("OTX_API_KEY")
ADMIN_KEY = os.environ.get("ADMIN_KEY", "change_this")

# ================= DATABASE =================
def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS threats (
        id TEXT PRIMARY KEY,
        pulse_name TEXT,
        threat_actor TEXT,
        indicator TEXT,
        indicator_type TEXT,
        latitude REAL,
        longitude REAL,
        mitre_tactic TEXT,
        classification TEXT,
        created TEXT
    )
    """)
    c.execute("""
    CREATE TABLE IF NOT EXISTS notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        threat_id TEXT,
        analyst TEXT,
        note TEXT,
        created TEXT
    )
    """)
    conn.commit()
    conn.close()

init_db()

# ================= INTELLIGENCE LOGIC =================
def mitre_tag(indicator_type):
    mapping = {
        "domain": "Command and Control",
        "IPv4": "Initial Access",
        "URL": "Execution",
        "FileHash-SHA256": "Defense Evasion"
    }
    return mapping.get(indicator_type, "Reconnaissance")

def classify_indicator(indicator):
    indicator = indicator.lower()
    if ".my" in indicator:
        return "TARGET_MY"
    if indicator.startswith(("103.","175.","60.")):
        return "SOURCE_MY"
    return "SOURCE_OTHER"

def get_geo(ip):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        if r.status_code == 200:
            data = r.json()
            return data.get("lat"), data.get("lon")
    except:
        pass
    return None, None

def calculate_risk(rows):
    weights = {"TARGET_MY":4,"SOURCE_MY":3,"SOURCE_OTHER":1}
    score = sum(weights.get(r["classification"],0) for r in rows)
    if score>100: level="CRITICAL"
    elif score>50: level="HIGH"
    elif score>20: level="MODERATE"
    else: level="LOW"
    return score, level

def cleanup_old():
    cutoff=(datetime.utcnow()-timedelta(days=30)).isoformat()
    conn=get_db()
    conn.execute("DELETE FROM threats WHERE created < ?",(cutoff,))
    conn.commit()
    conn.close()

# ================= ADMIN INGEST =================
@app.route("/admin/update")
def admin_update():
    if request.args.get("key")!=ADMIN_KEY:
        abort(403)

    headers={"X-OTX-API-KEY":OTX_API_KEY}
    r=requests.get("https://otx.alienvault.com/api/v1/pulses/subscribed",headers=headers,timeout=15)
    if r.status_code!=200:
        return jsonify({"error":"OTX fetch failed"}),500

    pulses=r.json().get("results",[])
    conn=get_db()
    c=conn.cursor()
    inserted=0

    for pulse in pulses:
        actor=pulse.get("author_name","Unknown")
        created=pulse.get("created")
        for ind in pulse.get("indicators",[]):
            indicator=ind.get("indicator")
            ind_type=ind.get("type")
            tactic=mitre_tag(ind_type)
            classification=classify_indicator(indicator)
            lat,lon=(None,None)
            if ind_type=="IPv4":
                lat,lon=get_geo(indicator)
            threat_id=pulse.get("id")+indicator
            c.execute("""
            INSERT OR IGNORE INTO threats
            VALUES (?,?,?,?,?,?,?,?,?,?)
            """,(
                threat_id,
                pulse.get("name"),actor,
                indicator,ind_type,
                lat,lon,tactic,
                classification,created
            ))
            inserted+=1

    conn.commit()
    conn.close()
    cleanup_old()
    generate_weekly_reports()
    return jsonify({"status":"updated","inserted":inserted})

# ================= DASHBOARD =================
@app.route("/")
def dashboard():
    conn=get_db()
    rows=[dict(r) for r in conn.execute("SELECT * FROM threats ORDER BY created DESC LIMIT 50").fetchall()]
    conn.close()
    score,level=calculate_risk(rows)

    # Trend chart last 30 days
    trend={}
    today=datetime.utcnow().date()
    for i in range(30):
        day=today-timedelta(days=i)
        trend[str(day)]=0
    for r in rows:
        try:
            d=datetime.fromisoformat(r["created"]).date()
            if str(d) in trend:
                trend[str(d)]+=1
        except:
            continue

    return render_template_string(DASHBOARD_TEMPLATE,rows=rows,score=score,level=level,trend=trend)

# ================= EXPORT =================
@app.route("/export/csv")
def export_csv():
    conn=get_db()
    rows=conn.execute("SELECT * FROM threats ORDER BY created DESC").fetchall()
    conn.close()
    path=os.path.join(REPORTS_DIR,"export.csv")
    write_csv(rows,path)
    return send_file(path,as_attachment=True)

@app.route("/export/json")
def export_json():
    conn=get_db()
    rows=[dict(r) for r in conn.execute("SELECT * FROM threats ORDER BY created DESC").fetchall()]
    conn.close()
    path=os.path.join(REPORTS_DIR,"export.json")
    write_json(rows,path)
    return send_file(path,as_attachment=True)

@app.route("/export/pdf")
def export_pdf():
    conn=get_db()
    rows=[dict(r) for r in conn.execute("SELECT * FROM threats ORDER BY created DESC").fetchall()]
    conn.close()
    path=os.path.join(REPORTS_DIR,"export.pdf")
    write_pdf(rows,path)
    return send_file(path,as_attachment=True)

# ================= WRITE FUNCTIONS =================
def write_csv(rows,path):
    output=io.StringIO()
    writer=csv.writer(output)
    if rows:
        writer.writerow(rows[0].keys())
        for r in rows:
            writer.writerow(r)
    with open(path,"w") as f:
        f.write(output.getvalue())

def write_json(rows,path):
    with open(path,"w") as f:
        json.dump([dict(r) for r in rows],f,indent=2)

# ================= PDF WITH PAGE NUMBERS =================
class PageNumCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_number(num_pages)
            super().showPage()
        super().save()

    def draw_page_number(self, page_count):
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.grey)
        self.drawRightString(800, 15, f"Page {self._pageNumber} of {page_count}")

def write_pdf(rows,path):
    score,level=calculate_risk(rows)
    buffer=io.BytesIO()
    doc=SimpleDocTemplate(buffer,pagesize=landscape(A4),
                          leftMargin=40,rightMargin=40,topMargin=40,bottomMargin=40)
    elements=[]
    styles=getSampleStyleSheet()
    wrap_style=ParagraphStyle("wrap",fontSize=8,leading=10)

    # Trend chart
    dates=[]
    counts=[]
    today=datetime.utcnow().date()
    for i in range(30):
        d=today-timedelta(days=i)
        dates.append(str(d))
        counts.append(sum(1 for r in rows if r["created"].startswith(str(d))))
    plt.figure(figsize=(8,2))
    plt.plot(dates[::-1],counts[::-1],marker='o',color='orange')
    plt.xticks(rotation=45)
    plt.tight_layout()
    img_path=os.path.join(REPORTS_DIR,"trend.png")
    plt.savefig(img_path)
    plt.close()
    trend_img = Image(img_path, width=400, height=100)

    elements.append(Paragraph("<b>REDSHARK.MY Weekly Threat Intelligence Report</b>",styles["Title"]))
    elements.append(Spacer(1,10))
    elements.append(Paragraph(f"Risk Index: {score} ({level})",styles["Normal"]))
    elements.append(Spacer(1,10))
    elements.append(trend_img)
    elements.append(Spacer(1,10))

    page_size=50
    for i in range(0,len(rows),page_size):
        chunk=rows[i:i+page_size]
        data=[["Actor","Indicator","Type","MITRE","Class","Date"]]
        for r in chunk:
            data.append([
                Paragraph(r["threat_actor"],wrap_style),
                Paragraph(r["indicator"],wrap_style),
                r["indicator_type"],
                r["mitre_tactic"],
                r["classification"],
                r["created"]
            ])
        table=Table(data,repeatRows=1)
        table.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,0),colors.darkblue),
            ("TEXTCOLOR",(0,0),(-1,0),colors.white),
            ("GRID",(0,0),(-1,-1),0.5,colors.grey)
        ]))
        elements.append(table)
        elements.append(Spacer(1,10))
        elements.append(Paragraph("Disclaimer: Developed from public sources by darkgrid@redshark.my",styles["Normal"]))
        if i+page_size<len(rows):
            elements.append(PageBreak())

    doc.build(elements, canvasmaker=PageNumCanvas)
    with open(path,"wb") as f:
        f.write(buffer.getvalue())

# ================= WEEKLY REPORT GENERATOR =================
def generate_weekly_reports():
    conn=get_db()
    rows=[dict(r) for r in conn.execute("SELECT * FROM threats ORDER BY created DESC").fetchall()]
    conn.close()
    if not rows:
        return
    date_str=str(datetime.utcnow().date())
    write_csv(rows,os.path.join(REPORTS_DIR,f"weekly_{date_str}.csv"))
    write_json(rows,os.path.join(REPORTS_DIR,f"weekly_{date_str}.json"))
    write_pdf(rows,os.path.join(REPORTS_DIR,f"weekly_{date_str}.pdf"))

# ================= NOTES SYSTEM =================
@app.route("/notes/add",methods=["POST"])
def add_note():
    data=request.json
    conn=get_db()
    conn.execute("""
    INSERT INTO notes (threat_id,analyst,note,created)
    VALUES (?,?,?,?)
    """,(data["threat_id"],data["analyst"],data["note"],datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()
    return jsonify({"status":"note added"})

@app.route("/notes/<threat_id>")
def get_notes(threat_id):
    conn=get_db()
    rows=conn.execute("SELECT * FROM notes WHERE threat_id=? ORDER BY created DESC",(threat_id,)).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

# ================= DASHBOARD TEMPLATE =================
DASHBOARD_TEMPLATE="""
<!DOCTYPE html>
<html>
<head>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<link rel="stylesheet" href="https://unpkg.com/leaflet/dist/leaflet.css"/>
<script src="https://unpkg.com/leaflet/dist/leaflet.js"></script>
<style>
body{background:#0b0f1a;color:#e0e0e0;font-family:Arial;}
h1{color:orange;}
table{width:100%;border-collapse:collapse;margin-top:10px;}
th{background:#001f4d;color:white;cursor:pointer;}
td,th{padding:6px;border:1px solid #333;}
tr:nth-child(even){background:#001a33;}
#map{height:400px;margin-bottom:20px;}
a{color:orange;margin-right:10px;}
</style>
</head>
<body>
<h1>REDSHARK.MY CTI Dashboard</h1>
<h2>Risk Index: {{score}} ({{level}})</h2>

<a href="/export/pdf">Download PDF</a>
<a href="/export/csv">CSV</a>
<a href="/export/json">JSON</a>

<canvas id="trendChart" width="600" height="150"></canvas>
<div id="map"></div>
<script>
var trend={{trend|tojson}};
var labels=Object.keys(trend).sort();
var data=labels.map(l=>trend[l]);
var ctx=document.getElementById('trendChart').getContext('2d');
new Chart(ctx,{type:'line',data:{labels:labels,datasets:[{label:'Threats per day',data:data,borderColor:'orange',fill:false}]},options:{responsive:true}});
var map=L.map('map').setView([4.2105,101.9758],6);
L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png').addTo(map);
var threats={{rows|tojson}};
threats.forEach(function(t){
 if(t.latitude && t.longitude){
   L.marker([t.latitude,t.longitude]).addTo(map)
   .bindPopup(t.indicator + "<br>" + t.mitre_tactic);
 }
});
</script>

<table>
<tr><th>Actor</th><th>Indicator</th><th>Type</th><th>MITRE</th><th>Class</th><th>Date</th></tr>
{% for r in rows %}
<tr>
<td>{{r.threat_actor}}</td>
<td>{{r.indicator}}</td>
<td>{{r.indicator_type}}</td>
<td>{{r.mitre_tactic}}</td>
<td>{{r.classification}}</td>
<td>{{r.created}}</td>
</tr>
{% endfor %}
</table>

<p>Total Showing: {{rows|length}}</p>
<p style="font-size:0.8em;color:#aaa;">Disclaimer: Developed from public sources by darkgrid@redshark.my</p>
</body>
</html>
"""

# ================= WEEKLY SCHEDULER (Precise) =================
def weekly_scheduler_precise():
    import time
    import datetime
    while True:
        now = datetime.datetime.utcnow()
        days_ahead = 6 - now.weekday()
        if days_ahead < 0:
            days_ahead += 7
        next_run = datetime.datetime.combine(
            now.date() + datetime.timedelta(days=days_ahead),
            datetime.time(hour=0, minute=0, second=0)
        )
        delta = (next_run - now).total_seconds()
        if delta <= 0:
            next_run += datetime.timedelta(days=7)
            delta = (next_run - now).total_seconds()
        print(f"[Scheduler] Next weekly report in {delta/3600:.2f} hours")
        time.sleep(delta)
        print("[Scheduler] Generating weekly reports...")
        generate_weekly_reports()

threading.Thread(target=weekly_scheduler_precise, daemon=True).start()

# ================= START =================
if __name__=="__main__":
    port=int(os.environ.get("PORT",10000))
    app.run(host="0.0.0.0",port=port)
