import os
import sqlite3
import requests
import io
import csv
import json
from datetime import datetime, timedelta
from flask import Flask, jsonify, request, render_template_string, send_file
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.pagesizes import landscape, A4
from reportlab.pdfgen import canvas
import matplotlib.pyplot as plt
import folium
from folium.plugins import MarkerCluster
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
        indicator TEXT,
        indicator_type TEXT,
        latitude REAL,
        longitude REAL,
        mitre_tactic TEXT,
        classification TEXT,
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

# ================= INGESTION =================
def ingest_otx():
    if not OTX_API_KEY:
        print("OTX_API_KEY missing")
        return 0
    headers={"X-OTX-API-KEY":OTX_API_KEY}
    try:
        r=requests.get("https://otx.alienvault.com/api/v1/pulses/subscribed",headers=headers,timeout=15)
        if r.status_code!=200:
            print("OTX fetch failed",r.status_code)
            return 0
        pulses=r.json().get("results",[])
    except Exception as e:
        print("OTX fetch error:",e)
        return 0

    conn=get_db()
    c=conn.cursor()
    inserted=0
    for pulse in pulses:
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
            VALUES (?,?,?,?,?,?,?,?,?)
            """,(
                threat_id,
                pulse.get("name"),
                indicator,
                ind_type,
                lat,lon,
                tactic,
                classification,
                created
            ))
            inserted+=1
    conn.commit()
    conn.close()
    cleanup_old()
    return inserted

# ================= DASHBOARD =================
@app.route("/")
def dashboard():
    page=int(request.args.get("page",1))
    sort_column=request.args.get("sort","created")
    sort_order=request.args.get("order","desc").lower()
    if sort_order not in ["asc","desc"]:
        sort_order="desc"
    allowed=["indicator","indicator_type","mitre_tactic","classification","created"]
    if sort_column not in allowed:
        sort_column="created"

    limit=50
    offset=(page-1)*limit

    conn=get_db()
    total_count=conn.execute("SELECT COUNT(*) as c FROM threats").fetchone()["c"]
    rows=[dict(r) for r in conn.execute(f"SELECT * FROM threats ORDER BY {sort_column} {sort_order} LIMIT {limit} OFFSET {offset}").fetchall()]

    # ================== Malaysia GeoIP heatmap with clustering ==================
    map_obj = folium.Map(location=[4.2105,101.9758], zoom_start=5)
    marker_cluster = MarkerCluster().add_to(map_obj)
    for r in rows:
        if r["latitude"] and r["longitude"]:
            folium.CircleMarker(
                location=[r["latitude"], r["longitude"]],
                radius=4,
                color="red" if r["classification"]=="TARGET_MY" else "blue",
                fill=True
            ).add_to(marker_cluster)
    map_html = map_obj._repr_html_()
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

    total_pages=(total_count+limit-1)//limit

    return render_template_string(DASHBOARD_TEMPLATE,rows=rows,score=score,level=level,trend=trend,
                                  page=page,total_pages=total_pages,sort_column=sort_column,sort_order=sort_order,
                                  map_html=map_html,total_count=total_count)

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
        data=[["Indicator","Type","MITRE","Class","Date"]]
        for idx,r in enumerate(chunk):
            data.append([
                Paragraph(r["indicator"],wrap_style),
                r["indicator_type"],
                r["mitre_tactic"],
                r["classification"],
                r["created"]
            ])
        table=Table(data,repeatRows=1)
        table.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,0),colors.crimson),
            ("TEXTCOLOR",(0,0),(-1,0),colors.white),
            ("GRID",(0,0),(-1,-1),0.5,colors.grey),
        ]))
        for row_idx in range(1,len(data)):
            if row_idx%2==0:
                table.setStyle(TableStyle([("BACKGROUND",(0,row_idx),(-1,row_idx),colors.lightgrey)]))
            else:
                table.setStyle(TableStyle([("BACKGROUND",(0,row_idx),(-1,row_idx),colors.white)]))
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

# ================= WEEKLY SCHEDULER =================
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

# ================= FIRST RUN INGESTION =================
print("[Startup] Performing initial data ingestion...")
inserted = ingest_otx()
print(f"[Startup] Inserted {inserted} indicators from OTX.")

# ================= DASHBOARD TEMPLATE =================
DASHBOARD_TEMPLATE = """
<html>
<head>
<title>REDSHARK.MY Threat Dashboard</title>
<style>
body{font-family:Arial,sans-serif;background-color:#111;color:#eee;}
table{border-collapse:collapse;width:100%;margin-top:20px;}
th,td{border:1px solid #555;padding:8px;text-align:left;}
th{background-color:#001F3F;cursor:pointer;color:white;}
tr:nth-child(even){background-color:#1a1a1a;}
.header{display:flex;align-items:center;gap:15px;}
.headline h3{color:#ff4d4d;margin-top:5px;margin-bottom:15px;font-weight:bold;}
.buttons{margin-bottom:20px;}
.buttons a{background-color:#001F3F;color:#eee;padding:8px 12px;text-decoration:none;margin-right:10px;border-radius:4px;}
.buttons a:hover{background-color:#003366;}
</style>
<script>
function sortTable(column){
    const url = new URL(window.location.href);
    let currentOrder = url.searchParams.get("order");
    currentOrder = currentOrder === "asc" ? "desc" : "asc";
    url.searchParams.set("sort", column);
    url.searchParams.set("order", currentOrder);
    window.location.href=url.href;
}
function changePage(page){
    const url=new URL(window.location.href);
    url.searchParams.set("page",page);
    window.location.href=url.href;
}
</script>
</head>
<body>
<h1>REDSHARK.MY Threat Dashboard</h1>
<div class="buttons">
<a href="/export/json" target="_blank">Download JSON</a>
<a href="/export/csv" target="_blank">Download CSV</a>
<a href="/export/pdf" target="_blank">Download PDF</a>
</div>
<div style="width:100%;height:400px;">{{ map_html|safe }}</div>
<h3>Trend Last 30 Days</h3>
<canvas id="trend" width="800" height="200"></canvas>
<table>
<tr>
<th onclick="sortTable('indicator')">Indicator</th>
<th onclick="sortTable('indicator_type')">Type</th>
<th onclick="sortTable('mitre_tactic')">MITRE</th>
<th onclick="sortTable('classification')">Classification</th>
<th onclick="sortTable('created')">Created</th>
</tr>
{% for row in rows %}
<tr style="background-color:{% if loop.index0 %2 ==0 %}#222{% else %}#1a1a1a{% endif %}">
<td>{{ row['indicator'] }}</td>
<td>{{ row['indicator_type'] }}</td>
<td>{{ row['mitre_tactic'] }}</td>
<td>{{ row['classification'] }}</td>
<td>{{ row['created'] }}</td>
</tr>
{% endfor %}
</table>
<p>Showing {{ rows|length }} of {{ total_count }} indicators</p>
<div>
{% if page>1 %}
<button onclick="changePage({{ page-1 }})">Previous</button>
{% endif %}
Page {{ page }} of {{ total_pages }}
{% if page<total_pages %}
<button onclick="changePage({{ page+1 }})">Next</button>
{% endif %}
</div>
<p style="margin-top:20px;font-size:0.8em;color:#999;">Disclaimer: Developed from public sources by darkgrid@redshark.my</p>
<script>
const ctx = document.getElementById('trend').getContext('2d');
const data = {{ trend|tojson }};
new Chart(ctx,{type:'line',data:{labels:Object.keys(data),datasets:[{label:'Indicators',data:Object.values(data),borderColor:'crimson',fill:false}]},options:{scales:{x:{ticks:{maxRotation:90,minRotation:45}}}}});
</script>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</body>
</html>
"""

# ================= START =================
if __name__=="__main__":
    port=int(os.environ.get("PORT",10000))
    app.run(host="0.0.0.0",port=port)
