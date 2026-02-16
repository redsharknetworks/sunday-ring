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

    # Malaysia GeoIP heatmap
    map_obj = folium.Map(location=[4.2105,101.9758], zoom_start=5)
    marker_cluster = MarkerCluster().add_to(map_obj)
    for r in rows:
        if r["latitude"] and r["longitude"]:
            folium.CircleMarker(
                location=[r["latitude"], r["longitude"]],
                radius=4,
                color="crimson" if r["classification"]=="TARGET_MY" else "darkblue",
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

# ================= DASHBOARD TEMPLATE =================
DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>REDSHARK.MY Threat Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #111; color: #eee; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th, td { border: 1px solid #555; padding: 8px; text-align: left; }
        th { background-color: darkblue; cursor: pointer; color:#fff; }
        tr:nth-child(even) { background-color: #ccc; color:#000; }
        tr:nth-child(odd) { background-color: #fff; color:#000; }
        .header { display: flex; align-items: center; gap: 15px; }
        .headline h3 { color: crimson; margin-top: 5px; margin-bottom: 15px; font-weight: bold; }
        .email { margin-bottom: 12px; font-size: 0.9em; color: #aaa; }
        .buttons { margin-bottom: 20px; }
        .buttons a { background-color: #222; color: #eee; padding: 8px 12px; text-decoration: none; margin-right: 10px; border-radius: 4px; }
        .buttons a:hover { background-color: #333; }
        .trend-chart { margin-top: 20px; background-color: #1a1a1a; padding: 15px; border-radius: 8px; }
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script>
        function sortTable(column) {
            const url = new URL(window.location.href);
            let currentOrder = url.searchParams.get("order");
            currentOrder = currentOrder === "asc" ? "desc" : "asc";
            url.searchParams.set("sort", column);
            url.searchParams.set("order", currentOrder);
            window.location.href = url.href;
        }
    </script>
</head>
<body>
    <div class="header">
        <h1>REDSHARK.MY Threat Dashboard</h1>
    </div>
    <div class="headline">
        <h3>Real-Time Threat Intelligence</h3>
    </div>
    <div class="email">Contact: darkgrid@redshark.my</div>
    <div class="buttons">
        <a href="/export/json" target="_blank">Download JSON</a>
        <a href="/export/csv" target="_blank">Download CSV</a>
        <a href="/export/pdf" target="_blank">Download PDF</a>
    </div>

    <div class="trend-chart">
        <canvas id="trendChart"></canvas>
    </div>
    <script>
        const trendLabels = {{ trend.keys() | list | tojson }};
        const trendData = {{ trend.values() | list | tojson }};
        const ctx = document.getElementById('trendChart').getContext('2d');
        new Chart(ctx, {
            type: 'line',
            data: {
                labels: trendLabels,
                datasets: [{
                    label: 'Indicators Last 30 Days',
                    data: trendData,
                    borderColor: 'orange',
                    backgroundColor: 'rgba(255,165,0,0.2)',
                    tension: 0.3
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: { display: true, labels: { color: '#fff' } }
                },
                scales: {
                    x: { ticks: { color: '#eee' }, grid: { color: '#333' } },
                    y: { ticks: { color: '#eee' }, grid: { color: '#333' } }
                }
            }
        });
    </script>

    <table>
        <tr>
            <th onclick="sortTable('indicator')">Indicator</th>
            <th onclick="sortTable('indicator_type')">Type</th>
            <th onclick="sortTable('mitre_tactic')">MITRE</th>
            <th onclick="sortTable('classification')">Class</th>
            <th onclick="sortTable('created')">Created</th>
        </tr>
        {% for row in rows %}
        <tr>
            <td>{{ row['indicator'] }}</td>
            <td>{{ row['indicator_type'] }}</td>
            <td>{{ row['mitre_tactic'] }}</td>
            <td>{{ row['classification'] }}</td>
            <td>{{ row['created'] }}</td>
        </tr>
        {% endfor %}
    </table>
    <p>Total Showing: {{ rows|length }} / {{ total_count }}</p>

    <div style="margin-top:20px;">
        {% if page > 1 %}
        <a href="?page={{ page-1 }}&sort={{ sort_column }}&order={{ sort_order }}">Previous</a>
        {% endif %}
        Page {{ page }} / {{ total_pages }}
        {% if page < total_pages %}
        <a href="?page={{ page+1 }}&sort={{ sort_column }}&order={{ sort_order }}">Next</a>
        {% endif %}
    </div>

    <div style="margin-top:20px;">
        {{ map_html | safe }}
    </div>

    <p style="margin-top:15px; font-size:0.8em; color:#aaa;">Disclaimer: Developed from public sources by darkgrid@redshark.my</p>
</body>
</html>
"""

# ================= EXPORT =================
@app.route("/export/csv")
def export_csv():
    conn=get_db()
    rows=conn.execute("SELECT * FROM threats ORDER BY created DESC").fetchall()
    conn.close()
    path=os.path.join(REPORTS_DIR,"export.csv")
    with open(path,"w",newline='') as f:
        writer=csv.writer(f)
        if rows:
            writer.writerow(rows[0].keys())
            for r in rows: writer.writerow(r)
    return send_file(path,as_attachment=True)

@app.route("/export/json")
def export_json():
    conn=get_db()
    rows=[dict(r) for r in conn.execute("SELECT * FROM threats ORDER BY created DESC").fetchall()]
    conn.close()
    path=os.path.join(REPORTS_DIR,"export.json")
    with open(path,"w") as f:
        json.dump(rows,f,indent=2)
    return send_file(path,as_attachment=True)

@app.route("/export/pdf")
def export_pdf():
    path=os.path.join(REPORTS_DIR,"export.pdf")
    generate_pdf(path)
    return send_file(path,as_attachment=True)

# ================= PDF GENERATOR =================
def generate_pdf(filepath):
    conn=get_db()
    rows=[dict(r) for r in conn.execute("SELECT * FROM threats ORDER BY created DESC").fetchall()]
    conn.close()
    doc=SimpleDocTemplate(filepath,pagesize=landscape(A4),
                          leftMargin=20,rightMargin=20,topMargin=20,bottomMargin=20)
    elements=[]
    styles=getSampleStyleSheet()
    header_style=ParagraphStyle("header",parent=styles["Heading1"],alignment=1,textColor=colors.crimson)
    elements.append(Paragraph("REDSHARK.MY Weekly Threat Report",header_style))
    elements.append(Spacer(1,12))

    # Trend chart
    dates=[str(datetime.utcnow().date()-timedelta(days=i)) for i in range(30)]
    counts=[len([r for r in rows if r["created"].startswith(d)]) for d in dates]
    plt.figure(figsize=(10,2))
    plt.plot(dates[::-1],counts[::-1],color="orange",linewidth=2)
    plt.xticks(rotation=45,fontsize=6)
    plt.tight_layout()
    chart_path=os.path.join(REPORTS_DIR,"trend.png")
    plt.savefig(chart_path)
    plt.close()
    elements.append(Image(chart_path,width=500,height=100))
    elements.append(Spacer(1,12))

    # Table with alternating row colors
    chunk_size=50
    for i in range(0,len(rows),chunk_size):
        data=[["Indicator","Type","MITRE","Class","Created"]]
        for idx,r in enumerate(rows[i:i+chunk_size]):
            data.append([r["indicator"],r["indicator_type"],r["mitre_tactic"],r["classification"],r["created"]])
        table=Table(data,repeatRows=1)
        tbl_style=TableStyle([
            ('BACKGROUND',(0,0),(-1,0),colors.darkblue),
            ('TEXTCOLOR',(0,0),(-1,0),colors.whitesmoke),
            ('ALIGN',(0,0),(-1,-1),'LEFT'),
            ('GRID',(0,0),(-1,-1),0.5,colors.grey)
        ])
        for row_num in range(1,len(data)):
            bg=colors.whitesmoke if row_num%2==1 else colors.lightgrey
            tbl_style.add('BACKGROUND',(0,row_num),(-1,row_num),bg)
        table.setStyle(tbl_style)
        elements.append(table)
        elements.append(PageBreak())

    elements.append(Paragraph("Disclaimer: Developed from public sources by darkgrid@redshark.my",styles["Normal"]))

    def add_page_number(canvas_obj, doc_obj):
        canvas_obj.setFont("Helvetica",8)
        page_num_text=f"Page {canvas_obj.getPageNumber()}"
        canvas_obj.drawRightString(landscape(A4)[0]-20,10,page_num_text)

    doc.build(elements, onFirstPage=add_page_number, onLaterPages=add_page_number)

# ================= WEEKLY REPORT SCHEDULER =================
def weekly_report_scheduler():
    while True:
        now=datetime.utcnow()
        next_run=(now + timedelta(days=7-now.weekday())).replace(hour=0,minute=5,second=0)
        wait=(next_run-now).total_seconds()
        print(f"[Scheduler] Next weekly report in {wait/3600:.2f} hours")
        threading.Event().wait(wait)
        print("[Scheduler] Generating weekly report...")
        ingest_otx()
        generate_pdf(os.path.join(REPORTS_DIR,f"weekly_{datetime.utcnow().date()}.pdf"))
        export_csv()
        export_json()

# ================= STARTUP =================
if __name__=="__main__":
    print("[Startup] Performing initial ingestion...")
    inserted=ingest_otx()
    print(f"[Startup] Inserted {inserted} indicators from OTX.")
    threading.Thread(target=weekly_report_scheduler,daemon=True).start()
    port=int(os.environ.get("PORT",10000))
    app.run(host="0.0.0.0",port=port)
