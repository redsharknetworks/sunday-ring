import os
import sys
import sqlite3
import requests
import io
import csv
import json
from datetime import datetime, timedelta

from flask import Flask, jsonify, send_file, render_template_string, request
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image as RLImage
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.pagesizes import A4, landscape
import matplotlib.pyplot as plt

# -----------------------------
# Flask App
# -----------------------------
app = Flask(__name__)

# -----------------------------
# Config
# -----------------------------
OTX_API_KEY = os.environ.get("OTX_API_KEY")
if not OTX_API_KEY:
    raise RuntimeError("OTX_API_KEY environment variable is required!")

DB_FILE = os.environ.get("DB_FILE", "threat_intel.db")
ADMIN_KEY = os.environ.get("ADMIN_KEY", "changeme")

DASHBOARD_TITLE = "Malaysia Threat Intelligence Dashboard"
EXECUTIVE_HEADLINE = "Threat Campaigns Impacting Malaysian Digital Ecosystem"
DISCLAIMER = "Developed and analyzed by darkgrid@redshark.my from public sources."

# -----------------------------
# Database
# -----------------------------
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS indicators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator TEXT,
            type TEXT,
            pulse_name TEXT,
            classification TEXT,
            created TEXT,
            UNIQUE(indicator, pulse_name)
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS metadata (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)
    conn.commit()
    conn.close()

def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

init_db()

# -----------------------------
# Classification
# -----------------------------
def classify_pulse(pulse):
    indicators = pulse.get("indicators", [])
    targeted_countries = [c.lower() for c in pulse.get("targeted_countries", [])]
    has_target_my = any(
        ind.get("type")=="domain" and ind.get("indicator","").endswith(".my")
        for ind in indicators
    )
    has_targeted_my = "my" in targeted_countries
    if has_target_my and has_targeted_my:
        return "BOTH"
    elif has_target_my:
        return "TARGET_MY"
    elif has_targeted_my:
        return "SOURCE_MY"
    elif indicators:
        return "SOURCE_OTHER"
    else:
        return "UNCLASSIFIED"

# -----------------------------
# Fetch OTX
# -----------------------------
def fetch_otx(limit=200):
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    try:
        r = requests.get(
            "https://otx.alienvault.com/api/v1/pulses/subscribed",
            headers=headers,
            params={"limit": limit},
            timeout=15
        )
        r.raise_for_status()
        return r.json().get("results",[])
    except Exception as e:
        print("OTX Fetch Error:", e)
        return []

# -----------------------------
# Ingest Pulses
# -----------------------------
def ingest():
    pulses = fetch_otx()
    conn = get_db_connection()
    c = conn.cursor()
    for pulse in pulses:
        classification = classify_pulse(pulse)
        for ind in pulse.get("indicators", []):
            c.execute("""
                INSERT OR IGNORE INTO indicators
                (indicator,type,pulse_name,classification,created)
                VALUES (?,?,?,?,?)
            """,(ind.get("indicator"),ind.get("type"),pulse.get("name"),classification,pulse.get("created")))
    # Auto-clean 30 days
    c.execute("DELETE FROM indicators WHERE created < datetime('now','-30 days')")
    conn.commit()
    conn.close()
    print("Ingestion complete.")

# -----------------------------
# Smart 30-min Ingest
# -----------------------------
def smart_ingest():
    conn = get_db_connection()
    row = conn.execute("SELECT value FROM metadata WHERE key='last_ingest'").fetchone()
    now = int(datetime.utcnow().timestamp())
    last_ingest_time = int(row["value"]) if row else 0
    if now - last_ingest_time < 1800:
        conn.close()
        return last_ingest_time
    ingest()
    conn.execute("INSERT OR REPLACE INTO metadata(key,value) VALUES (?,?)", ("last_ingest", str(now)))
    conn.commit()
    conn.close()
    return now

# -----------------------------
# PDF Generator with Trend Chart
# -----------------------------
def generate_pdf(rows, title="Malaysia Threat Report"):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=landscape(A4),
        leftMargin=30,rightMargin=30,topMargin=20,bottomMargin=20
    )
    elements=[]
    styles=getSampleStyleSheet()
    elements.append(Paragraph(title,styles["Heading1"]))
    elements.append(Spacer(1,12))

    # --- Trend Chart
    date_counts = {}
    for i in range(7):
        day = (datetime.utcnow() - timedelta(days=6-i)).strftime("%Y-%m-%d")
        date_counts[day] = 0
    for r in rows:
        day = r["created"][:10]
        if day in date_counts:
            date_counts[day] += 1

    plt.figure(figsize=(6,2))
    plt.plot(list(date_counts.keys()), list(date_counts.values()), marker='o', color='orange')
    plt.title('Indicators Last 7 Days')
    plt.grid(True, linestyle='--', alpha=0.5)
    plt.tight_layout()
    chart_buffer = io.BytesIO()
    plt.savefig(chart_buffer, format='PNG', dpi=100, bbox_inches='tight')
    plt.close()
    chart_buffer.seek(0)
    img = RLImage(chart_buffer)
    img.drawHeight=1.5*72
    img.drawWidth=5.5*72
    elements.append(img)
    elements.append(Spacer(1,12))

    # --- Table ---
    table_data=[["Indicator","Type","Pulse","Classification","Created"]]
    cell_style=ParagraphStyle('cell',fontSize=9,leading=11,wordWrap='CJK')
    for r in rows:
        table_data.append([
            Paragraph(r["indicator"],cell_style),
            Paragraph(r["type"],cell_style),
            Paragraph(r["pulse_name"],cell_style),
            Paragraph(r["classification"],cell_style),
            Paragraph(r["created"],cell_style)
        ])
    col_ratios=[0.25,0.1,0.35,0.15,0.15]
    page_width,_=landscape(A4)
    usable_width=page_width-60
    col_widths=[usable_width*r for r in col_ratios]
    table=Table(table_data,colWidths=col_widths,repeatRows=1)
    table.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,0),colors.darkblue),
        ('TEXTCOLOR',(0,0),(-1,0),colors.white),
        ('GRID',(0,0),(-1,-1),0.5,colors.grey),
        ('LEFTPADDING',(0,0),(-1,-1),4),
        ('RIGHTPADDING',(0,0),(-1,-1),4),
        ('TOPPADDING',(0,0),(-1,-1),2),
        ('BOTTOMPADDING',(0,0),(-1,-1),2)
    ]))
    # Row coloring
    color_map={"TARGET_MY":colors.orange,"SOURCE_MY":colors.orange,"BOTH":colors.darkblue,"SOURCE_OTHER":colors.lightblue,"UNCLASSIFIED":colors.lightgrey}
    text_map={"BOTH":colors.whitesmoke}
    for i,row in enumerate(rows,start=1):
        cls=row["classification"]
        bg=color_map.get(cls,colors.lightgrey)
        table.setStyle(TableStyle([('BACKGROUND',(0,i),(-1,i),bg)]))
        if cls in text_map:
            table.setStyle(TableStyle([('TEXTCOLOR',(0,i),(-1,i),text_map[cls])]))
    elements.append(table)
    elements.append(Spacer(1,12))
    elements.append(Paragraph(DISCLAIMER,styles["Normal"]))
    doc.build(elements)
    buffer.seek(0)
    return buffer

# -----------------------------
# Dashboard
# -----------------------------
@app.route("/")
def dashboard():
    last_ingest_time = smart_ingest()
    page = int(request.args.get("page",1))
    per_page = 50

    conn = get_db_connection()
    total_indicators = conn.execute("SELECT COUNT(*) as total FROM indicators").fetchone()["total"]
    rows = conn.execute("SELECT * FROM indicators ORDER BY created DESC LIMIT ? OFFSET ?", (per_page, per_page*(page-1))).fetchall()

    # Trend chart last 7 days
    trend_data = []
    for i in range(7):
        day = (datetime.utcnow() - timedelta(days=6-i)).strftime("%Y-%m-%d")
        count = conn.execute("SELECT COUNT(*) as c FROM indicators WHERE date(created)=?",(day,)).fetchone()["c"]
        trend_data.append({"day":day,"count":count})
    conn.close()

    color_map={"TARGET_MY":"#ff9933","SOURCE_MY":"#ffa64d","BOTH":"#001f4d","SOURCE_OTHER":"#003366","UNCLASSIFIED":"#001a33"}
    total_pages=(total_indicators + per_page -1)//per_page
    last_updated=datetime.utcfromtimestamp(last_ingest_time).strftime("%Y-%m-%d %H:%M:%S UTC") if last_ingest_time else "Never"

    html="""
    <html>
    <head>
        <title>{{ dashboard_title }}</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            body{background:#111;color:#eee;font-family:Arial}
            table{border-collapse:collapse;width:100%;margin-top:10px}
            th,td{border:1px solid #555;padding:8px}
            th{background:#001f4d;cursor:pointer}
            tr:nth-child(even){background:#001a33}
            .buttons a{background:#001f4d;color:#eee;padding:6px 12px;text-decoration:none;margin-right:8px;border-radius:4px;}
            .buttons a:hover{background:#003366}
            .disclaimer{font-size:0.8em;color:#888;margin-top:15px}
            .pagination a{color:#eee;margin:0 5px;text-decoration:none}
        </style>
        <script>
        function sortTable(column){
            const url=new URL(window.location.href);
            let order=url.searchParams.get("order")||"desc";
            order=order==="asc"?"desc":"asc";
            url.searchParams.set("sort",column);
            url.searchParams.set("order",order);
            window.location.href=url.href;
        }
        </script>
    </head>
    <body>
        <h1>{{ dashboard_title }}</h1>
        <h3>{{ executive_headline }}</h3>
        <p>Total Showing: {{ total_indicators }}</p>
        <canvas id="trendChart" width="600" height="200"></canvas>
        <script>
            const ctx=document.getElementById('trendChart').getContext('2d');
            const chart=new Chart(ctx,{
                type:'line',
                data:{
                    labels:[{% for d in trend_data %}'{{d.day}}',{% endfor %}],
                    datasets:[{
                        label:'Indicators Last 7 Days',
                        data:[{% for d in trend_data %}{{d.count}},{% endfor %}],
                        backgroundColor:'rgba(255,153,51,0.2)',
                        borderColor:'rgba(255,153,51,1)',
                        borderWidth:2,
                        fill:true,
                        tension:0.3
                    }]
                },
                options:{scales:{y:{beginAtZero:true}}}
            });
        </script>
        <div class="buttons">
            <a href="/report/json" target="_blank">Download JSON</a>
            <a href="/report/csv" target="_blank">Download CSV</a>
            <a href="/report/pdf" target="_blank">Download PDF</a>
        </div>
        <table>
            <tr>
                <th onclick="sortTable('indicator')">Indicator</th>
                <th onclick="sortTable('type')">Type</th>
                <th onclick="sortTable('pulse_name')">Pulse Name</th>
                <th onclick="sortTable('classification')">Classification</th>
                <th onclick="sortTable('created')">Created</th>
            </tr>
            {% for row in rows %}
            <tr style="background-color: {{ color_map.get(row['classification'],'#001a33') }}">
                <td>{{ row['indicator'] }}</td>
                <td>{{ row['type'] }}</td>
                <td>{{ row['pulse_name'] }}</td>
                <td>{{ row['classification'] }}</td>
                <td>{{ row['created'] }}</td>
            </tr>
            {% endfor %}
        </table>
        <div class="pagination">
            {% for p in range(1,total_pages+1) %}
                {% if p==page %}
                    <strong>{{p}}</strong>
                {% else %}
                    <a href="/?page={{p}}">{{p}}</a>
                {% endif %}
            {% endfor %}
        </div>
        <div class="disclaimer">{{ disclaimer }}</div>
    </body>
    </html>
    """
    return render_template_string(html,
        rows=rows,
        dashboard_title=DASHBOARD_TITLE,
        executive_headline=EXECUTIVE_HEADLINE,
        total_indicators=total_indicators,
        color_map=color_map,
        page=page,
        total_pages=total_pages,
        trend_data=trend_data,
        disclaimer=DISCLAIMER
    )

# -----------------------------
# Reports Endpoints
# -----------------------------
@app.route("/report/pdf")
def report_pdf():
    conn = get_db_connection()
    rows = conn.execute("SELECT * FROM indicators ORDER BY created DESC LIMIT 100").fetchall()
    conn.close()
    buffer = generate_pdf(rows)
    return send_file(buffer, mimetype="application/pdf", as_attachment=True, download_name="malaysia_threat_report.pdf")

@app.route("/report/json")
def report_json():
    conn = get_db_connection()
    rows = conn.execute("SELECT * FROM indicators ORDER BY created DESC LIMIT 100").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/report/csv")
def report_csv():
    conn = get_db_connection()
    rows = conn.execute("SELECT * FROM indicators ORDER BY created DESC LIMIT 100").fetchall()
    conn.close()
    output=io.StringIO()
    writer=csv.writer(output)
    writer.writerow(["Indicator","Type","Pulse Name","Classification","Created"])
    for r in rows:
        writer.writerow([r["indicator"],r["type"],r["pulse_name"],r["classification"],r["created"]])
    output.seek(0)
    return send_file(io.BytesIO(output.getvalue().encode()), mimetype="text/csv", as_attachment=True, download_name="malaysia_threat_report.csv")

# -----------------------------
# Weekly Report Endpoint
# -----------------------------
@app.route("/report/weekly")
def report_weekly():
    key = request.args.get("key")
    if key != ADMIN_KEY:
        return jsonify({"error":"Unauthorized"}),403

    conn = get_db_connection()
    rows = conn.execute("""
        SELECT * FROM indicators
        WHERE created >= datetime('now','-7 days')
        ORDER BY created DESC
    """).fetchall()
    conn.close()

    os.makedirs("weekly_reports", exist_ok=True)

    # CSV
    csv_file="weekly_reports/malaysia_weekly_report.csv"
    with open(csv_file,"w",newline="",encoding="utf-8") as f:
        writer=csv.writer(f)
        writer.writerow(["Indicator","Type","Pulse Name","Classification","Created"])
        for r in rows:
            writer.writerow([r["indicator"],r["type"],r["pulse_name"],r["classification"],r["created"]])

    # JSON
    json_file="weekly_reports/malaysia_weekly_report.json"
    with open(json_file,"w",encoding="utf-8") as f:
        json.dump([dict(r) for r in rows],f,indent=2)

    # PDF
    pdf_file="weekly_reports/malaysia_weekly_report.pdf"
    buffer=generate_pdf(rows,title="Malaysian Cyber Threat Weekly Report")
    with open(pdf_file,"wb") as f:
        f.write(buffer.getbuffer())

    return jsonify({
        "status":"success",
        "csv":csv_file,
        "json":json_file,
        "pdf":pdf_file,
        "total_indicators":len(rows)
    })

# -----------------------------
# Update Endpoint
# -----------------------------
@app.route("/update")
def update_endpoint():
    key = request.args.get("key")
    if key != ADMIN_KEY:
        return jsonify({"error":"Unauthorized"}),403
    ingest()
    return jsonify({"status":"updated","message":"OTX pulses ingested successfully"})

# -----------------------------
# CLI & Run
# -----------------------------
if __name__=="__main__":
    init_db()
    if len(sys.argv)>1 and sys.argv[1] in ["ingest","--update"]:
        ingest()
        sys.exit(0)
    port=int(os.environ.get("PORT",5000))
    app.run(host="0.0.0.0",port=port)
