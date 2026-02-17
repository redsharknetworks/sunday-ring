import os
import sqlite3
from datetime import datetime, timedelta
import requests
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import io
import base64
import csv
from flask import Flask, jsonify, request, render_template_string, send_file
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
import pytz

app = Flask(__name__)

DB = "/tmp/threats.db"
BOXING_RING = "./boxing_ring.png"
OTX_API_KEY = os.environ.get("OTX_API_KEY")
PAGE_SIZE = 50

# --------------------------
# DATABASE INIT
# --------------------------
def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS threats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pulse TEXT,
        indicator TEXT,
        type TEXT,
        classification TEXT,
        mitre TEXT,
        risk_score INTEGER,
        created_at TEXT
    )""")
    c.execute("""
    CREATE TABLE IF NOT EXISTS threat_hashes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pulse TEXT,
        hash TEXT,
        classification TEXT,
        mitre TEXT,
        risk_score INTEGER,
        created_at TEXT
    )""")
    conn.commit()
    conn.close()

init_db()

# --------------------------
# OTX FETCH
# --------------------------
def fetch_otx():
    if not OTX_API_KEY:
        return
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    url = "https://otx.alienvault.com/api/v1/indicators/export"
    params = {"limit":100}
    try:
        r = requests.get(url, headers=headers, params=params, timeout=10)
        data = r.json().get("results", [])
    except:
        data = []

    conn = sqlite3.connect(DB)
    c = conn.cursor()
    for item in data:
        indicator_type = item.get("type")
        indicator = item.get("indicator")
        pulse = item.get("pulse_name","OTX")
        mitre = item.get("mitre","")
        classification = item.get("classification","Medium")
        risk_score = item.get("risk_score",50)
        created_at = item.get("created_at",datetime.utcnow().isoformat())

        if indicator_type == "hash":
            c.execute("""
                INSERT OR IGNORE INTO threat_hashes (pulse,hash,classification,mitre,risk_score,created_at)
                VALUES (?,?,?,?,?,?)
            """,(pulse,indicator,classification,mitre,risk_score,created_at))
        else:
            c.execute("""
                INSERT OR IGNORE INTO threats (pulse,indicator,type,classification,mitre,risk_score,created_at)
                VALUES (?,?,?,?,?,?,?)
            """,(pulse,indicator,indicator_type,classification,mitre,risk_score,created_at))
    conn.commit()
    conn.close()

fetch_otx()

# --------------------------
# RISK ENGINE
# --------------------------
def risk_index():
    conn = sqlite3.connect(DB)
    scores = [x[0] for x in conn.execute("SELECT risk_score FROM threats").fetchall()]
    conn.close()
    return int(sum(scores)/len(scores)) if scores else 0

def executive_summary():
    conn = sqlite3.connect(DB)
    total = conn.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
    high = conn.execute("SELECT COUNT(*) FROM threats WHERE risk_score>=70").fetchone()[0]
    top_mitre = conn.execute("SELECT mitre,COUNT(*) FROM threats GROUP BY mitre ORDER BY COUNT(*) DESC LIMIT 1").fetchone()
    conn.close()
    mitre_text = top_mitre[0] if top_mitre else "N/A"
    return f"REDSHARK identified {total} indicators. {high} rated High/Critical. Dominant technique: {mitre_text}. SecureNation Index: {risk_index()}"

# --------------------------
# TREND CHART
# --------------------------
def generate_trend(pdf=False):
    conn = sqlite3.connect(DB)
    data = conn.execute("""
        SELECT substr(created_at,1,10), COUNT(*) FROM threats GROUP BY substr(created_at,1,10)
    """).fetchall()
    conn.close()
    dates = [d[0] for d in data]
    counts = [d[1] for d in data]

    plt.figure(figsize=(10,4))
    if os.path.exists(BOXING_RING):
        img = plt.imread(BOXING_RING)
        plt.imshow(img, extent=[-1,len(dates),0,max(counts)*1.2], aspect='auto', alpha=0.2, zorder=-1)
    
    # Bold line, thicker for PDF
    line_width = 5 if pdf else 3
    plt.plot(dates, counts, color="#2a3d6a", linewidth=line_width, label="Total Indicators")
    plt.xticks(rotation=45)
    plt.grid(True, linestyle='--', alpha=0.5)
    plt.tight_layout()

    img_buf = io.BytesIO()
    plt.savefig(img_buf, format="png", facecolor="#2a3d6a")
    plt.close()
    img_buf.seek(0)
    return base64.b64encode(img_buf.read()).decode()

# --------------------------
# TYPE CHART → LINE CHART
# --------------------------
def generate_type_chart():
    conn = sqlite3.connect(DB)
    counts = conn.execute("SELECT type, COUNT(*) FROM threats GROUP BY type").fetchall()
    conn.close()
    labels = [c[0] for c in counts]
    values = [c[1] for c in counts]

    plt.figure(figsize=(8,4))
    colors = ["#7fbf7f","#ffb366","#80d4ff","#dc143c","#ffa07a","#8a2be2"]
    for i, v in enumerate(values):
        plt.plot([0,1], [v,v], color=colors[i % len(colors)], linewidth=2, label=labels[i])
    plt.xticks([])
    plt.ylabel("Count")
    plt.legend(loc="upper right", fontsize=8)
    plt.grid(True, linestyle='--', alpha=0.5)
    plt.tight_layout()

    buf = io.BytesIO()
    plt.savefig(buf, format="png", facecolor="#0a1f44")
    plt.close()
    buf.seek(0)
    return base64.b64encode(buf.read()).decode()

# --------------------------
# HEAT MAP
# --------------------------
def generate_heatmap():
    conn = sqlite3.connect(DB)
    data = conn.execute("""
        SELECT type, substr(created_at,1,10), COUNT(*) FROM threats GROUP BY type, substr(created_at,1,10)
    """).fetchall()
    conn.close()

    types = list(sorted(set([d[0] for d in data])))
    dates = list(sorted(set([d[1] for d in data])))

    heat_values = [[0]*len(dates) for _ in types]
    type_idx = {t:i for i,t in enumerate(types)}
    date_idx = {d:i for i,d in enumerate(dates)}

    for t,d,c in data:
        heat_values[type_idx[t]][date_idx[d]] = c

    plt.figure(figsize=(10,4))
    plt.imshow(heat_values, aspect='auto', cmap="YlOrRd")
    plt.yticks(range(len(types)), types)
    plt.xticks(range(len(dates)), dates, rotation=45)
    plt.colorbar(label="Indicator Count")
    plt.tight_layout()

    buf = io.BytesIO()
    plt.savefig(buf, format="png", facecolor="#0a1f44")
    plt.close()
    buf.seek(0)
    return base64.b64encode(buf.read()).decode()

# --------------------------
# DASHBOARD TEMPLATE
# --------------------------
TEMPLATE = """
<html>
<head>
<style>
body { background:#0a1f44; color:white; font-family:Arial; text-align:center; }
h1 { color:crimson; }
th { background:#001f3f; padding:8px; }
td { padding:6px; }
tr:nth-child(even) { background:#2a3d6a; }
tr:nth-child(odd) { background:#1a2d5a; }
a { color:orange; }
</style>
</head>
<body>
<h1>REDSHARK CYBER THREAT INTELLIGENCE DASHBOARD</h1>
<h4>{{ current_time }}</h4>
<h3>SecureNation Index: {{ risk_index }}</h3>
<p>{{ summary }}</p>

<img src="data:image/png;base64,{{ heatmap }}"><br><br>
<img src="data:image/png;base64,{{ trend }}"><br><br>
<img src="data:image/png;base64,{{ type_chart }}"><br><br>

<h3>Total Indicators: {{ total }}</h3>
<table width="90%" align="center">
<tr><th>Pulse</th><th>Indicator</th><th>Type</th><th>MITRE</th><th>Risk Score</th><th>Created</th></tr>
{% for row in data %}
<tr>
<td>{{ row[0] }}</td>
<td>{{ row[1] }}</td>
<td>{{ row[2] }}</td>
<td>{{ row[3] }}</td>
<td>{{ row[4] }}</td>
<td>{{ row[5] }}</td>
</tr>
{% endfor %}
</table>

<p style="margin-top:20px; font-size:0.8em;">Disclaimer: Information developed and analyzed from public sources by darkgrid@redshark.my</p>
<br>
<a href="/report/pdf">PDF</a> |
<a href="/report/csv">CSV</a> |
<a href="/report/json">JSON</a>
</body>
</html>
"""

@app.route("/")
def dashboard():
    page = int(request.args.get("page",1))
    sort = request.args.get("sort","risk_score")
    offset = (page-1)*PAGE_SIZE
    conn = sqlite3.connect(DB)
    rows = conn.execute(f"SELECT pulse,indicator,type,mitre,risk_score,created_at FROM threats ORDER BY {sort} DESC LIMIT ? OFFSET ?",(PAGE_SIZE,offset)).fetchall()
    total = conn.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
    conn.close()

    tz = pytz.timezone("Asia/Kuala_Lumpur")
    current_time = datetime.now(tz).strftime("%Y-%m-%d %H:%M:%S")

    return render_template_string(TEMPLATE, data=rows, total=total, trend=generate_trend(),
                                  type_chart=generate_type_chart(), risk_index=risk_index(),
                                  summary=executive_summary(), heatmap=generate_heatmap(),
                                  current_time=current_time)

# --------------------------
# REPORTS
# --------------------------
def report_filename(base):
    tz = pytz.timezone("Asia/Kuala_Lumpur")
    date_str = datetime.now(tz).strftime("%Y%m%d")
    return f"{base}-{date_str}"

@app.route("/report/pdf")
def pdf_report():
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=landscape(A4), rightMargin=20, leftMargin=20, topMargin=20, bottomMargin=40)
    styles = getSampleStyleSheet()
    elements = []

    tz = pytz.timezone("Asia/Kuala_Lumpur")
    current_time = datetime.now(tz).strftime("%Y-%m-%d %H:%M:%S")

    # Title & summary
    elements.append(Paragraph("REDSHARK DARKGRID REPORT", styles["Title"]))
    elements.append(Spacer(1,12))
    elements.append(Paragraph(f"Report generated on: {current_time}", styles["Normal"]))
    elements.append(Spacer(1,12))
    elements.append(Paragraph(executive_summary(), styles["Normal"]))
    elements.append(Spacer(1,20))

    def add_chart(chart_func, title):
        # Use thicker line for trend chart in PDF
        if title == "Trend Chart":
            img_data = base64.b64decode(chart_func(pdf=True))
        else:
            img_data = base64.b64decode(chart_func())
        img_buf = io.BytesIO(img_data)
        elements.append(Paragraph(title, styles["Heading2"]))
        elements.append(Paragraph(f"Snapshot: {current_time}", styles["Normal"]))
        page_width = landscape(A4)[0] - doc.leftMargin - doc.rightMargin
        elements.append(Image(img_buf, width=0.9*page_width, height=0.35*page_width))
        elements.append(Spacer(1,20))

    add_chart(generate_heatmap, "Heat Map of Threat Indicators")
    add_chart(generate_trend, "Trend Chart")
    add_chart(generate_type_chart, "Type Chart")

    # Top 10 weekly tables
    week_ago = datetime.now(tz) - timedelta(days=7)
    conn = sqlite3.connect(DB)
    for t in ["IPv4","domain","URL","hash"]:
        table = "threat_hashes" if t=="hash" else "threats"
        col = "hash" if t=="hash" else "indicator"
        res = conn.execute(f"SELECT {col},risk_score,COUNT(*) as c FROM {table} WHERE created_at>=? AND type!=? GROUP BY {col},risk_score ORDER BY c DESC LIMIT 10",(week_ago.isoformat(), "hash")).fetchall()
        elements.append(Paragraph(f"Top 10 {t} Weekly", styles["Heading2"]))
        elements.append(Paragraph(f"Snapshot: {current_time}", styles["Normal"]))
        header = [t.capitalize(),"Risk Score","Count"]
        data = [header]+[list(r) for r in res]
        table = Table(data, repeatRows=1)
        table.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.black),
                                   ("TEXTCOLOR",(0,0),(-1,0),colors.white),
                                   ("GRID",(0,0),(-1,-1),0.5,colors.grey),
                                   ("BACKGROUND",(0,1),(-1,-1),colors.whitesmoke)]))
        elements.append(table)
        elements.append(PageBreak())
    conn.close()

    # Disclaimer
    elements.append(Paragraph("Disclaimer: Information developed from public sources by darkgrid@redshark.my", styles["Normal"]))

    # Page numbers
    def add_page_number(canvas, doc):
        page_num = canvas.getPageNumber()
        text = f"Page {page_num}"
        canvas.setFont("Helvetica", 9)
        canvas.setFillColor(colors.white)
        canvas.drawRightString(landscape(A4)[0] - 20, 15, text)

    doc.build(elements, onFirstPage=add_page_number, onLaterPages=add_page_number)
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name=report_filename("sunday-ring-redshark")+".pdf", mimetype="application/pdf")

@app.route("/report/csv")
def csv_report():
    conn = sqlite3.connect(DB)
    rows = conn.execute("SELECT * FROM threats").fetchall()
    conn.close()
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(["ID","Pulse","Indicator","Type","Classification","MITRE","Risk","Created"])
    cw.writerows(rows)
    output = io.BytesIO()
    output.write(si.getvalue().encode())
    output.seek(0)
    return send_file(output, as_attachment=True, download_name="darkgrid-redshark.csv")

@app.route("/report/json")
def json_report():
    conn = sqlite3.connect(DB)
    rows = conn.execute("SELECT * FROM threats").fetchall()
    conn.close()
    return jsonify(rows)

# --------------------------
# RUN
# --------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
