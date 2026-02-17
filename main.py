import os
import sqlite3
import random
from datetime import datetime, timedelta
from flask import Flask, jsonify, request, render_template_string, send_file
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import io
import csv
import base64
import folium
from folium.plugins import HeatMap
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import A4, landscape
import requests

app = Flask(__name__)

DB = "/tmp/threats.db"
PAGE_SIZE = 50
BOXING_RING = "/mnt/data/A_digital_photograph_captures_an_empty_boxing_ring.png"

# -------------------------------------------------
# DATABASE INITIALIZATION
# -------------------------------------------------
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
    )
    """)
    c.execute("""
    CREATE TABLE IF NOT EXISTS threat_hashes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pulse TEXT,
        hash TEXT,
        classification TEXT,
        mitre TEXT,
        risk_score INTEGER,
        created_at TEXT
    )
    """)
    conn.commit()
    conn.close()

# -------------------------------------------------
# RISK ENGINE
# -------------------------------------------------
def calculate_risk(classification, mitre):
    base = {"Low":30,"Medium":60,"High":80}.get(classification,50)
    mitre_weight = 15 if "T1566" in mitre else 10
    recency = random.randint(5,15)
    return min(base + mitre_weight + recency, 100)

def risk_level(score):
    if score >= 90:
        return "Critical"
    elif score >= 70:
        return "High"
    elif score >= 40:
        return "Medium"
    return "Low"

# -------------------------------------------------
# OTX FETCH
# -------------------------------------------------
OTX_API_KEY = os.getenv("OTX_API_KEY")
OTX_URL = "https://otx.alienvault.com/api/v1/indicators/export"

def fetch_otx():
    """Fetch top 50 indicators from OTX and store in DB"""
    headers = {"X-OTX-API-KEY": OTX_API_KEY} if OTX_API_KEY else {}
    types = ["IPv4","domain","url","file:md5"]
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    for t in types:
        params = {"type": t, "limit": 50}
        try:
            resp = requests.get(OTX_URL, params=params, headers=headers, timeout=15)
            data = resp.json().get("results",[])
        except Exception:
            data = []

        for d in data:
            pulse = d.get("pulse_info","OTX")
            created = d.get("created","")
            if t=="file:md5":
                c.execute("INSERT INTO threat_hashes (pulse,hash,classification,mitre,risk_score,created_at) VALUES (?,?,?,?,?,?)",
                          (pulse,d.get("indicator",""),d.get("threat_level","Medium"),d.get("tags",""),calculate_risk("Medium",""),created))
            else:
                c.execute("INSERT INTO threats (pulse,indicator,type,classification,mitre,risk_score,created_at) VALUES (?,?,?,?,?,?,?)",
                          (pulse,d.get("indicator",""),t,d.get("threat_level","Medium"),d.get("tags",""),calculate_risk("Medium",""),created))
    conn.commit()
    conn.close()

# -------------------------------------------------
# TREND CHART
# -------------------------------------------------
def generate_trend():
    conn = sqlite3.connect(DB)
    data = conn.execute("""
        SELECT substr(created_at,1,10), COUNT(*) 
        FROM threats GROUP BY substr(created_at,1,10)
    """).fetchall()
    conn.close()
    dates = [d[0] for d in data]
    counts = [d[1] for d in data]
    plt.figure(figsize=(10,5))
    plt.plot(dates, counts, color="crimson", marker="o")
    plt.fill_between(dates, counts, color="grey", alpha=0.2)
    plt.xticks(rotation=45)
    plt.grid(True, linestyle="--", alpha=0.3)
    plt.tight_layout()
    # Add boxing ring image as background
    if os.path.exists(BOXING_RING):
        img = plt.imread(BOXING_RING)
        plt.imshow(img, extent=[-1,len(dates),0,max(counts)*1.2], aspect='auto', alpha=0.2, zorder=-1)
    buf = io.BytesIO()
    plt.savefig(buf, format="png", facecolor="#2b2b2b")
    plt.close()
    buf.seek(0)
    return base64.b64encode(buf.read()).decode()

# -------------------------------------------------
# HEATMAP
# -------------------------------------------------
def generate_map():
    m = folium.Map(location=[4.21,101.97], zoom_start=6)
    heat = [[3.139,101.6869,5],[1.49,103.74,4],[5.41,100.33,3]]
    HeatMap(heat).add_to(m)
    return m._repr_html_()

# -------------------------------------------------
# DASHBOARD DATA
# -------------------------------------------------
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
    return f"REDSHARK identified {total} indicators, {high} High/Critical. Dominant technique: {mitre_text}. SecureNation Index: {risk_index()}."

# -------------------------------------------------
# DASHBOARD ROUTE
# -------------------------------------------------
@app.route("/")
def dashboard():
    page = int(request.args.get("page",1))
    sort = request.args.get("sort","risk_score")
    offset = (page-1)*PAGE_SIZE
    conn = sqlite3.connect(DB)
    data = conn.execute(f"SELECT pulse,indicator,type,mitre,risk_score,created_at FROM threats ORDER BY {sort} DESC LIMIT ? OFFSET ?",
                        (PAGE_SIZE,offset)).fetchall()
    total = conn.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
    conn.close()
    return render_template_string(TEMPLATE, data=data, total=total, trend=generate_trend(), map_html=generate_map(), summary=executive_summary(), risk_index=risk_index())

# -------------------------------------------------
# REPORTS
# -------------------------------------------------
def top10_weekly(t_type):
    """Return top 10 indicators of the week by type"""
    week_ago = (datetime.utcnow()-timedelta(days=7)).isoformat()
    conn = sqlite3.connect(DB)
    if t_type=="hash":
        rows = conn.execute("SELECT hash, COUNT(*) FROM threat_hashes WHERE created_at>? GROUP BY hash ORDER BY COUNT(*) DESC LIMIT 10",(week_ago,)).fetchall()
    else:
        rows = conn.execute("SELECT indicator, COUNT(*) FROM threats WHERE type=? AND created_at>? GROUP BY indicator ORDER BY COUNT(*) DESC LIMIT 10",(t_type,week_ago)).fetchall()
    conn.close()
    return rows

@app.route("/report/pdf")
def pdf_report():
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=landscape(A4))
    elements = []
    styles = getSampleStyleSheet()
    elements.append(Paragraph("REDSHARK DARKGRID REPORT", styles["Title"]))
    elements.append(Spacer(1,12))
    elements.append(Paragraph(executive_summary(), styles["Normal"]))
    elements.append(Spacer(1,12))
    # Top 10 weekly
    for t in ["IPv4","domain","url","hash"]:
        rows = top10_weekly(t)
        if rows:
            elements.append(Paragraph(f"Top 10 weekly {t} threats", styles["Heading2"]))
            data = [[t,"Count"]]+[list(r) for r in rows]
            table = Table(data, repeatRows=1)
            table.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.black),
                                       ("TEXTCOLOR",(0,0),(-1,0),colors.white),
                                       ("GRID",(0,0),(-1,-1),0.5,colors.grey)]))
            elements.append(table)
            elements.append(Spacer(1,12))
    elements.append(Paragraph("Disclaimer: Developed and analyzed from public sources by DarkGrid (darkgrid@redshark.my).", styles["Normal"]))
    doc.build(elements)
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name="darkgridatredsharkdotmy.pdf", mimetype="application/pdf")

@app.route("/report/csv")
def csv_report():
    conn = sqlite3.connect(DB)
    rows = conn.execute("SELECT pulse,indicator,type,classification,mitre,risk_score,created_at FROM threats").fetchall()
    conn.close()
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(["Pulse","Indicator","Type","Classification","MITRE","Risk","Created"])
    cw.writerows(rows)
    output = io.BytesIO()
    output.write(si.getvalue().encode())
    output.seek(0)
    return send_file(output, as_attachment=True, download_name="darkgridatredsharkdotmy.csv", mimetype="text/csv")

@app.route("/report/json")
def json_report():
    conn = sqlite3.connect(DB)
    rows = conn.execute("SELECT pulse,indicator,type,classification,mitre,risk_score,created_at FROM threats").fetchall()
    conn.close()
    return jsonify(rows)

# -------------------------------------------------
# DASHBOARD TEMPLATE
# -------------------------------------------------
TEMPLATE = """
<html>
<head>
<style>
body { background:#0a1f44; color:white; font-family:Arial; text-align:center; }
h1 { color:crimson; }
th { background:#001f3f; padding:8px; cursor:pointer; }
td { padding:6px; }
tr:nth-child(even) { background:#2a3d6a; }
tr:nth-child(odd) { background:#1a2d5a; }
a { color:orange; }
</style>
<script>
function sortTable(n){
  var table=document.querySelector("table");
  var rows=Array.from(table.rows).slice(1);
  var asc=table.asc=!table.asc;
  rows.sort((a,b)=>{
    var x=a.cells[n].innerText,y=b.cells[n].innerText;
    return asc?x.localeCompare(y):y.localeCompare(x);
  });
  rows.forEach(r=>table.appendChild(r));
}
</script>
</head>
<body>
<h1>REDSHARK CYBER THREAT INTELLIGENCE DASHBOARD</h1>
<h3>SecureNation Index: {{ risk_index }}</h3>
<div>{{ map_html|safe }}</div>
<p>{{ summary }}</p>
<img src="data:image/png;base64,{{ trend }}">
<h3>Total Indicators: {{ total }}</h3>
<table width="100%">
<tr>
<th onclick="sortTable(0)">Pulse</th>
<th onclick="sortTable(1)">Indicator</th>
<th onclick="sortTable(2)">Type</th>
<th onclick="sortTable(3)">MITRE</th>
<th onclick="sortTable(4)">Risk Score</th>
<th onclick="sortTable(5)">Created</th>
</tr>
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
<br>
<a href="/report/pdf">PDF</a> |
<a href="/report/csv">CSV</a> |
<a href="/report/json">JSON</a>
<p style="font-size:0.8em;">Disclaimer: Developed and analyzed from public sources by DarkGrid (darkgrid@redshark.my)</p>
</body>
</html>
"""

# -------------------------------------------------
# MANUAL STARTUP (Flask 3.x compatible)
# -------------------------------------------------
init_db()
fetch_otx()

# -------------------------------------------------
# RUN APP (for local testing)
# -------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
