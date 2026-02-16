import os
import sqlite3
import random
from datetime import datetime, timedelta
from flask import Flask, jsonify, request, render_template_string, send_file, redirect
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import io
import csv
import base64
import folium
from folium.plugins import HeatMap
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import A4, landscape

app = Flask(__name__)
DB = "threats.db"

# -----------------------
# DATABASE INIT
# -----------------------
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
    CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT,
        severity TEXT,
        status TEXT,
        linked_indicator TEXT,
        created_at TEXT
    )
    """)

    conn.commit()
    conn.close()

# -----------------------
# RISK ENGINE
# -----------------------
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

# -----------------------
# DEMO DATA
# -----------------------
def seed_data():
    conn = sqlite3.connect(DB)
    c = conn.cursor()

    if c.execute("SELECT COUNT(*) FROM threats").fetchone()[0] > 0:
        conn.close()
        return

    for i in range(150):
        classification = random.choice(["Low","Medium","High"])
        mitre = random.choice(["T1566 Phishing","T1071 C2","T1059 Execution"])
        score = calculate_risk(classification, mitre)

        c.execute("""
        INSERT INTO threats (pulse,indicator,type,classification,mitre,risk_score,created_at)
        VALUES (?,?,?,?,?,?,?)
        """,(
            f"Campaign {i%6}",
            f"malicious{i}.com",
            random.choice(["domain","IPv4","URL"]),
            classification,
            mitre,
            score,
            datetime.utcnow().isoformat()
        ))

    conn.commit()
    conn.close()

# -----------------------
# RISK INDEX
# -----------------------
def national_risk_index():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    scores = [x[0] for x in c.execute("SELECT risk_score FROM threats").fetchall()]
    conn.close()
    if not scores:
        return 0
    return int(sum(scores)/len(scores))

# -----------------------
# EXEC SUMMARY
# -----------------------
def executive_summary():
    conn = sqlite3.connect(DB)
    c = conn.cursor()

    total = c.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
    high = c.execute("SELECT COUNT(*) FROM threats WHERE risk_score >=70").fetchone()[0]
    top_mitre = c.execute("""
        SELECT mitre, COUNT(*) as c FROM threats
        GROUP BY mitre ORDER BY c DESC LIMIT 1
    """).fetchone()

    conn.close()

    mitre_text = top_mitre[0] if top_mitre else "N/A"

    return f"""
    REDSHARK.MY identified {total} active indicators this week.
    {high} indicators were rated High or Critical risk.
    Dominant observed technique: {mitre_text}.
    Risk Index currently rated {risk_index()}.
    """

# -----------------------
# TREND CHART
# -----------------------
def generate_trend():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    data = c.execute("""
        SELECT substr(created_at,1,10), COUNT(*)
        FROM threats GROUP BY substr(created_at,1,10)
    """).fetchall()
    conn.close()

    dates = [d[0] for d in data]
    counts = [d[1] for d in data]

    plt.figure()
    plt.plot(dates, counts, color="orange")
    plt.xticks(rotation=45)
    plt.tight_layout()

    img = io.BytesIO()
    plt.savefig(img, format="png")
    plt.close()
    img.seek(0)
    return base64.b64encode(img.read()).decode()

# -----------------------
# HEATMAP
# -----------------------
def generate_map():
    m = folium.Map(location=[4.21,101.97], zoom_start=6)
    heat = [[3.139,101.6869,5],[1.49,103.74,4],[5.41,100.33,3]]
    HeatMap(heat).add_to(m)
    return m._repr_html_()

# -----------------------
# DASHBOARD
# -----------------------
@app.route("/")
def dashboard():
    page = int(request.args.get("page",1))
    sort = request.args.get("sort","risk_score")

    conn = sqlite3.connect(DB)
    c = conn.cursor()

    total = c.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
    offset = (page-1)*50

    data = c.execute(f"""
        SELECT pulse,indicator,type,mitre,risk_score,created_at
        FROM threats ORDER BY {sort} DESC
        LIMIT 50 OFFSET ?
    """,(offset,)).fetchall()

    conn.close()

    return render_template_string(TEMPLATE,
        data=data,
        total=total,
        risk_index=risk_index(),
        summary=executive_summary(),
        trend=generate_trend(),
        map_html=generate_map()
    )

# -----------------------
# INCIDENT
# -----------------------
@app.route("/create_incident", methods=["POST"])
def create_incident():
    title = request.form["title"]
    severity = request.form["severity"]
    indicator = request.form["indicator"]

    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("""
    INSERT INTO incidents (title,severity,status,linked_indicator,created_at)
    VALUES (?,?,?,?,?)
    """,(title,severity,"Open",indicator,datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()

    return redirect("/")

# -----------------------
# PDF REPORT
# -----------------------
@app.route("/report/pdf")
def pdf_report():
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=landscape(A4))
    elements = []
    styles = getSampleStyleSheet()

    elements.append(Paragraph("REDSHARK.MY SOC WEEKLY REPORT", styles["Title"]))
    elements.append(Spacer(1,12))
    elements.append(Paragraph(executive_summary(), styles["Normal"]))
    elements.append(PageBreak())

    conn = sqlite3.connect(DB)
    c = conn.cursor()
    rows = c.execute("""
        SELECT pulse,indicator,type,mitre,risk_score,created_at
        FROM threats
    """).fetchall()
    conn.close()

    header = ["Pulse","Indicator","Type","MITRE","Risk","Created"]
    chunk = 40

    for i in range(0,len(rows),chunk):
        table_data = [header] + rows[i:i+chunk]
        table = Table(table_data, repeatRows=1)
        table.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,0),colors.crimson),
            ("TEXTCOLOR",(0,0),(-1,0),colors.white),
            ("GRID",(0,0),(-1,-1),0.5,colors.grey),
            ("BACKGROUND",(0,1),(-1,-1),colors.whitesmoke)
        ]))
        elements.append(table)
        elements.append(PageBreak())

    doc.build(elements)
    buffer.seek(0)

    return send_file(buffer, as_attachment=True,
                     download_name="soc_weekly.pdf",
                     mimetype="application/pdf")

# -----------------------
# CSV / JSON
# -----------------------
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
    return send_file(output, as_attachment=True, download_name="soc.csv")

@app.route("/report/json")
def json_report():
    conn = sqlite3.connect(DB)
    rows = conn.execute("SELECT * FROM threats").fetchall()
    conn.close()
    return jsonify(rows)

# -----------------------
# TEMPLATE
# -----------------------
TEMPLATE = """
<html>
<head>
<style>
body { background:#0a1f44; color:white; font-family:Arial; }
h1 { color:crimson; }
th { background:#001f3f; padding:8px; }
td { padding:6px; }
tr:nth-child(even) { background:#2a3d6a; }
tr:nth-child(odd) { background:#1a2d5a; }
a { color:orange; }
.badge { padding:4px 8px; border-radius:4px; }
</style>
</head>
<body>
<h1>REDSHARK.MY SOC DASHBOARD</h1>
<h3>Risk Index: {{ risk_index }}</h3>
<div>{{ map_html|safe }}</div>
<p>{{ summary }}</p>
<img src="data:image/png;base64,{{ trend }}">
<h3>Total Indicators: {{ total }}</h3>
<table width="100%">
<tr>
<th>Pulse</th><th>Indicator</th><th>Type</th><th>MITRE</th><th>Risk Score</th><th>Created</th>
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
</body>
</html>
"""

# -----------------------
# START
# -----------------------
if __name__ == "__main__":
    init_db()
    seed_data()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT",5000)))
