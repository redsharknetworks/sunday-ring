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
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import A4, landscape
import ipaddress
import re
import plotly.graph_objs as go
import plotly.io as pio

app = Flask(__name__)

DB = "/tmp/threats.db"
PAGE_SIZE = 50
DISCLAIMER = "Information and analysis are derived from publicly available sources and developed by DarkGrid (darkgrid@redshark.my)."

# ------------------ DATABASE INIT ------------------
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
        hash TEXT,
        created_at TEXT
    )
    """)
    conn.commit()
    conn.close()

# ------------------ VALIDATION ------------------
def is_valid_ipv4(addr):
    try:
        ipaddress.IPv4Address(addr)
        return True
    except ipaddress.AddressValueError:
        return False

def is_valid_domain(domain):
    pattern = re.compile(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")
    return bool(pattern.match(domain))

def is_valid_url(url):
    return url.startswith("http://") or url.startswith("https://")

# ------------------ RISK ENGINE ------------------
def calculate_risk(classification, mitre):
    base = {"Low":30,"Medium":60,"High":80}.get(classification,50)
    mitre_weight = 15 if "T1566" in mitre else 10
    recency = random.randint(5,15)
    return min(base + mitre_weight + recency, 100)

def risk_level(score):
    if score >= 90: return "Critical"
    elif score >= 70: return "High"
    elif score >= 40: return "Medium"
    return "Low"

# ------------------ SEED DATA ------------------
def seed_data():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    count = c.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
    if count > 0:
        conn.close()
        return

    for i in range(120):
        classification = random.choice(["Low","Medium","High"])
        mitre = random.choice(["T1566 Phishing","T1071 C2","T1059 Execution"])
        score = calculate_risk(classification, mitre)
        typ = random.choice(["domain","IPv4","URL"])

        if typ == "domain":
            indicator = f"malicious{i}.com"
            if not is_valid_domain(indicator): continue
        elif typ == "IPv4":
            indicator = f"192.168.{i%255}.{i%255}"
            if not is_valid_ipv4(indicator): continue
        else:
            indicator = f"http://malicious{i}.com"
            if not is_valid_url(indicator): continue

        hash_val = f"{random.getrandbits(128):032x}"

        c.execute("""
        INSERT INTO threats (pulse,indicator,type,classification,mitre,risk_score,hash,created_at)
        VALUES (?,?,?,?,?,?,?,?)
        """,(
            f"Campaign {i%6}",
            indicator,
            typ,
            classification,
            mitre,
            score,
            hash_val,
            datetime.utcnow().isoformat()
        ))
    conn.commit()
    conn.close()

def ensure_database():
    init_db()
    seed_data()

ensure_database()

# ------------------ ANALYTICS ------------------
def risk_index():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    scores = [x[0] for x in c.execute("SELECT risk_score FROM threats").fetchall()]
    conn.close()
    return int(sum(scores)/len(scores)) if scores else 0

def executive_summary():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    total = c.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
    high = c.execute("SELECT COUNT(*) FROM threats WHERE risk_score >=70").fetchone()[0]
    top_mitre = c.execute("SELECT mitre, COUNT(*) FROM threats GROUP BY mitre ORDER BY COUNT(*) DESC LIMIT 1").fetchone()
    conn.close()
    mitre_text = top_mitre[0] if top_mitre else "N/A"
    return f"REDSHARK.MY identified {total} active indicators this week. {high} were High/Critical. Dominant technique: {mitre_text}. SecureNation Index: {risk_index()}."

# ------------------ TREND CHART ------------------
def get_top10_indicators_for_chart():
    week_ago = datetime.utcnow() - timedelta(days=7)
    week_str = week_ago.isoformat()
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    top10 = c.execute("""
        SELECT indicator, type, MAX(risk_score) as risk, COUNT(*) as c
        FROM threats
        WHERE created_at >= ?
        GROUP BY indicator
        ORDER BY risk DESC, c DESC
        LIMIT 10
    """,(week_str,)).fetchall()
    conn.close()
    return top10

def generate_trend_html():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    data = c.execute("SELECT substr(created_at,1,10), COUNT(*) FROM threats GROUP BY substr(created_at,1,10)").fetchall()
    conn.close()
    dates = [d[0] for d in data]
    counts = [d[1] for d in data]

    top10 = get_top10_indicators_for_chart()
    top_indicators = [t[0] for t in top10]

    plt.figure(figsize=(10,4))
    plt.plot(dates, counts, color="crimson", marker="o", label="Total Indicators")

    for i, date in enumerate(dates):
        conn = sqlite3.connect(DB)
        day_indicators = [x[0] for x in conn.execute("SELECT indicator FROM threats WHERE substr(created_at,1,10)=?",(date,)).fetchall()]
        conn.close()
        if any(ind in top_indicators for ind in day_indicators):
            plt.scatter(date, counts[i], color="orange", s=100, zorder=5, label="Top 10 Weekly" if i==0 else "")

    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.legend()
    img = io.BytesIO()
    plt.savefig(img, format="png")
    plt.close()
    img.seek(0)
    return base64.b64encode(img.read()).decode()

# ------------------ TYPE COUNT CHART ------------------
def generate_type_count_chart(ipv4_count, domain_count, url_count):
    fig = go.Figure()
    fig.add_trace(go.Bar(
        x=["IPv4","Domain","URL"],
        y=[ipv4_count, domain_count, url_count],
        marker_color=["crimson","orange","lime"],
        text=[ipv4_count, domain_count, url_count],
        textposition="auto",
        hovertemplate='%{x}: %{y} indicators<extra></extra>'
    ))
    fig.update_layout(title="Active Indicators by Type", template="plotly_dark", height=300, margin=dict(l=20,r=20,t=40,b=20))
    return pio.to_html(fig, full_html=False)

# ------------------ MAP ------------------
def generate_map():
    m = folium.Map(location=[4.21,101.97], zoom_start=6)
    heat = [[3.139,101.6869,5],[1.49,103.74,4],[5.41,100.33,3]]
    HeatMap(heat).add_to(m)
    return m._repr_html_()

# ------------------ WEEKLY TOP 10 FOR PDF ------------------
def get_weekly_top10():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    week_ago = datetime.utcnow() - timedelta(days=7)
    week_str = week_ago.isoformat()
    top_ipv4 = c.execute("""SELECT indicator, MAX(risk_score) as risk, COUNT(*) as c FROM threats WHERE type='IPv4' AND created_at>=? GROUP BY indicator ORDER BY risk DESC, c DESC LIMIT 10""",(week_str,)).fetchall()
    top_domain = c.execute("""SELECT indicator, MAX(risk_score) as risk, COUNT(*) as c FROM threats WHERE type='domain' AND created_at>=? GROUP BY indicator ORDER BY risk DESC, c DESC LIMIT 10""",(week_str,)).fetchall()
    top_url = c.execute("""SELECT indicator, MAX(risk_score) as risk, COUNT(*) as c FROM threats WHERE type='URL' AND created_at>=? GROUP BY indicator ORDER BY risk DESC, c DESC LIMIT 10""",(week_str,)).fetchall()
    top_hash = c.execute("""SELECT hash, MAX(risk_score) as risk, COUNT(*) as c FROM threats WHERE created_at>=? GROUP BY hash ORDER BY risk DESC, c DESC LIMIT 10""",(week_str,)).fetchall()
    conn.close()
    return top_ipv4, top_domain, top_url, top_hash

def add_top10_table(elements, title, rows, col_headers):
    elements.append(Paragraph(title, getSampleStyleSheet()["Heading2"]))
    elements.append(Spacer(1,6))
    if rows:
        table_data = [col_headers] + rows
        table = Table(table_data, repeatRows=1)
        style = TableStyle([
            ("BACKGROUND",(0,0),(-1,0),colors.black),
            ("TEXTCOLOR",(0,0),(-1,0),colors.white),
            ("GRID",(0,0),(-1,-1),0.5,colors.grey),
            ("BACKGROUND",(0,1),(-1,-1),colors.whitesmoke)
        ])
        for idx, row_val in enumerate(rows, start=1):
            score = row_val[1]
            if score >= 90: style.add("TEXTCOLOR",(1,idx),(1,idx),colors.red)
            elif score >= 70: style.add("TEXTCOLOR",(1,idx),(1,idx),colors.orange)
            elif score >= 40: style.add("TEXTCOLOR",(1,idx),(1,idx),colors.yellow)
            else: style.add("TEXTCOLOR",(1,idx),(1,idx),colors.green)
        table.setStyle(style)
        elements.append(table)
        elements.append(Spacer(1,12))

# ------------------ DASHBOARD ------------------
@app.route("/")
def dashboard():
    page = int(request.args.get("page",1))
    sort = request.args.get("sort","risk_score")
    offset = (page-1)*PAGE_SIZE
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    total = c.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
    ipv4_count = c.execute("SELECT COUNT(*) FROM threats WHERE type='IPv4'").fetchone()[0]
    domain_count = c.execute("SELECT COUNT(*) FROM threats WHERE type='domain'").fetchone()[0]
    url_count = c.execute("SELECT COUNT(*) FROM threats WHERE type='URL'").fetchone()[0]
    data = c.execute(f"SELECT pulse,indicator,type,classification,mitre,risk_score,hash,created_at FROM threats ORDER BY {sort} DESC LIMIT ? OFFSET ?",(PAGE_SIZE, offset)).fetchall()
    conn.close()
    type_chart = generate_type_count_chart(ipv4_count, domain_count, url_count)
    trend = generate_trend_html()
    return render_template_string(TEMPLATE,
        data=data,total=total,page=page,risk_index=risk_index(),summary=executive_summary(),
        trend=trend,map_html=generate_map(),disclaimer=DISCLAIMER,
        ipv4_count=ipv4_count,domain_count=domain_count,url_count=url_count,type_chart=type_chart)

# ------------------ REPORTS ------------------
@app.route("/report/pdf")
def pdf_report():
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=landscape(A4))
    elements = []
    styles = getSampleStyleSheet()
    elements.append(Paragraph("REDSHARK DARKGRID REPORT", styles["Title"]))
    elements.append(Spacer(1,12))
    elements.append(Paragraph(executive_summary(), styles["Normal"]))

    top_ipv4, top_domain, top_url, top_hash = get_weekly_top10()
    add_top10_table(elements, "Weekly Top 10 IPv4 Threats", top_ipv4, ["IPv4","Risk Score","Count"])
    add_top10_table(elements, "Weekly Top 10 Domain Threats", top_domain, ["Domain","Risk Score","Count"])
    add_top10_table(elements, "Weekly Top 10 URL Threats", top_url, ["URL","Risk Score","Count"])
    add_top10_table(elements, "Weekly Top 10 Hash Threats", top_hash, ["Hash","Risk Score","Count"])
    elements.append(PageBreak())

    conn = sqlite3.connect(DB)
    rows = conn.execute("SELECT pulse,indicator,type,mitre,risk_score,hash,created_at FROM threats").fetchall()
    conn.close()
    header = ["Pulse","Indicator","Type","MITRE","Risk","Hash","Created"]
    chunk = 40
    for i in range(0,len(rows),chunk):
        table_data = [header] + rows[i:i+chunk]
        table = Table(table_data, repeatRows=1)
        table.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,0),colors.black),
            ("TEXTCOLOR",(0,0),(-1,0),colors.white),
            ("GRID",(0,0),(-1,-1),0.5,colors.grey),
            ("BACKGROUND",(0,1),(-1,-1),colors.whitesmoke)
        ]))
        elements.append(table)
        elements.append(PageBreak())

    doc.build(elements)
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name="soc_elite_report.pdf", mimetype="application/pdf")

@app.route("/report/csv")
def csv_report():
    conn = sqlite3.connect(DB)
    rows = conn.execute("SELECT * FROM threats").fetchall()
    conn.close()
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(["ID","Pulse","Indicator","Type","Classification","MITRE","Risk","Hash","Created"])
    cw.writerows(rows)
    output = io.BytesIO()
    output.write(si.getvalue().encode())
    output.seek(0)
    return send_file(output, as_attachment=True, download_name="soc_elite.csv")

@app.route("/report/json")
def json_report():
    conn = sqlite3.connect(DB)
    rows = conn.execute("SELECT * FROM threats").fetchall()
    conn.close()
    return jsonify(rows)

# ------------------ DASHBOARD TEMPLATE ------------------
TEMPLATE = """
<html><head><style>
body { background:#0a1f44; color:white; font-family:Arial; }
h1 { color:crimson; }
th { background:#001f3f; padding:8px; }
td { padding:6px; }
tr:nth-child(even) { background:#2a3d6a; }
tr:nth-child(odd) { background:#1a2d5a; }
a { color:orange; }
</style></head>
<body>
<h1>REDSHARK DARKGRID DASHBOARD</h1>
<h3>SecureNation Index: {{ risk_index }}</h3>
<div>{{ map_html|safe }}</div>
<p>{{ summary }}</p>
<img src="data:image/png;base64,{{ trend }}">
<h3>Indicator Breakdown:</h3>
<div>{{ type_chart|safe }}</div>
<h3>Total Indicators: {{ total }}</h3>
<table width="100%">
<tr><th>Pulse</th><th>Indicator</th><th>Type</th><th>Classification</th><th>MITRE</th><th>Risk Score</th><th>Hash</th><th>Created</th></tr>
{% for row in data %}
<tr>
<td>{{ row[0] }}</td>
<td>{{ row[1] }}</td>
<td>{{ row[2] }}</td>
<td>{{ row[3] }}</td>
<td>{{ row[4] }}</td>
<td>{{ row[5] }}</td>
<td>{{ row[6] }}</td>
<td>{{ row[7] }}</td>
</tr>
{% endfor %}
</table>
<br>
<a href="/report/pdf">PDF</a> | <a href="/report/csv">CSV</a> | <a href="/report/json">JSON</a>
<p style="font-size:10px;">{{ disclaimer }}</p>
</body></html>
"""

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
