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
        """,(f"Campaign {i%6}",indicator,typ,classification,mitre,score,hash_val,datetime.utcnow().isoformat()))
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
def generate_trend_html():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    data = c.execute("SELECT substr(created_at,1,10), COUNT(*) FROM threats GROUP BY substr(created_at,1,10)").fetchall()
    conn.close()
    dates = [d[0] for d in data]
    counts = [d[1] for d in data]

    plt.figure(figsize=(10,4))
    plt.plot(dates, counts, color="crimson", marker="o", label="Total Indicators")
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
        marker_color=["crimson","orange","#7fb77e"],  # grey-green
        text=[ipv4_count, domain_count, url_count],
        textposition="auto",
        hovertemplate='%{x}: %{y} indicators<extra></extra>'
    ))
    fig.update_layout(title="Active Indicators by Type", template="plotly_dark", height=300, margin=dict(l=50,r=50,t=40,b=20))
    return pio.to_html(fig, full_html=False)

# ------------------ MAP ------------------
def generate_map():
    m = folium.Map(location=[4.21,101.97], zoom_start=6)
    heat = [[3.139,101.6869,5],[1.49,103.74,4],[5.41,100.33,3]]
    HeatMap(heat).add_to(m)
    return m._repr_html_()

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

# ------------------ RUN SERVER ------------------
def run_app():
    app.run(host="0.0.0.0", port=5000, debug=True)

if __name__ == "__main__":
    print("Starting REDSHARK Cyber Threat Intelligence Dashboard...")
    run_app()

# ------------------ DASHBOARD TEMPLATE ------------------
TEMPLATE = """
<html><head>
<style>
body { background:#0a1f44; color:white; font-family:Arial; margin:0 auto; max-width:1200px; }
h1 { color:crimson; text-align:center; }
h3 { text-align:center; }
table { width:100%; border-collapse:collapse; margin:auto; }
th, td { padding:6px; text-align:center; }
tr:nth-child(even) { background:#2a3d6a; }
tr:nth-child(odd) { background:#1a2d5a; }
th { background:#001f3f; cursor:pointer; }
a { color:orange; }
.container { text-align:center; margin:auto; }
</style>
<script>
function sortTable(n) {
  var table=document.getElementById("threatTable");
  var rows, switching, i, x, y, shouldSwitch, dir="asc", switchcount=0;
  switching=true;
  while(switching){
    switching=false;
    rows=table.rows;
    for(i=1;i<rows.length-1;i++){
      shouldSwitch=false;
      x=rows[i].getElementsByTagName("TD")[n];
      y=rows[i+1].getElementsByTagName("TD")[n];
      if(dir=="asc" && x.innerHTML.toLowerCase()>y.innerHTML.toLowerCase()){shouldSwitch=true;break;}
      else if(dir=="desc" && x.innerHTML.toLowerCase()<y.innerHTML.toLowerCase()){shouldSwitch=true;break;}
    }
    if(shouldSwitch){rows[i].parentNode.insertBefore(rows[i+1],rows[i]);switching=true;switchcount++;}
    else if(switchcount==0 && dir=="asc"){dir="desc";switching=true;}
  }
}
</script>
</head>
<body>
<h1>REDSHARK CYBER THREAT INTELLIGENCE DASHBOARD</h1>
<div class="container">{{ map_html|safe }}</div>
<p style="text-align:center;">{{ summary }}</p>
<div class="container"><img src="data:image/png;base64,{{ trend }}"></div>
<div class="container">{{ type_chart|safe }}</div>
<h3>Total Indicators: {{ total }}</h3>
<table id="threatTable">
<tr>
<th onclick="sortTable(0)">Pulse</th>
<th onclick="sortTable(1)">Indicator</th>
<th onclick="sortTable(2)">Type</th>
<th onclick="sortTable(3)">Classification</th>
<th onclick="sortTable(4)">MITRE</th>
<th onclick="sortTable(5)">Risk Score</th>
<th onclick="sortTable(6)">Hash</th>
<th onclick="sortTable(7)">Created</th>
</tr>
{% for row in data %}
<tr>
<td>{{ row[0] }}</td><td>{{ row[1] }}</td><td>{{ row[2] }}</td><td>{{ row[3] }}</td>
<td>{{ row[4] }}</td><td>{{ row[5] }}</td><td>{{ row[6] }}</td><td>{{ row[7] }}</td>
</tr>
{% endfor %}
</table>
<p style="text-align:center;">{{ disclaimer }}</p>
</body></html>
"""
