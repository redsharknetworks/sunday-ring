import os
import sqlite3
import random
from datetime import datetime, timedelta
from threading import Thread
import time
from flask import Flask, jsonify, request, render_template_string, send_file
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import io
import csv
import base64
import folium
from folium.plugins import HeatMap
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import A4, landscape
import ipaddress
import re
from OTXv2 import OTXv2  # make sure to install otx-api-client

# ---------------- CONFIG ----------------
app = Flask(__name__)
DB = "/tmp/threats.db"
PAGE_SIZE = 50
DISCLAIMER = "Information and analysis are derived from publicly available sources and developed by DarkGrid (darkgrid@redshark.my)."
OTX_KEY = os.environ.get("OTX_API_KEY")  # set in Render dashboard
otx = OTXv2(OTX_KEY)

# ---------------- DATABASE ----------------
def get_conn():
    return sqlite3.connect(DB, check_same_thread=False)

def init_db():
    conn = get_conn()
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

# ---------------- VALIDATION ----------------
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

# ---------------- RISK ENGINE ----------------
def calculate_risk(classification, mitre):
    base = {"Low":30,"Medium":60,"High":80}.get(classification,50)
    mitre_weight = 15 if "T1566" in mitre else 10
    recency = random.randint(5,15)
    return min(base + mitre_weight + recency, 100)

# ---------------- SEED DATA ----------------
def seed_data():
    conn = get_conn()
    c = conn.cursor()
    if c.execute("SELECT COUNT(*) FROM threats").fetchone()[0] > 0:
        conn.close()
        return
    for i in range(50):
        classification = random.choice(["Low","Medium","High"])
        mitre = random.choice(["T1566 Phishing","T1071 C2","T1059 Execution"])
        score = calculate_risk(classification, mitre)
        typ = random.choice(["domain","IPv4","URL","hash"])
        pulse = f"Campaign {i%6}"
        created_at = datetime.utcnow().isoformat()
        if typ == "domain":
            indicator = f"malicious{i}.com"
            c.execute("INSERT INTO threats (pulse,indicator,type,classification,mitre,risk_score,created_at) VALUES (?,?,?,?,?,?,?)",
                      (pulse, indicator, typ, classification, mitre, score, created_at))
        elif typ == "IPv4":
            indicator = f"192.168.{i%255}.{i%255}"
            c.execute("INSERT INTO threats (pulse,indicator,type,classification,mitre,risk_score,created_at) VALUES (?,?,?,?,?,?,?)",
                      (pulse, indicator, typ, classification, mitre, score, created_at))
        elif typ == "URL":
            indicator = f"http://malicious{i}.com"
            c.execute("INSERT INTO threats (pulse,indicator,type,classification,mitre,risk_score,created_at) VALUES (?,?,?,?,?,?,?)",
                      (pulse, indicator, typ, classification, mitre, score, created_at))
        else:
            hash_val = f"{random.getrandbits(128):032x}"
            c.execute("INSERT INTO threat_hashes (pulse,hash,classification,mitre,risk_score,created_at) VALUES (?,?,?,?,?,?)",
                      (pulse, hash_val, classification, mitre, score, created_at))
    conn.commit()
    conn.close()

# ---------------- OTX FETCH ----------------
def fetch_otx():
    try:
        pulses = otx.getall_pulses()  # fetch recent pulses
        conn = get_conn()
        c = conn.cursor()
        for pulse in pulses:
            pulse_name = pulse.get("name", "Unknown")
            indicators = pulse.get("indicators", [])
            for i in indicators:
                typ = i.get("type", "")
                indicator = i.get("indicator", "")
                mitre = i.get("technique", "")
                classification = "Medium"
                risk_score = calculate_risk(classification, mitre)
                created_at = datetime.utcnow().isoformat()
                if typ in ["IPv4", "domain", "URL"] and indicator:
                    c.execute("INSERT OR IGNORE INTO threats (pulse,indicator,type,classification,mitre,risk_score,created_at) VALUES (?,?,?,?,?,?,?)",
                              (pulse_name, indicator, typ, classification, mitre, risk_score, created_at))
                elif typ == "file hash":
                    c.execute("INSERT OR IGNORE INTO threat_hashes (pulse,hash,classification,mitre,risk_score,created_at) VALUES (?,?,?,?,?,?)",
                              (pulse_name, indicator, classification, mitre, risk_score, created_at))
        conn.commit()
        conn.close()
    except Exception as e:
        print("OTX fetch error:", e)

def auto_fetch_otx():
    while True:
        fetch_otx()
        time.sleep(3600)  # every hour

# ---------------- ANALYTICS ----------------
def risk_index():
    conn = get_conn()
    c = conn.cursor()
    scores = [x[0] for x in c.execute("SELECT risk_score FROM threats").fetchall()]
    scores += [x[0] for x in c.execute("SELECT risk_score FROM threat_hashes").fetchall()]
    conn.close()
    return int(sum(scores)/len(scores)) if scores else 0

def executive_summary():
    conn = get_conn()
    c = conn.cursor()
    total = c.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
    total += c.execute("SELECT COUNT(*) FROM threat_hashes").fetchone()[0]
    high = c.execute("SELECT COUNT(*) FROM threats WHERE risk_score >=70").fetchone()[0]
    high += c.execute("SELECT COUNT(*) FROM threat_hashes WHERE risk_score >=70").fetchone()[0]
    top_mitre = c.execute("SELECT mitre, COUNT(*) FROM threats GROUP BY mitre ORDER BY COUNT(*) DESC LIMIT 1").fetchone()
    conn.close()
    mitre_text = top_mitre[0] if top_mitre else "N/A"
    return f"Redshark observed {total} active indicators this week. {high} were High/Critical. Dominant technique: {mitre_text}. SecureNation Index: {risk_index()}."

# ---------------- TREND CHART ----------------
def generate_trend_html():
    conn = get_conn()
    c = conn.cursor()
    data = c.execute("SELECT substr(created_at,1,10), COUNT(*) FROM threats GROUP BY substr(created_at,1,10) ORDER BY substr(created_at,1,10)").fetchall()
    conn.close()
    if not data: return ""
    dates = [d[0] for d in data]
    counts = [d[1] for d in data]

    plt.figure(figsize=(10,4))
    ax = plt.gca()
    ax.set_facecolor('#2a2a2a')

    # Boxing ring background
    if os.path.exists("boxing_ring.png"):
        bg = plt.imread("boxing_ring.png")
        ax.imshow(bg, extent=[0,len(dates)-1,0,max(counts)+5], aspect='auto', alpha=0.2)

    plt.plot(dates, counts, color="crimson", marker="o", linewidth=2, label="Total Indicators")
    plt.fill_between(dates, counts, color="crimson", alpha=0.1)
    plt.grid(color='white', linestyle='--', linewidth=0.3, alpha=0.5)
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.legend()
    img = io.BytesIO()
    plt.savefig(img, format="png", facecolor=ax.get_facecolor())
    plt.close()
    img.seek(0)
    return base64.b64encode(img.read()).decode()

# ---------------- INDICATOR TYPE LINE CHART ----------------
def generate_type_chart_html():
    conn = get_conn()
    c = conn.cursor()
    data = c.execute("SELECT type, COUNT(*) FROM threats GROUP BY type").fetchall()
    conn.close()
    if not data: return ""
    types = [d[0] for d in data]
    counts = [d[1] for d in data]

    plt.figure(figsize=(8,3))
    plt.plot(types, counts, color="orange", marker="o", linewidth=2)
    plt.grid(color='white', linestyle='--', linewidth=0.3, alpha=0.5)
    plt.tight_layout()
    img = io.BytesIO()
    plt.savefig(img, format="png", facecolor='#0a1f44')
    plt.close()
    img.seek(0)
    return base64.b64encode(img.read()).decode()

# ---------------- MAP ----------------
def generate_map():
    m = folium.Map(location=[4.21,101.97], zoom_start=6)
    heat = [[3.139,101.6869,5],[1.49,103.74,4],[5.41,100.33,3]]
    HeatMap(heat).add_to(m)
    return m._repr_html_()

# ---------------- REPORTS ----------------
def get_weekly_top10():
    week_ago = (datetime.utcnow() - timedelta(days=7)).isoformat()
    conn = get_conn()
    c = conn.cursor()
    result = {}
    for typ in ["IPv4","domain","URL"]:
        result[typ] = c.execute("SELECT pulse,indicator,type,classification,mitre,risk_score,created_at FROM threats WHERE type=? AND created_at >= ? ORDER BY risk_score DESC LIMIT 10",(typ, week_ago)).fetchall()
    result["hash"] = c.execute("SELECT pulse,hash AS indicator,'hash' AS type,classification,mitre,risk_score,created_at FROM threat_hashes WHERE created_at >= ? ORDER BY risk_score DESC LIMIT 10",(week_ago,)).fetchall()
    conn.close()
    return result

# ---------------- DASHBOARD ----------------
@app.route("/")
def dashboard():
    page = int(request.args.get("page",1))
    sort = request.args.get("sort","risk_score")
    offset = (page-1)*PAGE_SIZE
    conn = get_conn()
    c = conn.cursor()
    total = c.execute("SELECT COUNT(*) FROM threats WHERE type IN ('domain','IPv4','URL')").fetchone()[0]
    data = c.execute(f"SELECT pulse,indicator,type,classification,mitre,risk_score,created_at FROM threats WHERE type IN ('domain','IPv4','URL') ORDER BY {sort} DESC LIMIT ? OFFSET ?", (PAGE_SIZE, offset)).fetchall()
    conn.close()

    trend = generate_trend_html()
    type_chart = generate_type_chart_html()
    return render_template_string(TEMPLATE,
                                  data=data,
                                  total=total,
                                  page=page,
                                  risk_index=risk_index(),
                                  summary=executive_summary(),
                                  trend=trend,
                                  type_chart=type_chart,
                                  map_html=generate_map(),
                                  disclaimer=DISCLAIMER)

# ---------------- PDF/CSV/JSON ----------------
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

    weekly_top = get_weekly_top10()
    for typ, rows in weekly_top.items():
        elements.append(Paragraph(f"Weekly Top 10 {typ} Threats", styles["Heading2"]))
        header = ["Pulse","Indicator","Type","Classification","MITRE","Risk","Created"]
        table_data = [header] + rows
        table = Table(table_data, repeatRows=1)
        table.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,0),colors.black),
            ("TEXTCOLOR",(0,0),(-1,0),colors.white),
            ("GRID",(0,0),(-1,-1),0.5,colors.grey),
            ("BACKGROUND",(0,1),(-1,-1),colors.whitesmoke)
        ]))
        elements.append(table)
        elements.append(Spacer(1,12))

    elements.append(Paragraph(DISCLAIMER, styles["Italic"]))
    doc.build(elements)
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name="darkgridatredsharkdotmy.pdf", mimetype="application/pdf")

@app.route("/report/csv")
def csv_report():
    conn = get_conn()
    rows = conn.execute("SELECT * FROM threats").fetchall()
    hash_rows = conn.execute("SELECT id,pulse,hash,type,classification,mitre,risk_score,created_at FROM threat_hashes").fetchall()
    conn.close()
    all_rows = rows + hash_rows
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(["ID","Pulse","Indicator","Type","Classification","MITRE","Risk","Created"])
    cw.writerows(all_rows)
    output = io.BytesIO()
    output.write(si.getvalue().encode())
    output.seek(0)
    return send_file(output, as_attachment=True, download_name="darkgridatredsharkdotmy.csv")

@app.route("/report/json")
def json_report():
    conn = get_conn()
    rows = conn.execute("SELECT * FROM threats").fetchall()
    hash_rows = conn.execute("SELECT id,pulse,hash,type,classification,mitre,risk_score,created_at FROM threat_hashes").fetchall()
    conn.close()
    combined = rows + hash_rows
    return jsonify(combined)

# ---------------- RUN ----------------
if __name__ == "__main__":
    init_db()
    seed_data()
    Thread(target=auto_fetch_otx, daemon=True).start()
    app.run(host="0.0.0.0", port=5000, debug=True)

# ---------------- DASHBOARD TEMPLATE ----------------
TEMPLATE = """<html><head>
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
<h1>REDSHARK CYBER THREATS INTELLIGENCE DASHBOARD</h1>
<div class="container">{{ map_html|safe }}</div>
<p style="text-align:center;">{{ summary }}</p>
<div class="container"><img src="data:image/png;base64,{{ trend }}"></div>
<div class="container"><img src="data:image/png;base64,{{ type_chart }}"></div>
<h3>Total Indicators: {{ total }}</h3>
<table id="threatTable">
<tr>
<th onclick="sortTable(0)">Pulse</th>
<th onclick="sortTable(1)">Indicator</th>
<th onclick="sortTable(2)">Type</th>
<th onclick="sortTable(3)">Classification</th>
<th onclick="sortTable(4)">MITRE</th>
<th onclick="sortTable(5)">Risk Score</th>
<th onclick="sortTable(6)">Created</th>
</tr>
{% for row in data %}
<tr>
<td>{{ row[0] }}</td>
<td>{{ row[1] }}</td>
<td>{{ row[2] }}</td>
<td>{{ row[3] }}</td>
<td>{{ row[4] }}</td>
<td>{{ row[5] }}</td>
<td>{{ row[6] }}</td>
</tr>
{% endfor %}
</table>
<p style="text-align:center;">{{ disclaimer }}</p>
<p style="text-align:center;">
<a href="/report/pdf">Download PDF</a> |
<a href="/report/csv">Download CSV</a>
