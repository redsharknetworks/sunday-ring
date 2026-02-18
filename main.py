import os
import sqlite3
import random
import requests
from datetime import datetime, timedelta
from flask import Flask, jsonify, render_template_string, send_file
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import io, csv, base64
import folium
from folium.plugins import HeatMap
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import A4, landscape
import ipaddress
import re

app = Flask(__name__)

DB = "threats.db"
DISCLAIMER = "Information and analysis derived from publicly available sources by DarkGrid."
OTX_API_KEY = os.environ.get("OTX_API_KEY")
OTX_BASE = "https://otx.alienvault.com/api/v1/indicators"

# ------------------ DATABASE ------------------
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
    count_main = c.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
    count_hash = c.execute("SELECT COUNT(*) FROM threat_hashes").fetchone()[0]
    if count_main > 0 or count_hash > 0:
        conn.close()
        return
    for i in range(50):
        classification = random.choice(["Low","Medium","High"])
        mitre = random.choice(["T1566 Phishing","T1071 C2","T1059 Execution"])
        score = calculate_risk(classification, mitre)
        typ = random.choice(["domain","IPv4","URL","hash"])
        if typ == "domain":
            indicator = f"malicious{i}.com"
            if not is_valid_domain(indicator): continue
            c.execute("""
                INSERT INTO threats (pulse,indicator,type,classification,mitre,risk_score,created_at)
                VALUES (?,?,?,?,?,?,?)
            """,(f"Campaign {i%6}",indicator,typ,classification,mitre,score,datetime.utcnow().isoformat()))
        elif typ == "IPv4":
            indicator = f"192.168.{i%255}.{i%255}"
            if not is_valid_ipv4(indicator): continue
            c.execute("""
                INSERT INTO threats (pulse,indicator,type,classification,mitre,risk_score,created_at)
                VALUES (?,?,?,?,?,?,?)
            """,(f"Campaign {i%6}",indicator,typ,classification,mitre,score,datetime.utcnow().isoformat()))
        elif typ == "URL":
            indicator = f"http://malicious{i}.com"
            if not is_valid_url(indicator): continue
            c.execute("""
                INSERT INTO threats (pulse,indicator,type,classification,mitre,risk_score,created_at)
                VALUES (?,?,?,?,?,?,?)
            """,(f"Campaign {i%6}",indicator,typ,classification,mitre,score,datetime.utcnow().isoformat()))
        else:
            hash_val = f"{random.getrandbits(128):032x}"
            c.execute("""
                INSERT INTO threat_hashes (pulse,hash,classification,mitre,risk_score,created_at)
                VALUES (?,?,?,?,?,?)
            """,(f"Campaign {i%6}",hash_val,classification,mitre,score,datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()

# ------------------ OTX FETCH ------------------
def fetch_otx_data():
    if not OTX_API_KEY:
        print("OTX_API_KEY not set")
        return
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    types = ["IPv4","domain","URL"]
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    for typ in types:
        url = f"{OTX_BASE}/{typ.lower()}/reputation"
        try:
            r = requests.get(url, headers=headers, timeout=10)
            if r.status_code != 200:
                continue
            for item in r.json().get("results", [])[:10]:  # top 10 recent
                indicator = item.get("indicator")
                mitre = item.get("tags")[0] if item.get("tags") else "N/A"
                classification = random.choice(["Low","Medium","High"])
                score = calculate_risk(classification, mitre)
                exists = c.execute("SELECT 1 FROM threats WHERE indicator=?",(indicator,)).fetchone()
                if not exists:
                    c.execute("""
                        INSERT INTO threats (pulse,indicator,type,classification,mitre,risk_score,created_at)
                        VALUES (?,?,?,?,?,?,?)
                    """,(f"OTX {typ}",indicator,typ,classification,mitre,score,datetime.utcnow().isoformat()))
        except Exception as e:
            print(f"OTX fetch error {typ}: {e}")
    conn.commit()
    conn.close()

# ------------------ DATABASE INIT ------------------
def ensure_database():
    init_db()
    seed_data()
    fetch_otx_data()

ensure_database()

# ------------------ ANALYTICS ------------------
def secure_nation_index():
    conn = sqlite3.connect(DB)
    scores = [x[0] for x in conn.execute("SELECT risk_score FROM threats").fetchall()]
    conn.close()
    return int(sum(scores)/len(scores)) if scores else 0

def executive_summary():
    conn = sqlite3.connect(DB)
    total = conn.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
    high = conn.execute("SELECT COUNT(*) FROM threats WHERE risk_score>=70").fetchone()[0]
    top_mitre = conn.execute("""
        SELECT mitre, COUNT(*) FROM threats
        GROUP BY mitre ORDER BY COUNT(*) DESC LIMIT 1
    """).fetchone()
    conn.close()
    mitre_text = top_mitre[0] if top_mitre else "N/A"
    return f"Redshark observed {total} active threat indicators this week. {high} classified as High/Critical. Dominant technique: {mitre_text}. SecureNation Index: {secure_nation_index()}."

# ------------------ HEAT MAP ------------------
def malaysia_heatmap():
    m = folium.Map(location=[4.2,101.97], zoom_start=6)
    heat_data = [
        [3.139,101.6869,5],
        [1.49,103.74,4],
        [5.41,100.33,3],
        [6.12,102.24,2],
        [2.19,102.25,3]
    ]
    HeatMap(heat_data).add_to(m)
    return m._repr_html_()

# ------------------ TREND CHART ------------------
def trend_chart():
    conn = sqlite3.connect(DB)
    data = conn.execute("""
        SELECT substr(created_at,1,10), COUNT(*) FROM threats GROUP BY substr(created_at,1,10)
    """).fetchall()
    conn.close()
    if not data: return ""
    dates = [d[0] for d in data]
    counts = [d[1] for d in data]

    plt.figure(figsize=(8,3))
    ax = plt.gca()
    ax.set_facecolor("black")

    if os.path.exists("boxing_ring.png"):
        bg = plt.imread("boxing_ring.png")
        ax.imshow(bg, extent=[0,len(dates)-1,0,max(counts)+5], aspect="auto", alpha=0.15)

    plt.plot(dates, counts, color="crimson", marker="o")
    plt.xticks(rotation=45)
    plt.tight_layout()

    img = io.BytesIO()
    plt.savefig(img, format="png", transparent=True)
    plt.close()
    img.seek(0)
    return base64.b64encode(img.read()).decode()

# ------------------ TYPE CHART ------------------
def type_chart():
    conn = sqlite3.connect(DB)
    data = conn.execute("""
        SELECT substr(created_at,1,10),
            SUM(CASE WHEN type='IPv4' THEN 1 ELSE 0 END),
            SUM(CASE WHEN type='domain' THEN 1 ELSE 0 END),
            SUM(CASE WHEN type='URL' THEN 1 ELSE 0 END)
        FROM threats GROUP BY substr(created_at,1,10)
    """).fetchall()
    conn.close()
    if not data: return ""
    dates = [d[0] for d in data]
    ipv4 = [d[1] for d in data]
    dom = [d[2] for d in data]
    urlc = [d[3] for d in data]

    plt.figure(figsize=(8,3))
    plt.plot(dates, ipv4, label="IPv4", marker="o")
    plt.plot(dates, dom, label="Domain", marker="o")
    plt.plot(dates, urlc, label="URL", marker="o")
    plt.xticks(rotation=45)
    plt.legend()
    plt.tight_layout()

    img = io.BytesIO()
    plt.savefig(img, format="png", transparent=True)
    plt.close()
    img.seek(0)
    return base64.b64encode(img.read()).decode()

# ------------------ DASHBOARD ------------------
@app.route("/")
def dashboard():
    conn = sqlite3.connect(DB)
    rows = conn.execute("""
        SELECT pulse,indicator,type,classification,mitre,risk_score,created_at
        FROM threats ORDER BY risk_score DESC
    """).fetchall()
    conn.close()

    return render_template_string(TEMPLATE,
        data=rows,
        total=len(rows),
        map_html=malaysia_heatmap(),
        trend=trend_chart(),
        type_chart_img=type_chart(),
        disclaimer=DISCLAIMER,
        summary=executive_summary(),
        index=secure_nation_index()
    )

# ------------------ REPORTS ------------------
def get_weekly_top10():
    week_ago = (datetime.utcnow() - timedelta(days=7)).isoformat()
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    result = {}
    for typ in ["IPv4","domain","URL"]:
        result[typ] = c.execute(f"""
            SELECT pulse,indicator,type,classification,mitre,risk_score,created_at
            FROM threats WHERE type=? AND created_at>=?
            ORDER BY risk_score DESC LIMIT 10
        """,(typ,week_ago)).fetchall()
    result["hash"] = c.execute("""
        SELECT pulse,hash AS indicator,'hash',classification,mitre,risk_score,created_at
        FROM threat_hashes WHERE created_at>=? ORDER BY risk_score DESC LIMIT 10
    """,(week_ago,)).fetchall()
    conn.close()
    return result

@app.route("/report/pdf")
def pdf_report():
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=landscape(A4))
    styles = getSampleStyleSheet()
    elements = [Paragraph("REDSHAK DARKGRID WEEKLY REPORT", styles["Title"]), Spacer(1,12)]
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
    return send_file(buffer, as_attachment=True, download_name="darkgrid_report.pdf")

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
    return send_file(output, as_attachment=True, download_name="report.csv")

@app.route("/report/json")
def json_report():
    conn = sqlite3.connect(DB)
    rows = conn.execute("SELECT * FROM threats").fetchall()
    conn.close()
    return jsonify(rows)

# ------------------ RUN ------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT",5000))
    app.run(host="0.0.0.0", port=port)

# ------------------ DASHBOARD TEMPLATE ------------------
TEMPLATE = """
<html>
<body style='background:#0a1f44;color:white;font-family:Arial;margin:0 auto;max-width:1200px;'>

<h1 style='color:crimson;text-align:center;'>
REDSHAK CYBER THREATS INTELLIGENCE DASHBOARD
</h1>

<p style='text-align:center;font-size:18px;'>
SecureNation Index: <b>{{ index }}</b>
</p>

<p style='text-align:center;'>{{ summary }}</p>

<div style='text-align:center;'>{{ map_html|safe }}</div>

<div style='text-align:center;'>
<img src="data:image/png;base64,{{ trend }}">
</div>

<div style='text-align:center;'>
<img src="data:image/png;base64,{{ type_chart_img }}">
</div>

<h3 style='text-align:center;'>Total Indicators: {{ total }}</h3>

<table border=1 width=100% style='border-collapse:collapse;text-align:center;'>
<tr style='background:#001f3f;color:white;'>
<th>Pulse</th>
<th>Indicator</th>
<th>Type</th>
<th>Classification</th>
<th>MITRE</th>
<th>Risk Score</th>
<th>Created</th>
</tr>
{% for r in data %}
<tr style='background:#1a2d5a;color:white;'>
<td>{{ r[0] }}</td>
<td>{{ r[1] }}</td>
<td>{{ r[2] }}</td>
<td>{{ r[3] }}</td>
<td>{{ r[4] }}</td>
<td>{{ r[5] }}</td>
<td>{{ r[6] }}</td>
</tr>
{% endfor %}
</table>

<p style='text-align:center;'>{{ disclaimer }}</p>

<p style='text-align:center;'>
<a href='/report/pdf'>PDF</a> |
<a href='/report/csv'>CSV</a> |
<a href='/report/json'>JSON</a>
</p>

</body>
</html>
"""
