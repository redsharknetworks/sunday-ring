import os, sqlite3, io, base64, csv, json, requests
from datetime import datetime
from flask import Flask, request, render_template_string, Response
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from folium import Map
from folium.plugins import HeatMap
from reportlab.pdfgen import canvas

app = Flask(__name__)
DB = "threats.db"
PAGE_SIZE = 50
DISCLAIMER = "Information and analysis developed from publicly available sources by DarkGrid (darkgrid@redshark.my)."

# ---------------- OTX CONFIG ----------------
OTX_API_KEY = os.environ.get("OTX_API_KEY")
OTX_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"

# ---------------- DB INIT ----------------
def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS threats(
        id INTEGER PRIMARY KEY,
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
    CREATE TABLE IF NOT EXISTS threat_hashes(
        id INTEGER PRIMARY KEY,
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

# ---------------- ANALYTICS ----------------
def risk_index():
    conn = sqlite3.connect(DB)
    rows = conn.execute("SELECT risk_score FROM threats").fetchall()
    conn.close()
    if not rows:
        return 0
    return int(sum(r[0] for r in rows)/len(rows))

def executive_summary():
    conn = sqlite3.connect(DB)
    total = conn.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
    high = conn.execute("SELECT COUNT(*) FROM threats WHERE risk_score >=70").fetchone()[0]
    top_mitre = conn.execute("SELECT mitre, COUNT(*) FROM threats GROUP BY mitre ORDER BY COUNT(*) DESC LIMIT 1").fetchone()
    conn.close()
    mitre_text = top_mitre[0] if top_mitre else "N/A"
    return f"""
REDSHARK.MY identified {total} active indicators this week.
{high} were rated High or Critical risk.
Dominant technique observed: {mitre_text}.
SecureNation Index currently at {risk_index()}.
"""

# ---------------- OTX FETCH ----------------
def fetch_otx():
    if not OTX_API_KEY:
        print("OTX API key not found in environment.")
        return
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    try:
        r = requests.get(OTX_URL, headers=headers, timeout=30)
        if r.status_code != 200:
            print(f"OTX fetch failed: {r.status_code}")
            return
        data = r.json().get("results", [])
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        for pulse in data:
            pulse_name = pulse.get("name","OTX Pulse")
            for ind in pulse.get("indicators",[]):
                value = ind.get("indicator")
                itype = ind.get("type")
                if not value:
                    continue
                score = 50
                mitre = "T1071"
                if "FileHash" in itype:
                    c.execute("""
                        INSERT INTO threat_hashes(pulse,hash,classification,mitre,risk_score,created_at)
                        VALUES (?,?,?,?,?,?)
                    """,(pulse_name,value,"Medium",mitre,score,datetime.utcnow().isoformat()))
                else:
                    c.execute("""
                        INSERT INTO threats(pulse,indicator,type,classification,mitre,risk_score,created_at)
                        VALUES (?,?,?,?,?,?,?)
                    """,(pulse_name,value,itype,"Medium",mitre,score,datetime.utcnow().isoformat()))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"OTX fetch exception: {e}")

# ---------------- TREND CHART ----------------
def boxing_bg(ax,max_y,count):
    try:
        img = plt.imread("boxing_ring.png")
        ax.imshow(img, extent=[-1,count,0,max_y*1.2], alpha=0.25, aspect="auto")
    except:
        pass

def trend_chart():
    conn = sqlite3.connect(DB)
    rows = conn.execute("SELECT substr(created_at,1,10), COUNT(*) FROM threats GROUP BY 1").fetchall()
    conn.close()
    dates = [r[0] for r in rows]
    counts = [r[1] for r in rows]
    fig, ax = plt.subplots(figsize=(8,3))
    ax.set_facecolor("#2b2b2b")
    fig.patch.set_facecolor("#2b2b2b")
    if counts:
        boxing_bg(ax,max(counts)+5,len(dates))
        ax.plot(dates, counts, color="crimson", marker="o", linewidth=2)
        ax.fill_between(dates, counts, color="crimson", alpha=0.15)
    ax.set_title("Total Indicators Trend", color="white")
    ax.tick_params(colors="white")
    img = io.BytesIO()
    plt.savefig(img, format="png", bbox_inches="tight")
    img.seek(0)
    plt.close()
    return base64.b64encode(img.read()).decode()

# ---------------- TYPE CHART ----------------
def type_chart():
    conn = sqlite3.connect(DB)
    rows = conn.execute("SELECT type, COUNT(*) FROM threats GROUP BY type").fetchall()
    conn.close()
    labels = [r[0] for r in rows]
    counts = [r[1] for r in rows]
    fig, ax = plt.subplots(figsize=(8,3))
    ax.set_facecolor("#2b2b2b")
    fig.patch.set_facecolor("#2b2b2b")
    if counts:
        ax.bar(labels, counts, color="orange", alpha=0.9)
    ax.set_title("Indicator Types", color="white")
    ax.tick_params(colors="white")
    img = io.BytesIO()
    plt.savefig(img, format="png", bbox_inches="tight")
    img.seek(0)
    plt.close()
    return base64.b64encode(img.read()).decode()

# ---------------- HEAT MAP ----------------
def generate_map():
    m = Map(location=[4.21,101.97], zoom_start=6)
    heat = [[3.139,101.6869,5],[1.49,103.74,4],[5.41,100.33,3]]
    HeatMap(heat).add_to(m)
    return m._repr_html_()

# ---------------- DASHBOARD ----------------
@app.route("/")
def dashboard():
    page = int(request.args.get("page",1))
    sort = request.args.get("sort","risk_score")
    offset = (page-1)*PAGE_SIZE
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(f"SELECT * FROM threats ORDER BY {sort} DESC LIMIT ? OFFSET ?",(PAGE_SIZE,offset)).fetchall()
    conn.close()
    return render_template_string("""
<body style="background:#0a1f44;color:white;font-family:Arial;">
<h2 style="text-align:center;">RedShark Cyber Threat Intelligent Dashboard</h2>
<div style="text-align:center;">
    <img src="data:image/png;base64,{{trend}}"/><br>
    <img src="data:image/png;base64,{{type}}"/><br>
    {{ map_html|safe }}
</div>
<h3 style="text-align:center;">SecureNation Index: {{risk}}</h3>
<p style="text-align:center;">{{summary}}</p>
<table border=1 align=center width="80%">
<tr><th>Pulse</th><th>Indicator</th><th>Type</th><th>Risk</th></tr>
{% for r in rows %}
<tr><td>{{r.pulse}}</td><td>{{r.indicator}}</td><td>{{r.type}}</td><td>{{r.risk_score}}</td></tr>
{% endfor %}
</table>
<p style="text-align:center;margin-top:20px;">{{disc}}</p>
</body>
""", rows=rows, trend=trend_chart(), type=type_chart(),
   map_html=generate_map(), disc=DISCLAIMER, risk=risk_index(), summary=executive_summary())

# ---------------- REPORTS ----------------
@app.route("/report/csv")
def csv_report():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM threats").fetchall()
    hash_rows = conn.execute("SELECT * FROM threat_hashes").fetchall()
    conn.close()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID","Pulse","Indicator","Type","Classification","MITRE","Risk","Created"])
    for r in rows:
        writer.writerow(list(r))
    writer.writerow([])
    writer.writerow(["HASH Indicators"])
    writer.writerow(["ID","Pulse","Hash","Classification","MITRE","Risk","Created"])
    for r in hash_rows:
        writer.writerow(list(r))
    return Response(output.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition":"attachment; filename=darkgridatredsharkdotmy.csv"})

@app.route("/report/json")
def json_report():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM threats").fetchall()
    hash_rows = conn.execute("SELECT * FROM threat_hashes").fetchall()
    conn.close()
    data = [dict(r) for r in rows] + [dict(r) for r in hash_rows]
    return Response(json.dumps(data,indent=2), mimetype="application/json",
                    headers={"Content-Disposition":"attachment; filename=darkgridatredsharkdotmy.json"})

@app.route("/report/pdf")
def pdf_report():
    buf = io.BytesIO()
    c = canvas.Canvas(buf,pagesize=(612,792))
    # Executive summary
    y = 750
    for line in executive_summary().split("\n"):
        c.drawString(50,y,line.strip())
        y -= 20
    y -= 20
    conn = sqlite3.connect(DB)
    # Top 10 normal indicators
    rows = conn.execute("SELECT indicator,risk_score FROM threats ORDER BY risk_score DESC LIMIT 10").fetchall()
    # Top 10 hash indicators
    hash_rows = conn.execute("SELECT hash,risk_score FROM threat_hashes ORDER BY risk_score DESC LIMIT 10").fetchall()
    conn.close()
    c.drawString(50,y,"Weekly Top 10 Threats (Indicators)")
    y -= 20
    for r in rows:
        c.drawString(50,y,f"{r[0]} - {r[1]}")
        y -= 20
    y -= 20
    c.drawString(50,y,"Weekly Top 10 Hash Threats")
    y -= 20
    for r in hash_rows:
        c.drawString(50,y,f"{r[0]} - {r[1]}")
        y -= 20
    c.drawString(50,50,DISCLAIMER)
    c.save()
    buf.seek(0)
    return Response(buf,mimetype="application/pdf",
                    headers={"Content-Disposition":"attachment; filename=darkgridatredsharkdotmy.pdf"})

# ---------------- MAIN ----------------
if __name__=="__main__":
    init_db()
    fetch_otx()
    app.run(host="0.0.0.0", port=5000)
