import os
import io
import sqlite3
import random
from datetime import datetime, timedelta
import asyncio

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from OTXv2 import OTXv2
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
plt.rcParams['font.sans-serif'] = ['DejaVu Sans']
plt.rcParams['axes.unicode_minus'] = False
import base64
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image as RLImage
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
import csv

# ---------------- FastAPI Setup ----------------
app = FastAPI()
templates = Jinja2Templates(directory="templates")
DB = "threats.db"

# ---------------- OTX Setup ----------------
OTX_KEY = os.getenv("OTX_KEY")
otx = OTXv2(OTX_KEY) if OTX_KEY else None
if not OTX_KEY:
    print("⚠️ WARNING: OTX_KEY not set. Using dummy data.")

# ---------------- Database ----------------
def ensure_database():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS threats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pulse TEXT,
            indicator TEXT UNIQUE,
            type TEXT,
            classification TEXT,
            mitre TEXT,
            risk_score INTEGER,
            created_at TEXT
        )
    """)
    conn.commit()
    conn.close()

# ---------------- OTX Fetch (Async) ----------------
async def fetch_otx_loop():
    while True:
        try:
            await fetch_otx_data()
        except Exception as e:
            print("OTX fetch error:", e)
        await asyncio.sleep(3600)  # every hour

async def fetch_otx_data():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    created = datetime.utcnow().isoformat()

    # OTX fetch
    if otx:
        try:
            pulses = otx.getall(limit=10)
            for pulse in pulses:
                name = pulse.get("name","OTX")
                for ind in pulse.get("indicators", []):
                    val = ind.get("indicator")
                    typ = ind.get("type","domain")
                    if not val: continue
                    score = random.randint(50,95)
                    try:
                        c.execute(
                            "INSERT OR IGNORE INTO threats (pulse,indicator,type,classification,mitre,risk_score,created_at) VALUES (?,?,?,?,?,?,?)",
                            (name,val,typ,"Medium","OTX",score,created)
                        )
                    except: pass
        except Exception as e:
            print("OTX fetch error:", e)

    # Dummy data if empty
    count = c.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
    if count == 0:
        dummy_pulses = ["Red Shark Attack","Silent Hunter","Ghost Spider","Dark Wave","Cyber Kraken","Phantom Tiger"]
        dummy_types = ["IPv4","domain","URL","FileHash-MD5","FileHash-SHA256"]
        for _ in range(100):
            pulse = random.choice(dummy_pulses)
            indicator = f"dummy-{random.randint(1000,9999)}.com"
            typ = random.choice(dummy_types)
            score = random.randint(50,95)
            created = datetime.utcnow().isoformat()
            try:
                c.execute(
                    "INSERT OR IGNORE INTO threats (pulse,indicator,type,classification,mitre,risk_score,created_at) VALUES (?,?,?,?,?,?,?)",
                    (pulse,indicator,typ,random.choice(["Low","Medium","High"]),"N/A",score,created)
                )
            except: pass

    conn.commit()
    conn.close()

# ---------------- Chart Helpers ----------------
def plot_chart_to_base64(fig):
    buf = io.BytesIO()
    fig.savefig(buf, format="png", bbox_inches="tight")
    plt.close(fig)
    buf.seek(0)
    return base64.b64encode(buf.getvalue()).decode()

def generate_charts():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    charts = {}

    # Trend chart
    trend_data = c.execute("SELECT date(created_at), COUNT(*) FROM threats GROUP BY date(created_at) ORDER BY date(created_at)").fetchall()
    if trend_data:
        dates = [x[0] for x in trend_data]
        counts = [x[1] for x in trend_data]
        fig, ax = plt.subplots(figsize=(6,3), dpi=100)
        if os.path.exists("boxing_ring.png"):
            try:
                bg = plt.imread("boxing_ring.png")
                ax.imshow(bg, extent=[0,len(dates)-1,0,max(counts)+5], aspect='auto', alpha=0.2)
            except: pass
        ax.plot(dates, counts, marker="o", color="crimson")
        ax.set_title("Threat Trend")
        plt.xticks(rotation=45)
        charts["trend"] = plot_chart_to_base64(fig)

    # Type chart
    type_data = c.execute("SELECT type, COUNT(*) FROM threats GROUP BY type").fetchall()
    if type_data:
        labels = [x[0] for x in type_data]
        values = [x[1] for x in type_data]
        fig, ax = plt.subplots(figsize=(4,3), dpi=100)
        ax.bar(labels, values, color="darkblue")
        ax.set_title("Indicator Types")
        charts["type_chart"] = plot_chart_to_base64(fig)

    # Top 10 pulses
    top10_data = c.execute("SELECT pulse, COUNT(*) FROM threats GROUP BY pulse ORDER BY COUNT(*) DESC LIMIT 10").fetchall()
    if top10_data:
        pulses = [x[0] for x in top10_data]
        counts = [x[1] for x in top10_data]
        fig, ax = plt.subplots(figsize=(6,3), dpi=100)
        ax.barh(pulses[::-1], counts[::-1], color="red")
        ax.set_title("Top 10 Threat Pulses")
        charts["top10"] = plot_chart_to_base64(fig)

    # Malaysia heatmap
    cities = [
        (3.1390,101.6869),(1.4927,103.7414),(5.4164,100.3327),(2.1896,102.2501),
        (6.1254,102.2381),(2.9216,101.6509),(2.9264,101.6998),(1.5533,110.3592),
        (5.9804,116.0735),(6.1203,100.3660),(5.3289,103.1403),(4.5975,101.0901),
        (6.4383,100.2002),(3.8070,103.3255),(2.7295,101.9385)  # Seremban
    ]
    lats,lons = zip(*cities)
    fig, ax = plt.subplots(figsize=(6,6), dpi=100)
    ax.scatter(lons,lats,s=100,c="red",alpha=0.6)
    ax.set_title("Malaysia Threat Heatmap")
    charts["heatmap"] = plot_chart_to_base64(fig)

    conn.close()
    return charts

# ---------------- Dashboard ----------------
TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>DarkGrid Dashboard</title></head>
<body>
<h1>DarkGrid Threat Dashboard</h1>
{% if charts.trend %}<img src="data:image/png;base64,{{ charts.trend }}"><br>{% endif %}
{% if charts.type_chart %}<img src="data:image/png;base64,{{ charts.type_chart }}"><br>{% endif %}
{% if charts.top10 %}<img src="data:image/png;base64,{{ charts.top10 }}"><br>{% endif %}
{% if charts.heatmap %}<img src="data:image/png;base64,{{ charts.heatmap }}"><br>{% endif %}
<br>
<a href="/report/pdf">PDF</a> |
<a href="/report/csv">CSV</a> |
<a href="/report/json">JSON</a>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    charts = generate_charts()
    return templates.TemplateResponse(TEMPLATE, {"request": request, "charts": charts})

# ---------------- Reports ----------------
@app.get("/report/csv")
async def csv_report():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    data = c.execute("SELECT * FROM threats").fetchall()
    conn.close()
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(["ID","Pulse","Indicator","Type","Class","MITRE","Risk","Created"])
    cw.writerows(data)
    output = io.BytesIO()
    output.write(si.getvalue().encode())
    output.seek(0)
    return StreamingResponse(output, media_type="text/csv", headers={"Content-Disposition":"attachment; filename=report.csv"})

@app.get("/report/json")
async def json_report():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    data = c.execute("SELECT * FROM threats").fetchall()
    conn.close()
    return JSONResponse([dict(x) for x in data])

@app.get("/report/pdf")
async def pdf_report():
    charts = generate_charts()
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer,pagesize=letter)
    styles = getSampleStyleSheet()
    elements = [Paragraph("Threat Intelligence Report", styles["Title"]), Spacer(1,12)]
    for key in ["trend","type_chart","top10","heatmap"]:
        if charts.get(key):
            img = io.BytesIO(base64.b64decode(charts[key]))
            elements.append(RLImage(img, width=420, height=200))
            elements.append(Spacer(1,12))
    doc.build(elements)
    buffer.seek(0)
    return StreamingResponse(buffer, media_type="application/pdf", headers={"Content-Disposition":"attachment; filename=report.pdf"})

# ---------------- Startup ----------------
ensure_database()
# Start OTX fetch background task
if otx:
    loop = asyncio.get_event_loop()
    loop.create_task(fetch_otx_loop())
else:
    # Populate dummy data immediately
    import asyncio
    asyncio.run(fetch_otx_data())

# ---------------- Notes for Railway ----------------
# Run with:
#   gunicorn main:app -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:$PORT --workers 1
