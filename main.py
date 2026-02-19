import os
import io
import csv
import base64
import sqlite3
import threading
import time
import random
from datetime import datetime
import pytz
import requests
from flask import Flask, render_template_string, send_file, jsonify, request
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import A4
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# -------------------------------------------------
# CONFIG
# -------------------------------------------------

app = Flask(__name__, static_folder="static")
DB = os.getenv("DB_PATH", "/tmp/threats.db")
OTX_KEY = os.getenv("OTX_KEY")
OTX_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"

SORTABLE_COLUMNS = ["id","pulse","indicator","type","risk_score","created_at"]

# -------------------------------------------------
# DATABASE
# -------------------------------------------------

def ensure_database():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS threats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pulse TEXT,
        indicator TEXT,
        type TEXT,
        risk_score INTEGER,
        created_at TEXT
    )
    """)
    conn.commit()
    conn.close()

# -------------------------------------------------
# DUMMY DATA
# -------------------------------------------------

def insert_dummy_data():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    for i in range(10):
        c.execute("""
        INSERT INTO threats (pulse, indicator, type, risk_score, created_at)
        VALUES (?, ?, ?, ?, ?)
        """, (
            f"Dummy Pulse {i}",
            f"malicious{i}.com",
            "domain",
            random.randint(60,95),
            datetime.utcnow().isoformat()
        ))
    conn.commit()
    conn.close()

# -------------------------------------------------
# OTX FETCH
# -------------------------------------------------

def fetch_otx_data():
    ensure_database()

    if not OTX_KEY:
        insert_dummy_data()
        return

    headers = {"X-OTX-API-KEY": OTX_KEY}

    try:
        r = requests.get(OTX_URL, headers=headers, timeout=15)
        r.raise_for_status()
        pulses = r.json().get("results", [])
    except:
        insert_dummy_data()
        return

    conn = sqlite3.connect(DB)
    c = conn.cursor()

    for pulse in pulses[:10]:
        name = pulse.get("name","OTX Pulse")
        indicators = pulse.get("indicators",[])

        for ind in indicators:
            val = ind.get("indicator")
            typ = ind.get("type","domain")

            if not val:
                continue

            c.execute("""
            INSERT INTO threats (pulse, indicator, type, risk_score, created_at)
            VALUES (?, ?, ?, ?, ?)
            """, (
                name,
                val,
                typ,
                random.randint(60,95),
                datetime.utcnow().isoformat()
            ))

    conn.commit()
    conn.close()

def scheduler():
    while True:
        fetch_otx_data()
        time.sleep(3600)

# -------------------------------------------------
# SECURE NATION INDEX
# -------------------------------------------------

def calculate_secure_index():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    total = c.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
    high = c.execute("SELECT COUNT(*) FROM threats WHERE risk_score >= 80").fetchone()[0]
    conn.close()

    if total == 0:
        return 100

    ratio = high/total
    return int(max(0,100-(ratio*100)))

def generate_summary(index):
    if index >= 75:
        return ("RedShark DarkGrid assessment reflects a stable cyber posture. "
                "Observed threat activity remains controlled within expected operational thresholds.")
    elif index >= 50:
        return ("RedShark DarkGrid assessment identifies elevated cyber activity "
                "requiring proactive monitoring and strengthened defensive readiness.")
    else:
        return ("RedShark DarkGrid assessment signals significant cyber threat escalation. "
                "Immediate mitigation actions and executive-level oversight are recommended.")

# -------------------------------------------------
# TOP 10 THREAT SIGNALS
# -------------------------------------------------

def get_top_signals():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    rows = c.execute("""
        SELECT indicator, COUNT(*) as total,
               MAX(risk_score) as max_risk
        FROM threats
        GROUP BY indicator
        ORDER BY total DESC
        LIMIT 10
    """).fetchall()
    conn.close()
    return rows

# -------------------------------------------------
# TREND CHART
# -------------------------------------------------

def generate_trend_chart():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    rows = c.execute("""
        SELECT substr(created_at,1,10) as d, COUNT(*) as c
        FROM threats
        GROUP BY d
        ORDER BY d
    """).fetchall()
    conn.close()

    if not rows:
        return None

    dates = [r["d"] for r in rows]
    counts = [r["c"] for r in rows]

    plt.figure(figsize=(6,3))
    plt.plot(dates,counts,marker="o")
    plt.xticks(rotation=45)
    buf = io.BytesIO()
    plt.tight_layout()
    plt.savefig(buf,format="png")
    plt.close()

    return base64.b64encode(buf.getvalue()).decode()

# -------------------------------------------------
# MALAYSIA TIMESTAMP
# -------------------------------------------------

def malaysia_timestamp():
    tz = pytz.timezone("Asia/Kuala_Lumpur")
    return datetime.now(tz).strftime("%Y%m%d_%H%M%S")

# -------------------------------------------------
# DASHBOARD
# -------------------------------------------------

@app.route("/")
def dashboard():

    page = int(request.args.get("page",1))
    sort = request.args.get("sort","created_at")
    order = request.args.get("order","DESC")

    if sort not in SORTABLE_COLUMNS:
        sort="created_at"

    offset=(page-1)*50

    conn=sqlite3.connect(DB)
    conn.row_factory=sqlite3.Row
    c=conn.cursor()

    total=c.execute("SELECT COUNT(*) FROM threats").fetchone()[0]

    rows=c.execute(f"""
        SELECT * FROM threats
        ORDER BY {sort} {order}
        LIMIT 50 OFFSET ?
    """,(offset,)).fetchall()

    conn.close()

    total_pages=(total//50)+(1 if total%50 else 0)

    index=calculate_secure_index()
    summary=generate_summary(index)
    trend=generate_trend_chart()
    top10=get_top_signals()

    TEMPLATE = """
    <html>
    <head>
    <title>RedShark Cyber Threat Intelligence Dashboard</title>
    <style>
    body { background:#0b1c2d; color:white; font-family:Arial; padding:20px;}
    h2 { color:#ff8c00; }
    .box { background:#132f4c; padding:20px; margin-bottom:20px; border-radius:8px;}
    table { width:100%; border-collapse:collapse;}
    th { background:#ff8c00; color:black; padding:8px;}
    td { padding:8px; border-bottom:1px solid #1f4068;}
    .trend { background:url('/static/boxing_ring.png'); background-size:cover; padding:20px;}
    </style>
    </head>
    <body>

    <h2>RedShark DarkGrid Dashboard</h2>

    <div class="box">
    <h3>SecureNation Index: {{ secure_index }}/100</h3>
    <p>{{ summary }}</p>
    </div>

    <div class="box trend">
    <h3>Threat Trend</h3>
    {% if trend %}
    <img src="data:image/png;base64,{{ trend }}">
    {% else %}
    <p>No trend data available</p>
    {% endif %}
    </div>

    <div class="box">
    <h3>Top 10 Threat Signals</h3>
    <table>
    <tr><th>Threat Signal</th><th>Total</th><th>Max Risk</th></tr>
    {% for t in top10 %}
    <tr>
    <td>{{ t['indicator'] }}</td>
    <td>{{ t['total'] }}</td>
    <td>{{ t['max_risk'] }}</td>
    </tr>
    {% endfor %}
    </table>
    </div>

    <div class="box">
    <h3>Latest Threat Activity</h3>
    <table>
    <tr>
    <th>ID</th><th>Pulse</th><th>Threat Signal</th>
    <th>Type</th><th>Risk</th><th>Created</th>
    </tr>
    {% for r in table_data %}
    <tr>
    <td>{{ r['id'] }}</td>
    <td>{{ r['pulse'] }}</td>
    <td>{{ r['indicator'] }}</td>
    <td>{{ r['type'] }}</td>
    <td>{{ r['risk_score'] }}</td>
    <td>{{ r['created_at'] }}</td>
    </tr>
    {% endfor %}
    </table>
    </div>

    </body>
    </html>
    """

    return render_template_string(
        TEMPLATE,
        table_data=rows,
        secure_index=index,
        summary=summary,
        trend=trend,
        top10=top10
    )

# -------------------------------------------------
# EXPORT ROUTES
# -------------------------------------------------

@app.route("/export/csv")
def export_csv():
    ts=malaysia_timestamp()
    filename=f"redshark_darkgrid_report_{ts}.csv"
    conn=sqlite3.connect(DB)
    rows=conn.execute("SELECT * FROM threats").fetchall()
    conn.close()

    si=io.StringIO()
    writer=csv.writer(si)
    writer.writerow(["ID","Pulse","Threat Signal","Type","Risk","Created"])
    writer.writerows(rows)

    output=io.BytesIO()
    output.write(si.getvalue().encode())
    output.seek(0)
    return send_file(output,as_attachment=True,download_name=filename,mimetype="text/csv")

@app.route("/export/json")
def export_json():
    conn=sqlite3.connect(DB)
    conn.row_factory=sqlite3.Row
    rows=conn.execute("SELECT * FROM threats").fetchall()
    conn.close()

    return jsonify({
        "secure_index":calculate_secure_index(),
        "summary":generate_summary(calculate_secure_index()),
        "data":[dict(r) for r in rows]
    })

@app.route("/export/pdf")
def export_pdf():
    ts=malaysia_timestamp()
    filename=f"redshark_darkgrid_report_{ts}.pdf"
    buffer=io.BytesIO()
    doc=SimpleDocTemplate(buffer,pagesize=A4)
    styles=getSampleStyleSheet()
    elements=[]
    index=calculate_secure_index()

    elements.append(Paragraph("RedShark DarkGrid Report",styles["Heading1"]))
    elements.append(Spacer(1,12))
    elements.append(Paragraph(f"SecureNation Index: {index}",styles["Normal"]))
    elements.append(Paragraph(generate_summary(index),styles["Normal"]))
    doc.build(elements)
    buffer.seek(0)

    return send_file(buffer,as_attachment=True,download_name=filename,mimetype="application/pdf")

# -------------------------------------------------
# INIT
# -------------------------------------------------

ensure_database()
fetch_otx_data()

if not os.getenv("RUN_MAIN"):
    threading.Thread(target=scheduler,daemon=True).start()

if __name__=="__main__":
    app.run(host="0.0.0.0",port=int(os.getenv("PORT",5000)))
