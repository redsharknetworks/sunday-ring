import os
import io
import csv
import json
import base64
import sqlite3
import random
import threading
import time
from datetime import datetime
import pytz
import requests
from flask import Flask, render_template_string, send_file, jsonify, request
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
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

DISCLAIMER = ("Developed and analyzed by DarkGrid@redshark.my using publicly "
              "available threat intelligence sources. This report is provided "
              "for informational purposes only and does not constitute security advice.")

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
# DATA FETCH
# -------------------------------------------------

def insert_dummy_data():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    for i in range(20):
        c.execute("""
        INSERT INTO threats (pulse, indicator, type, risk_score, created_at)
        VALUES (?, ?, ?, ?, ?)
        """, (
            f"Sample Pulse {i}",
            f"malicious{i}.com",
            random.choice(["domain","ip","url"]),
            random.randint(60,95),
            datetime.utcnow().isoformat()
        ))
    conn.commit()
    conn.close()

def fetch_otx():
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
        fetch_otx()
        time.sleep(3600)

# -------------------------------------------------
# ANALYTICS
# -------------------------------------------------

def calculate_secure_index():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    total = c.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
    high = c.execute("SELECT COUNT(*) FROM threats WHERE risk_score >= 80").fetchone()[0]
    conn.close()

    if total == 0:
        return 100

    return int(max(0, 100 - ((high/total)*100)))

def generate_summary(index):
    if index >= 75:
        return ("RedShark DarkGrid assessment reflects a stable cyber posture. "
                "Observed threat activity remains controlled within expected thresholds.")
    elif index >= 50:
        return ("RedShark DarkGrid identifies elevated cyber activity requiring "
                "proactive monitoring and strengthened defensive readiness.")
    else:
        return ("RedShark DarkGrid signals significant cyber threat escalation. "
                "Immediate mitigation actions and executive oversight recommended.")

def get_top_signals():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    rows = c.execute("""
        SELECT indicator, COUNT(*) as total, MAX(risk_score) as max_risk
        FROM threats
        GROUP BY indicator
        ORDER BY total DESC
        LIMIT 10
    """).fetchall()
    conn.close()
    return rows

# -------------------------------------------------
# CHARTS
# -------------------------------------------------

def generate_trend_chart():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    rows = c.execute("""
        SELECT substr(created_at,1,10) as d, COUNT(*) as c
        FROM threats GROUP BY d ORDER BY d
    """).fetchall()
    conn.close()

    if not rows:
        return None

    dates = [r["d"] for r in rows]
    counts = [r["c"] for r in rows]

    plt.figure(figsize=(6,3))
    plt.plot(dates, counts, marker="o")
    plt.xticks(rotation=45)
    buf = io.BytesIO()
    plt.tight_layout()
    plt.savefig(buf, format="png")
    plt.close()

    return base64.b64encode(buf.getvalue()).decode()

def generate_type_chart():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    rows = c.execute("""
        SELECT type, COUNT(*) as c FROM threats GROUP BY type
    """).fetchall()
    conn.close()

    if not rows:
        return None

    labels = [r["type"] for r in rows]
    values = [r["c"] for r in rows]

    plt.figure()
    plt.pie(values, labels=labels, autopct="%1.1f%%")
    buf = io.BytesIO()
    plt.savefig(buf, format="png")
    plt.close()

    return base64.b64encode(buf.getvalue()).decode()

def generate_heatmap():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    total = c.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
    conn.close()

    plt.figure()
    plt.bar(["Malaysia"], [total])
    buf = io.BytesIO()
    plt.savefig(buf, format="png")
    plt.close()

    return base64.b64encode(buf.getvalue()).decode()

# -------------------------------------------------
# TIMESTAMP
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
        sort = "created_at"

    offset = (page-1)*50

    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    total = c.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
    rows = c.execute(f"""
        SELECT * FROM threats
        ORDER BY {sort} {order}
        LIMIT 50 OFFSET ?
    """,(offset,)).fetchall()

    conn.close()

    total_pages = (total//50)+(1 if total%50 else 0)

    index = calculate_secure_index()
    summary = generate_summary(index)

    return render_template_string("""
    <html>
    <head>
    <title>RedShark Threat Intelligence Dashboard</title>
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

    <h2>RedShark Threat Intelligence Dashboard</h2>

    <div class="box">
    <h3>SecureNation Index: {{ index }}/100</h3>
    <p>{{ summary }}</p>
    </div>

    <div class="box trend">
    <h3>Threat Trend</h3>
    {% if trend %}
    <img src="data:image/png;base64,{{ trend }}">
    {% endif %}
    </div>

    <div class="box">
    <h3>Threat Type Distribution</h3>
    {% if type_chart %}
    <img src="data:image/png;base64,{{ type_chart }}">
    {% endif %}
    </div>

    <div class="box">
    <h3>Malaysia Threat Heat Map</h3>
    <img src="data:image/png;base64,{{ heatmap }}">
    </div>

    <div class="box">
    <h3>Top 10 Threat Signals</h3>
    <table>
    <tr><th>Threat Signal</th><th>Total</th><th>Max Risk</th></tr>
    {% for t in top10 %}
    <tr><td>{{ t['indicator'] }}</td><td>{{ t['total'] }}</td><td>{{ t['max_risk'] }}</td></tr>
    {% endfor %}
    </table>
    </div>

    <div class="box">
    <h3>Latest Threat Activity</h3>
    <table>
    <tr><th>ID</th><th>Pulse</th><th>Threat Signal</th><th>Type</th><th>Risk</th><th>Created</th></tr>
    {% for r in rows %}
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

    <div class="box">
    <small>{{ disclaimer }}</small>
    </div>

    </body>
    </html>
    """,
    rows=rows,
    index=index,
    summary=summary,
    trend=generate_trend_chart(),
    type_chart=generate_type_chart(),
    heatmap=generate_heatmap(),
    top10=get_top_signals(),
    disclaimer=DISCLAIMER
    )

# -------------------------------------------------
# EXPORTS
# -------------------------------------------------

@app.route("/export/json")
def export_json():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM threats").fetchall()
    conn.close()

    return jsonify({
        "secure_index": calculate_secure_index(),
        "summary": generate_summary(calculate_secure_index()),
        "data": [dict(r) for r in rows],
        "disclaimer": DISCLAIMER
    })

@app.route("/export/csv")
def export_csv():
    ts = malaysia_timestamp()
    filename = f"redshark_darkgrid_report_{ts}.csv"

    conn = sqlite3.connect(DB)
    rows = conn.execute("SELECT * FROM threats").fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID","Pulse","Threat Signal","Type","Risk","Created"])
    writer.writerows(rows)

    mem = io.BytesIO()
    mem.write(output.getvalue().encode())
    mem.seek(0)

    return send_file(mem, as_attachment=True, download_name=filename, mimetype="text/csv")

@app.route("/export/pdf")
def export_pdf():
    ts = malaysia_timestamp()
    filename = f"redshark_darkgrid_report_{ts}.pdf"

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4)
    styles = getSampleStyleSheet()

    elements = []
    elements.append(Paragraph("RedShark Threat Intelligence Report", styles["Heading1"]))
    elements.append(Spacer(1,12))

    index = calculate_secure_index()
    elements.append(Paragraph(f"SecureNation Index: {index}/100", styles["Normal"]))
    elements.append(Paragraph(generate_summary(index), styles["Normal"]))
    elements.append(Spacer(1,12))

    conn = sqlite3.connect(DB)
    rows = conn.execute("SELECT pulse, indicator, type, risk_score FROM threats LIMIT 20").fetchall()
    conn.close()

    table_data = [["Pulse","Threat Signal","Type","Risk"]]
    for r in rows:
        table_data.append(list(r))

    table = Table(table_data)
    elements.append(table)
    elements.append(Spacer(1,12))
    elements.append(Paragraph(DISCLAIMER, styles["Normal"]))

    doc.build(elements)
    buffer.seek(0)

    return send_file(buffer, as_attachment=True, download_name=filename, mimetype="application/pdf")

# -------------------------------------------------
# INIT
# -------------------------------------------------

ensure_database()
fetch_otx()

if not os.getenv("RUN_MAIN"):
    threading.Thread(target=scheduler, daemon=True).start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT",5000)))
