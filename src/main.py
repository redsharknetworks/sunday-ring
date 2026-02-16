import os
import sqlite3
import requests
import io
import csv
from datetime import datetime, timedelta
from flask import Flask, jsonify, request, render_template_string, send_file
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, Image
from reportlab.lib import colors, pagesizes
from reportlab.lib.styles import getSampleStyleSheet
import urllib.request

# ==========================================================
# Flask App
# ==========================================================
app = Flask(__name__)

# ==========================================================
# Configuration
# ==========================================================
OTX_API_KEY = os.environ.get("OTX_API_KEY")
if not OTX_API_KEY:
    raise RuntimeError("OTX_API_KEY environment variable is required!")

ADMIN_KEY = os.environ.get("ADMIN_KEY")
DATABASE_FILE = "threat_intel.db"

REPORT_TITLE = "Sunday Ring With Red Shark - Top 10 Malaysia Weekly Threat Intelligence Report"
CONTACT_EMAIL = "darkgrid@redshark.my"

# ==========================================================
# Malaysia Targeting Rules
# ==========================================================
MALAYSIA_KEYWORDS = [
    "malaysia", "maybank", "cimb", "bank negara",
    "petronas", ".my", "gov.my", "edu.my"
]

THREAT_SCORES = {
    "keyword": 3,
    "my_domain": 4
}

# ==========================================================
# Database Setup
# ==========================================================
def init_db():
    conn = sqlite3.connect(DATABASE_FILE)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS malaysia_targeted_threats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator TEXT UNIQUE,
            indicator_type TEXT,
            pulse_name TEXT,
            pulse_description TEXT,
            pulse_author TEXT,
            pulse_created TEXT,
            threat_score INTEGER
        )
    """)
    conn.commit()
    conn.close()

init_db()

def get_db():
    conn = sqlite3.connect(DATABASE_FILE)
    conn.row_factory = sqlite3.Row
    return conn

# ==========================================================
# OTX Fetch
# ==========================================================
def fetch_otx_pulses(limit=100):
    headers = {
        "X-OTX-API-KEY": OTX_API_KEY,
        "Accept": "application/json"
    }
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
    try:
        r = requests.get(url, headers=headers, params={"limit": limit}, timeout=15)
        r.raise_for_status()
        return r.json().get("results", [])
    except Exception as e:
        print("OTX Fetch Error:", e)
        return []

# ==========================================================
# Threat Scoring
# ==========================================================
def compute_malaysia_score(pulse):
    score = 0
    text = (pulse.get("name", "") + " " + pulse.get("description", "")).lower()

    for kw in MALAYSIA_KEYWORDS:
        if kw in text:
            score += THREAT_SCORES["keyword"]

    for ind in pulse.get("indicators") or []:
        if ind.get("type") == "domain" and ind.get("indicator", "").endswith(".my"):
            score += THREAT_SCORES["my_domain"]

    return score

# ==========================================================
# Save Threats
# ==========================================================
def save_threats(pulses):
    conn = get_db()
    cur = conn.cursor()

    for pulse in pulses:
        score = compute_malaysia_score(pulse)
        if score < 1:
            continue

        for ind in pulse.get("indicators") or []:
            indicator = ind.get("indicator") or "N/A"

            cur.execute("""
                INSERT OR IGNORE INTO malaysia_targeted_threats
                (indicator, indicator_type, pulse_name, pulse_description,
                 pulse_author, pulse_created, threat_score)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                indicator,
                ind.get("type"),
                pulse.get("name"),
                pulse.get("description"),
                pulse.get("author"),
                pulse.get("created"),
                score
            ))

    conn.commit()
    conn.close()

# ==========================================================
# Update Endpoint
# ==========================================================
@app.route("/update")
def update():
    key = request.args.get("key")
    if ADMIN_KEY and key != ADMIN_KEY:
        return {"error": "Unauthorized"}, 403

    pulses = fetch_otx_pulses(limit=200)
    save_threats(pulses)

    return {"status": "updated", "pulses_fetched": len(pulses)}

# ==========================================================
# Weekly Top 10
# ==========================================================
def get_weekly_top10():
    conn = get_db()
    one_week_ago = (datetime.utcnow() - timedelta(days=7)).isoformat()

    rows = conn.execute("""
        SELECT indicator, indicator_type, threat_score, pulse_name
        FROM malaysia_targeted_threats
        WHERE pulse_created >= ?
        ORDER BY threat_score DESC
        LIMIT 100
    """, (one_week_ago,)).fetchall()

    conn.close()

    result = {"ips": [], "domains": [], "hashes": []}

    for r in rows:
        row = dict(r)
        t = row["indicator_type"]

        if t in ["IPv4", "IPv6"]:
            result["ips"].append(row)
        elif t == "domain":
            result["domains"].append(row)
        elif "FileHash" in t:
            result["hashes"].append(row)

    for k in result:
        result[k] = result[k][:10]

    return result

# ==========================================================
# JSON Report
# ==========================================================
@app.route("/report/json")
def report_json():
    return jsonify({
        "title": REPORT_TITLE,
        "generated": datetime.utcnow().isoformat(),
        "report": get_weekly_top10()
    })

# ==========================================================
# CSV Report
# ==========================================================
@app.route("/report/csv")
def report_csv():
    data = get_weekly_top10()
    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([REPORT_TITLE])
    writer.writerow(["Generated", datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")])
    writer.writerow([])
    writer.writerow(["Category", "Indicator", "Threat Score", "Pulse Name"])

    for category, items in data.items():
        for item in items:
            writer.writerow([
                category.upper(),
                item["indicator"],
                item["threat_score"],
                item["pulse_name"]
            ])

    output.seek(0)

    return send_file(
        io.BytesIO(output.getvalue().encode()),
        mimetype="text/csv",
        as_attachment=True,
        download_name="RedShark_Weekly_Threat_Report.csv"
    )

# ==========================================================
# Executive PDF Report
# ==========================================================
@app.route("/report/pdf")
def report_pdf():
    data = get_weekly_top10()
    buffer = io.BytesIO()

    doc = SimpleDocTemplate(buffer, pagesize=pagesizes.A4,
                            rightMargin=30, leftMargin=30,
                            topMargin=40, bottomMargin=40)

    elements = []
    styles = getSampleStyleSheet()

    # Logo
    logo_url = "https://raw.githubusercontent.com/redsharknetworks/sunday-ring/main/redshark.png"
    logo_file = io.BytesIO(urllib.request.urlopen(logo_url).read())
    logo = Image(logo_file, width=150, height=75)

    elements.append(logo)
    elements.append(Spacer(1, 20))

    # Title
    elements.append(Paragraph(f"<b>{REPORT_TITLE}</b>", styles["Heading1"]))
    elements.append(Spacer(1, 10))
    elements.append(Paragraph(
        f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        styles["Normal"]
    ))
    elements.append(Spacer(1, 20))

    # Table
    table_data = [["Category", "Indicator", "Score", "Pulse Name"]]

    for category, items in data.items():
        for item in items:
            table_data.append([
                category.upper(),
                item["indicator"],
                str(item["threat_score"]),
                Paragraph(item["pulse_name"], styles["Normal"])
            ])

    table = Table(
        table_data,
        colWidths=[80, 140, 60, 220],
        repeatRows=1
    )

    table.setStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#990000")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('GRID', (0, 0), (-1, -1), 0.4, colors.grey),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1),
         [colors.whitesmoke, colors.lightgrey])
    ])

    elements.append(table)
    elements.append(Spacer(1, 30))

    # Footer
    elements.append(Paragraph(
        f"<b>RedShark Cyber Intelligence Division</b><br/>"
        f"Contact: {CONTACT_EMAIL}<br/>"
        "Where Cyber Threats Fear to Swim",
        styles["Normal"]
    ))

    doc.build(elements)
    buffer.seek(0)

    return send_file(
        buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name="Sunday_Ring_RedShark_Weekly_Report.pdf"
    )

# ==========================================================
# Dashboard
# ==========================================================
@app.route("/")
def dashboard():
    conn = get_db()
    rows = conn.execute("""
        SELECT * FROM malaysia_targeted_threats
        ORDER BY threat_score DESC, pulse_created DESC
        LIMIT 20
    """).fetchall()
    conn.close()

    return render_template_string("""
    <html>
    <head>
        <title>RedShark Malaysia Threat Dashboard</title>
        <style>
            body { font-family: Arial; background:#111; color:#eee; }
            table { width:100%; border-collapse: collapse; margin-top:20px; }
            th, td { padding:8px; border:1px solid #444; }
            th { background:#990000; color:white; }
            tr:nth-child(even) { background:#1a1a1a; }
            .header { display:flex; align-items:center; gap:15px; }
            img { height:60px; }
            .btn a { padding:8px 12px; background:#990000; color:white;
                     text-decoration:none; margin-right:10px; }
        </style>
    </head>
    <body>
        <div class="header">
            <img src="https://raw.githubusercontent.com/redsharknetworks/sunday-ring/main/redshark.png">
            <h1>Malaysia Threat Intelligence Dashboard</h1>
        </div>
        <p>Contact: {{email}}</p>
        <div class="btn">
            <a href="/report/json">JSON</a>
            <a href="/report/csv">CSV</a>
            <a href="/report/pdf">PDF</a>
        </div>
        <table>
            <tr>
                <th>Indicator</th>
                <th>Type</th>
                <th>Pulse</th>
                <th>Score</th>
            </tr>
            {% for r in rows %}
            <tr>
                <td>{{r['indicator']}}</td>
                <td>{{r['indicator_type']}}</td>
                <td>{{r['pulse_name']}}</td>
                <td>{{r['threat_score']}}</td>
            </tr>
            {% endfor %}
        </table>
    </body>
    </html>
    """, rows=rows, email=CONTACT_EMAIL)

# ==========================================================
# Run
# ==========================================================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
