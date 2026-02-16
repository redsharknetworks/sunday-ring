import os
import sqlite3
import requests
import io
import csv
from datetime import datetime, timedelta
from flask import Flask, jsonify, request, render_template_string, send_file
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import pagesizes

# --------------------------
# Flask App
# --------------------------
app = Flask(__name__)

# --------------------------
# Environment / Config
# --------------------------
OTX_API_KEY = os.environ.get("OTX_API_KEY")
if not OTX_API_KEY:
    raise RuntimeError("OTX_API_KEY environment variable is required!")

ADMIN_KEY = os.environ.get("ADMIN_KEY")
DATABASE_FILE = "threat_intel.db"

# --------------------------
# Malaysia Targeting Rules
# --------------------------
MALAYSIA_KEYWORDS = [
    "malaysia", "maybank", "cimb", "bank negara",
    "petronas", ".my", "gov.my", "edu.my"
]

THREAT_SCORES = {
    "keyword": 3,
    "my_domain": 4
}

# --------------------------
# Database Setup
# --------------------------
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

def get_db_connection():
    conn = sqlite3.connect(DATABASE_FILE)
    conn.row_factory = sqlite3.Row
    return conn

# --------------------------
# Fetch OTX Pulses
# --------------------------
def fetch_otx_pulses(limit=100):
    headers = {"X-OTX-API-KEY": OTX_API_KEY, "Accept": "application/json"}
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
    params = {"limit": limit}

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        return response.json().get("results", [])
    except Exception as e:
        print("OTX Fetch Error:", e)
        return []

# --------------------------
# Compute Malaysia Score
# --------------------------
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

# --------------------------
# Save Threats
# --------------------------
def save_threats(pulses):
    conn = get_db_connection()
    cursor = conn.cursor()

    for pulse in pulses:
        score = compute_malaysia_score(pulse)
        if score < 1:
            continue
        for ind in pulse.get("indicators") or []:
            cursor.execute("""
                INSERT OR IGNORE INTO malaysia_targeted_threats
                (indicator, indicator_type, pulse_name, pulse_description, pulse_author, pulse_created, threat_score)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                ind.get("indicator"),
                ind.get("type"),
                pulse.get("name"),
                pulse.get("description"),
                pulse.get("author"),
                pulse.get("created"),
                score
            ))

    conn.commit()
    conn.close()

# --------------------------
# Update Endpoint
# --------------------------
@app.route("/update")
def update_threats():
    key = request.args.get("key")
    if ADMIN_KEY and key != ADMIN_KEY:
        return {"error": "Unauthorized"}, 403

    pulses = fetch_otx_pulses(limit=200)
    save_threats(pulses)
    return {"status": "updated", "total_pulses_fetched": len(pulses)}

# --------------------------
# Dashboard API
# --------------------------
@app.route("/api/dashboard")
def dashboard_api():
    conn = get_db_connection()
    rows = conn.execute("""
        SELECT * FROM malaysia_targeted_threats
        ORDER BY threat_score DESC, pulse_created DESC
        LIMIT 50
    """).fetchall()
    conn.close()
    return jsonify([dict(row) for row in rows])

# --------------------------
# Weekly Top 10 Report
# --------------------------
def get_weekly_top10():
    conn = get_db_connection()
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
    for row in rows:
        r = dict(row)
        t = r["indicator_type"]
        if t in ["IPv4", "IPv6"]:
            result["ips"].append(r)
        elif t == "domain":
            result["domains"].append(r)
        elif "FileHash" in t:
            result["hashes"].append(r)

    result["ips"] = result["ips"][:10]
    result["domains"] = result["domains"][:10]
    result["hashes"] = result["hashes"][:10]
    return result

# --------------------------
# JSON Report
# --------------------------
@app.route("/report/json")
def report_json():
    return jsonify(get_weekly_top10())

# --------------------------
# CSV Report
# --------------------------
@app.route("/report/csv")
def report_csv():
    data = get_weekly_top10()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Category", "Indicator", "Threat Score", "Pulse Name"])

    for category, items in data.items():
        for item in items:
            writer.writerow([
                category,
                item["indicator"],
                item["threat_score"],
                item["pulse_name"]
            ])
    output.seek(0)

    return send_file(
        io.BytesIO(output.getvalue().encode()),
        mimetype="text/csv",
        as_attachment=True,
        download_name="weekly_threat_report.csv"
    )

# --------------------------
# PDF Report
# --------------------------
@app.route("/report/pdf")
def report_pdf():
    data = get_weekly_top10()
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=pagesizes.A4)
    elements = []
    styles = getSampleStyleSheet()

    elements.append(Paragraph("Malaysia Weekly Threat Report", styles["Heading1"]))
    elements.append(Spacer(1, 12))
    table_data = [["Category", "Indicator", "Threat Score"]]

    for category, items in data.items():
        for item in items:
            table_data.append([
                category,
                item["indicator"],
                str(item["threat_score"])
            ])
    table = Table(table_data)
    table.setStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.grey),
        ('GRID', (0,0), (-1,-1), 1, colors.black),
    ])
    elements.append(table)
    doc.build(elements)
    buffer.seek(0)

    return send_file(
        buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name="weekly_threat_report.pdf"
    )

# --------------------------
# Dashboard HTML (with download buttons)
# --------------------------
@app.route("/")
def dashboard_html():
    conn = get_db_connection()
    rows = conn.execute("""
        SELECT * FROM malaysia_targeted_threats
        ORDER BY threat_score DESC, pulse_created DESC
        LIMIT 20
    """).fetchall()
    conn.close()

    html = """
    <html>
    <head>
        <title>Malaysia Threat Intel Dashboard</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #111; color: #eee; }
            table { border-collapse: collapse; width: 100%; margin-top: 20px; }
            th, td { border: 1px solid #555; padding: 8px; text-align: left; }
            th { background-color: #222; }
            tr:nth-child(even) { background-color: #1a1a1a; }
            .header { display: flex; align-items: center; gap: 15px; }
            img.logo { height: 60px; }
            .email { margin-top: 5px; font-size: 0.9em; color: #aaa; }
            .buttons { margin-top: 15px; }
            .buttons a { 
                background-color: #222; color: #eee; padding: 8px 12px; text-decoration: none; 
                margin-right: 10px; border-radius: 4px;
            }
            .buttons a:hover { background-color: #333; }
        </style>
    </head>
    <body>
        <div class="header">
            <img src="https://raw.githubusercontent.com/redsharknetworks/sunday-ring/main/redshark.png" class="logo" />
            <h1>Malaysia Threat Intel Dashboard</h1>
        </div>
        <div class="email">Contact: darkgrid@redshark.my</div>

        <div class="buttons">
            <a href="/report/json" target="_blank">Download JSON</a>
            <a href="/report/csv" target="_blank">Download CSV</a>
            <a href="/report/pdf" target="_blank">Download PDF</a>
        </div>

        <table>
            <tr>
                <th>Indicator</th>
                <th>Type</th>
                <th>Pulse Name</th>
                <th>Threat Score</th>
            </tr>
            {% for row in rows %}
            <tr>
                <td>{{ row['indicator'] }}</td>
                <td>{{ row['indicator_type'] }}</td>
                <td>{{ row['pulse_name'] }}</td>
                <td>{{ row['threat_score'] }}</td>
            </tr>
            {% endfor %}
        </table>
        <p>Total Showing: {{ rows|length }}</p>
    </body>
    </html>
    """
    return render_template_string(html, rows=rows)

# --------------------------
# Run App
# --------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
