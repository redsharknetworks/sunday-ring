import os
import sys
import sqlite3
import requests
import io
import csv
import time
from datetime import datetime

from flask import Flask, jsonify, send_file, render_template_string, request
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4, landscape

# -------------------------------------------------
# Flask App
# -------------------------------------------------
app = Flask(__name__, static_folder="static")

# -------------------------------------------------
# Configuration
# -------------------------------------------------
OTX_API_KEY = os.environ.get("OTX_API_KEY")
if not OTX_API_KEY:
    raise RuntimeError("OTX_API_KEY environment variable is required!")

DB_FILE = os.environ.get("DB_FILE", "threat_intel.db")
LOGO_FILE = os.environ.get("LOGO_FILE", "static/redshark_logo.png")

REPORT_TITLE = "Sunday Ring With Red Shark – Malaysian Cyber Threat Landscape"
DASHBOARD_TITLE = "Real-Time Malaysia Threat Intelligence Dashboard"
EXECUTIVE_HEADLINE = "Threat Campaigns Impacting the Malaysian Digital Ecosystem"
CONTACT_EMAIL = "darkgrid@redshark.my"

# -------------------------------------------------
# Database Setup
# -------------------------------------------------
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS indicators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator TEXT,
            type TEXT,
            pulse_name TEXT,
            classification TEXT,
            created TEXT,
            UNIQUE(indicator, pulse_name)
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS metadata (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)

    conn.commit()
    conn.close()

def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

init_db()

# -------------------------------------------------
# Classification Logic
# -------------------------------------------------
def classify_pulse(pulse):
    indicators = pulse.get("indicators", [])
    targeted_countries = [c.lower() for c in pulse.get("targeted_countries", [])]

    has_target_my = any(
        ind.get("type") == "domain" and ind.get("indicator", "").endswith(".my")
        for ind in indicators
    )

    has_targeted_my = "my" in targeted_countries

    if has_target_my and has_targeted_my:
        return "BOTH"
    elif has_target_my:
        return "TARGET_MY"
    elif has_targeted_my:
        return "SOURCE_MY"
    elif indicators:
        return "SOURCE_OTHER"
    else:
        return "UNCLASSIFIED"

# -------------------------------------------------
# Risk Scoring
# -------------------------------------------------
def calculate_risk_score(classification):
    score_map = {
        "BOTH": 5,
        "TARGET_MY": 4,
        "SOURCE_MY": 3,
        "SOURCE_OTHER": 2,
        "UNCLASSIFIED": 1
    }
    return score_map.get(classification, 1)

# -------------------------------------------------
# Fetch OTX Pulses
# -------------------------------------------------
def fetch_otx(limit=200):
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    try:
        r = requests.get(
            "https://otx.alienvault.com/api/v1/pulses/subscribed",
            headers=headers,
            params={"limit": limit},
            timeout=15
        )
        r.raise_for_status()
        return r.json().get("results", [])
    except Exception as e:
        print("OTX Fetch Error:", e)
        return []

# -------------------------------------------------
# Ingest (Malaysia Only + Auto Clean)
# -------------------------------------------------
def ingest():
    pulses = fetch_otx()
    conn = get_db_connection()
    c = conn.cursor()

    for pulse in pulses:
        classification = classify_pulse(pulse)

        # Malaysia-only filter
        if classification not in ["TARGET_MY", "SOURCE_MY", "BOTH"]:
            continue

        for ind in pulse.get("indicators", []):
            c.execute("""
                INSERT OR IGNORE INTO indicators
                (indicator, type, pulse_name, classification, created)
                VALUES (?, ?, ?, ?, ?)
            """, (
                ind.get("indicator"),
                ind.get("type"),
                pulse.get("name"),
                classification,
                pulse.get("created")
            ))

    # Keep only last 30 days
    c.execute("""
        DELETE FROM indicators
        WHERE created < datetime('now', '-30 days')
    """)

    conn.commit()
    conn.close()
    print("Ingestion completed.")

# -------------------------------------------------
# Smart 30-Minute Ingestion
# -------------------------------------------------
def smart_ingest():
    conn = get_db_connection()
    row = conn.execute(
        "SELECT value FROM metadata WHERE key='last_ingest'"
    ).fetchone()

    now = int(time.time())
    should_ingest = True
    last_ingest_time = None

    if row:
        last_ingest_time = int(row["value"])
        if now - last_ingest_time < 1800:
            should_ingest = False

    if should_ingest:
        ingest()
        conn.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
            ("last_ingest", str(now))
        )
        conn.commit()
        last_ingest_time = now

    conn.close()
    return last_ingest_time

# -------------------------------------------------
# Dashboard
# -------------------------------------------------
@app.route("/")
def dashboard():
    last_ingest_time = smart_ingest()

    conn = get_db_connection()

    # Classification counts
    counts = conn.execute("""
        SELECT classification, COUNT(*) as total
        FROM indicators
        GROUP BY classification
    """).fetchall()

    # Top 10 campaigns
    top_campaigns = conn.execute("""
        SELECT pulse_name, classification, COUNT(*) as total
        FROM indicators
        GROUP BY pulse_name, classification
        ORDER BY total DESC
        LIMIT 10
    """).fetchall()

    # Main table
    rows = conn.execute("""
        SELECT indicator, type, pulse_name, classification, created
        FROM indicators
        ORDER BY created DESC
        LIMIT 50
    """).fetchall()

    conn.close()

    # Risk index
    overall_risk = 0
    total_indicators = 0
    for row in counts:
        score = calculate_risk_score(row["classification"])
        overall_risk += score * row["total"]
        total_indicators += row["total"]

    overall_risk_index = round(overall_risk / total_indicators, 2) if total_indicators else 0

    last_updated = (
        datetime.utcfromtimestamp(last_ingest_time).strftime("%Y-%m-%d %H:%M:%S UTC")
        if last_ingest_time else "Never"
    )

    color_map = {
        "TARGET_MY": "#f08080",
        "SOURCE_MY": "#ffa500",
        "BOTH": "#8b0000",
        "SOURCE_OTHER": "#add8e6",
        "UNCLASSIFIED": "#d3d3d3"
    }

    html = """
    <html>
    <head>
        <title>{{ dashboard_title }}</title>
        <style>
            body { font-family: Arial; background:#111; color:#eee; }
            table { border-collapse: collapse; width:100%; margin-top:10px; }
            th, td { border:1px solid #555; padding:8px; }
            th { background:#222; }
            .panel { background:#1b1b1b; padding:12px; margin-bottom:15px; border:1px solid #333; }
            .risk { color:#ff4d4d; font-size:20px; font-weight:bold; }
            .buttons a { background:#222; color:#eee; padding:6px 12px; text-decoration:none; margin-right:8px; border-radius:4px;}
            .buttons a:hover { background:#333; }
        </style>
    </head>
    <body>

        <h1>{{ dashboard_title }}</h1>
        <h3>{{ executive_headline }}</h3>

        <div class="panel">
            <strong>Malaysia Threat Risk Index:</strong>
            <span class="risk">{{ overall_risk_index }}</span><br>
            Last Updated: {{ last_updated }}
        </div>

        <div class="panel">
            <strong>Top 10 Active Campaigns</strong>
            <table>
                <tr>
                    <th>Pulse Name</th>
                    <th>Classification</th>
                    <th>Indicators</th>
                </tr>
                {% for c in top_campaigns %}
                <tr>
                    <td>{{ c['pulse_name'] }}</td>
                    <td>{{ c['classification'] }}</td>
                    <td>{{ c['total'] }}</td>
                </tr>
                {% endfor %}
            </table>
        </div>

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
                <th>Classification</th>
                <th>Created</th>
            </tr>
            {% for row in rows %}
            <tr style="background-color: {{ color_map.get(row['classification'], '#222') }}">
                <td>{{ row['indicator'] }}</td>
                <td>{{ row['type'] }}</td>
                <td>{{ row['pulse_name'] }}</td>
                <td>{{ row['classification'] }}</td>
                <td>{{ row['created'] }}</td>
            </tr>
            {% endfor %}
        </table>

    </body>
    </html>
    """

    return render_template_string(
        html,
        rows=rows,
        top_campaigns=top_campaigns,
        dashboard_title=DASHBOARD_TITLE,
        executive_headline=EXECUTIVE_HEADLINE,
        overall_risk_index=overall_risk_index,
        last_updated=last_updated,
        color_map=color_map
    )

# -------------------------------------------------
# PDF Report
# -------------------------------------------------
@app.route("/report/pdf")
def report_pdf():
    buffer = io.BytesIO()
    page_width, page_height = landscape(A4)
    margin = 0.5 * inch
    usable_width = page_width - 2*margin

    doc = SimpleDocTemplate(
        buffer,
        pagesize=landscape(A4),
        leftMargin=margin,
        rightMargin=margin,
        topMargin=margin,
        bottomMargin=margin
    )

    elements = []
    styles = getSampleStyleSheet()

    conn = get_db_connection()
    rows = conn.execute("""
        SELECT indicator, type, pulse_name, classification, created
        FROM indicators
        ORDER BY created DESC
        LIMIT 100
    """).fetchall()

    counts = conn.execute("""
        SELECT classification, COUNT(*) as total
        FROM indicators
        GROUP BY classification
    """).fetchall()
    conn.close()

    overall_risk = 0
    total = 0
    for row in counts:
        score = calculate_risk_score(row["classification"])
        overall_risk += score * row["total"]
        total += row["total"]

    overall_risk_index = round(overall_risk / total, 2) if total else 0

    # Logo
    if os.path.exists(LOGO_FILE):
        img = Image(LOGO_FILE)
        img.drawWidth = min(img.imageWidth, 2*inch)
        img.drawHeight = min(img.imageHeight, 1*inch)
        elements.append(img)
        elements.append(Spacer(1, 12))

    elements.append(Paragraph(REPORT_TITLE, styles["Heading1"]))
    elements.append(Spacer(1, 12))
    elements.append(Paragraph(f"<b>Malaysia Threat Risk Index:</b> {overall_risk_index}", styles["Normal"]))
    elements.append(Spacer(1, 12))

    table_data = [["Indicator", "Type", "Pulse", "Classification", "Created"]]
    cell_style = ParagraphStyle('cell', fontSize=9, leading=11, wordWrap='CJK')

    for r in rows:
        table_data.append([
            Paragraph(r["indicator"], cell_style),
            Paragraph(r["type"], cell_style),
            Paragraph(r["pulse_name"], cell_style),
            Paragraph(r["classification"], cell_style),
            Paragraph(r["created"], cell_style)
        ])

    col_ratios = [0.25, 0.1, 0.35, 0.15, 0.15]
    col_widths = [usable_width * r for r in col_ratios]
    table = Table(table_data, colWidths=col_widths, repeatRows=1)

    table_style = TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.darkred),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
        ('LEFTPADDING', (0,0), (-1,-1), 4),
        ('RIGHTPADDING', (0,0), (-1,-1), 4),
        ('TOPPADDING', (0,0), (-1,-1), 2),
        ('BOTTOMPADDING', (0,0), (-1,-1), 2),
    ])

    table.setStyle(table_style)
    elements.append(table)

    doc.build(elements)
    buffer.seek(0)

    return send_file(
        buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name="malaysia_threat_report.pdf"
    )

# -------------------------------------------------
# JSON Report
# -------------------------------------------------
@app.route("/report/json")
def report_json():
    conn = get_db_connection()
    rows = conn.execute("""
        SELECT indicator, type, pulse_name, classification, created
        FROM indicators
        ORDER BY created DESC
        LIMIT 100
    """).fetchall()
    conn.close()

    return jsonify([dict(row) for row in rows])

# -------------------------------------------------
# CSV Report
# -------------------------------------------------
@app.route("/report/csv")
def report_csv():
    conn = get_db_connection()
    rows = conn.execute("""
        SELECT indicator, type, pulse_name, classification, created
        FROM indicators
        ORDER BY created DESC
        LIMIT 100
    """).fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Indicator", "Type", "Pulse Name", "Classification", "Created"])
    for row in rows:
        writer.writerow([row["indicator"], row["type"], row["pulse_name"], row["classification"], row["created"]])

    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode()),
        mimetype="text/csv",
        as_attachment=True,
        download_name="malaysia_threat_report.csv"
    )

# -------------------------------------------------
# CLI Ingestion Support & Run
# -------------------------------------------------
if __name__ == "__main__":
    init_db()
    if len(sys.argv) > 1 and sys.argv[1] in ["ingest", "--update"]:
        ingest()
        sys.exit(0)

    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
