import os
import sys
import sqlite3
import requests
import io
import csv
from datetime import datetime
from flask import Flask, jsonify, send_file, render_template_string, request
import geoip2.database
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib import colors, pagesizes
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER

# -----------------------------
# Flask App
# -----------------------------
app = Flask(__name__)

# -----------------------------
# Configuration
# -----------------------------
OTX_API_KEY = os.environ.get("OTX_API_KEY")
if not OTX_API_KEY:
    raise RuntimeError("OTX_API_KEY environment variable is required!")

ADMIN_KEY = os.environ.get("ADMIN_KEY", "changeme")
DB_FILE = "threat_intel.db"
GEOIP_DB = "GeoLite2-Country.mmdb"
LOGO_FILE = "static/redshark_logo.png"
OTX_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"

REPORT_TITLE = "Sunday Ring With Red Shark – Malaysian Cyber Threat Landscape"
DASHBOARD_TITLE = "Real-Time Malaysia Threat Intelligence Dashboard"
EXECUTIVE_HEADLINE = "Threat Campaigns Impacting the Malaysian Digital Ecosystem"

# -----------------------------
# Database Setup
# -----------------------------
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
            created TEXT
        )
    """)
    conn.commit()
    conn.close()

def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

init_db()

# -----------------------------
# GeoIP Lookup
# -----------------------------
def geoip_country(ip):
    try:
        with geoip2.database.Reader(GEOIP_DB) as reader:
            return reader.country(ip).country.iso_code
    except:
        return None

# -----------------------------
# Classification Logic
# -----------------------------
def classify_pulse(indicators):
    has_target_my = False
    has_source_my = False
    has_source_other = False

    for ind in indicators:
        ind_type = ind.get("type")
        value = ind.get("indicator")

        if ind_type in ["IPv4", "IPv6"]:
            country = geoip_country(value)
            if country == "MY":
                has_source_my = True
            elif country:
                has_source_other = True

        if ind_type == "domain" and value.endswith(".my"):
            has_target_my = True

    if has_target_my and has_source_my:
        return "BOTH"
    elif has_target_my:
        return "TARGET_MY"
    elif has_source_my:
        return "SOURCE_MY"
    elif has_source_other:
        return "SOURCE_OTHER"
    else:
        return "UNCLASSIFIED"

# -----------------------------
# Fetch OTX Pulses
# -----------------------------
def fetch_otx(limit=100):
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    params = {"limit": limit}
    try:
        r = requests.get(OTX_URL, headers=headers, params=params, timeout=15)
        r.raise_for_status()
        return r.json().get("results", [])
    except Exception as e:
        print("OTX Fetch Error:", e)
        return []

# -----------------------------
# Ingest Pulses
# -----------------------------
def ingest():
    pulses = fetch_otx(limit=200)
    conn = get_db_connection()
    c = conn.cursor()
    total_indicators = 0
    for pulse in pulses:
        classification = classify_pulse(pulse.get("indicators", []))
        for ind in pulse.get("indicators", []):
            c.execute("""
                INSERT INTO indicators (indicator, type, pulse_name, classification, created)
                VALUES (?, ?, ?, ?, ?)
            """, (
                ind.get("indicator"),
                ind.get("type"),
                ind.get("name") if "name" in ind else pulse.get("name"),
                classification,
                pulse.get("created")
            ))
            total_indicators += 1
    conn.commit()
    conn.close()
    print(f"Ingested {len(pulses)} pulses with {total_indicators} indicators.")

# -----------------------------
# /update Endpoint
# -----------------------------
@app.route("/update")
def update_endpoint():
    key = request.args.get("key")
    if key != ADMIN_KEY:
        return {"error": "Unauthorized"}, 403
    ingest()
    return {"status": "updated", "message": "OTX pulses ingested successfully"}

# -----------------------------
# PDF Report
# -----------------------------
def generate_pdf():
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=pagesizes.A4, rightMargin=30, leftMargin=30)
    elements = []
    styles = getSampleStyleSheet()

    # Logo
    if os.path.exists(LOGO_FILE):
        elements.append(Image(LOGO_FILE, width=2*inch, height=1*inch))
        elements.append(Spacer(1, 12))

    # Centered Title
    title_style = ParagraphStyle(
        "Title",
        parent=styles["Heading1"],
        alignment=TA_CENTER,
        spaceAfter=12,
        textColor=colors.darkred
    )
    elements.append(Paragraph(REPORT_TITLE, title_style))
    elements.append(Spacer(1, 8))

    # Executive Headline
    headline_style = ParagraphStyle(
        "Headline",
        parent=styles["Heading2"],
        textColor=colors.black,
        alignment=TA_CENTER,
        spaceAfter=12
    )
    elements.append(Paragraph(EXECUTIVE_HEADLINE, headline_style))
    elements.append(Spacer(1, 12))

    # Table Data
    conn = get_db_connection()
    rows = conn.execute("""
        SELECT indicator, type, pulse_name, classification, created
        FROM indicators
        ORDER BY created DESC
        LIMIT 100
    """).fetchall()
    conn.close()

    table_data = [["Indicator", "Type", "Pulse Name", "Classification", "Created"]]
    paragraph_style = ParagraphStyle('table', fontSize=9, leading=11)

    for row in rows:
        pulse_name_paragraph = Paragraph(row["pulse_name"], paragraph_style)
        table_data.append([row["indicator"], row["type"], pulse_name_paragraph, row["classification"], row["created"]])

    col_widths = [2*inch, 0.8*inch, 3*inch, 1.2*inch, 1.5*inch]
    table = Table(table_data, colWidths=col_widths, repeatRows=1)

    style = TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.red),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
    ])

    # Color-code rows by classification
    for i, row in enumerate(rows, start=1):
        cls = row["classification"]
        if cls == "TARGET_MY":
            style.add('BACKGROUND', (0,i), (-1,i), colors.lightcoral)
        elif cls == "SOURCE_MY":
            style.add('BACKGROUND', (0,i), (-1,i), colors.orange)
        elif cls == "BOTH":
            style.add('BACKGROUND', (0,i), (-1,i), colors.darkred)
            style.add('TEXTCOLOR', (0,i), (-1,i), colors.whitesmoke)
        elif cls == "SOURCE_OTHER":
            style.add('BACKGROUND', (0,i), (-1,i), colors.lightblue)
        elif cls == "UNCLASSIFIED":
            style.add('BACKGROUND', (0,i), (-1,i), colors.lightgrey)

    table.setStyle(style)
    elements.append(table)
    elements.append(Spacer(1, 24))
    # Contact visible above buttons in dashboard and in PDF footer
    elements.append(Paragraph("Contact: darkgrid@redshark.my", styles["Normal"]))
    doc.build(elements)
    buffer.seek(0)
    return buffer

# -----------------------------
# Dashboard HTML
# -----------------------------
@app.route("/")
def dashboard_html():
    conn = get_db_connection()
    rows = conn.execute("""
        SELECT indicator, type, pulse_name, classification, created
        FROM indicators
        ORDER BY created DESC
        LIMIT 50
    """).fetchall()
    conn.close()

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
            body { font-family: Arial, sans-serif; background-color: #111; color: #eee; }
            table { border-collapse: collapse; width: 100%; margin-top: 20px; }
            th, td { border: 1px solid #555; padding: 8px; text-align: left; }
            th { background-color: #222; }
            tr:nth-child(even) { background-color: #1a1a1a; }
            .header { display: flex; align-items: center; gap: 15px; }
            img.logo { height: 60px; }
            .headline h3 { color: #ff4d4d; margin-top: 5px; margin-bottom: 15px; font-weight: bold; }
            .email { margin-top: 5px; font-size: 0.9em; color: #aaa; }
            .buttons a { 
                background-color: #222; color: #eee; padding: 8px 12px; text-decoration: none; 
                margin-right: 10px; border-radius: 4px;
            }
            .buttons a:hover { background-color: #333; }
        </style>
    </head>
    <body>
        <div class="header">
            <img src="/static/redshark_logo.png" class="logo" />
            <h1>{{ dashboard_title }}</h1>
        </div>
        <div class="headline">
            <h3>{{ executive_headline }}</h3>
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
                <th>Classification</th>
                <th>Created</th>
            </tr>
            {% for row in rows %}
            <tr style="background-color: {{ color_map.get(row['classification'], '#d3d3d3') }}">
                <td>{{ row['indicator'] }}</td>
                <td>{{ row['type'] }}</td>
                <td>{{ row['pulse_name'] }}</td>
                <td>{{ row['classification'] }}</td>
                <td>{{ row['created'] }}</td>
            </tr>
            {% endfor %}
        </table>
        <p>Total Showing: {{ rows|length }}</p>
    </body>
    </html>
    """
    return render_template_string(html, rows=rows, color_map=color_map,
                                  dashboard_title=DASHBOARD_TITLE,
                                  executive_headline=EXECUTIVE_HEADLINE)

# -----------------------------
# Reports
# -----------------------------
@app.route("/report/pdf")
def report_pdf():
    buffer = generate_pdf()
    return send_file(buffer, mimetype="application/pdf", as_attachment=True, download_name="malaysia_threat_report.pdf")

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

# -----------------------------
# Main Entry
# -----------------------------
if __name__ == "__main__":
    init_db()
    if len(sys.argv) > 1 and sys.argv[1] == "ingest":
        ingest()
        sys.exit(0)
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
