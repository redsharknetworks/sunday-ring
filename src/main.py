import os
import sys
import sqlite3
import requests
import io
from datetime import datetime, timedelta
from flask import Flask, jsonify, send_file, render_template_string
import geoip2.database
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib import colors, pagesizes
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

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

# OTX API
OTX_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"

# -----------------------------
# Database Setup
# -----------------------------
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS pulses (
            id TEXT PRIMARY KEY,
            name TEXT,
            created TEXT,
            classification TEXT
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

        if ind_type == "domain":
            if value.endswith(".my"):
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
    for pulse in pulses:
        classification = classify_pulse(pulse.get("indicators", []))
        c.execute("""
            INSERT OR REPLACE INTO pulses (id, name, created, classification)
            VALUES (?, ?, ?, ?)
        """, (
            pulse.get("id"),
            pulse.get("name"),
            pulse.get("created"),
            classification
        ))
    conn.commit()
    conn.close()
    print(f"Ingested {len(pulses)} pulses.")

# -----------------------------
# PDF Report
# -----------------------------
def generate_pdf():
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=pagesizes.A4)
    elements = []
    styles = getSampleStyleSheet()

    # Logo
    if os.path.exists(LOGO_FILE):
        elements.append(Image(LOGO_FILE, width=2*inch, height=1*inch))
        elements.append(Spacer(1, 12))

    # Title
    elements.append(Paragraph(
        "Sunday Ring With Red Shark - Top 10 Malaysia Weekly Threat Report",
        styles["Heading1"]
    ))
    elements.append(Spacer(1, 8))

    # Executive Headline
    headline_style = ParagraphStyle(
        "Headline",
        parent=styles["Heading2"],
        textColor=colors.darkred,
        spaceAfter=12
    )
    elements.append(Paragraph(
        "Threat Campaigns Impacting the Malaysian Digital Ecosystem",
        headline_style
    ))
    elements.append(Spacer(1, 12))

    # Table Data
    conn = get_db_connection()
    rows = conn.execute("""
        SELECT name, classification, created
        FROM pulses
        ORDER BY created DESC
        LIMIT 50
    """).fetchall()
    conn.close()

    table_data = [["Pulse Name", "Classification", "Created"]]
    for row in rows:
        table_data.append([row["name"], row["classification"], row["created"]])

    table = Table(table_data, colWidths=[3*inch, 1.5*inch, 2*inch])
    table.setStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.red),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
    ])
    elements.append(table)
    elements.append(Spacer(1, 24))

    # Footer
    elements.append(Paragraph("Contact: darkgrid@redshark.my", styles["Normal"]))

    doc.build(elements)
    buffer.seek(0)
    return buffer

# -----------------------------
# Routes
# -----------------------------
@app.route("/")
def dashboard_html():
    conn = get_db_connection()
    rows = conn.execute("""
        SELECT name, classification, created
        FROM pulses
        ORDER BY created DESC
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
            .headline h3 { color: #ff4d4d; margin-top: 5px; margin-bottom: 15px; font-weight: bold; }
            .email { margin-top: 5px; font-size: 0.9em; color: #aaa; }
        </style>
    </head>
    <body>
        <div class="header">
            <img src="/static/redshark_logo.png" class="logo" />
            <h1>Malaysia Threat Intel Dashboard</h1>
        </div>
        <div class="headline">
            <h3>Threat Campaigns Impacting the Malaysian Digital Ecosystem</h3>
        </div>
        <div class="email">Contact: darkgrid@redshark.my</div>
        <table>
            <tr>
                <th>Pulse Name</th>
                <th>Classification</th>
                <th>Created</th>
            </tr>
            {% for row in rows %}
            <tr>
                <td>{{ row['name'] }}</td>
                <td>{{ row['classification'] }}</td>
                <td>{{ row['created'] }}</td>
            </tr>
            {% endfor %}
        </table>
        <p>Total Showing: {{ rows|length }}</p>
    </body>
    </html>
    """
    return render_template_string(html, rows=rows)

@app.route("/report/pdf")
def report_pdf():
    buffer = generate_pdf()
    return send_file(buffer, mimetype="application/pdf", as_attachment=True, download_name="weekly_threat_report.pdf")

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
