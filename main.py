import os
import sys
import sqlite3
import requests
import io
import csv
from flask import Flask, jsonify, send_file, render_template_string, request
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib import colors, pagesizes
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4, landscape

# -----------------------------
# Flask App
# -----------------------------
app = Flask(__name__, static_folder="static")

# -----------------------------
# Configuration
# -----------------------------
OTX_API_KEY = os.environ.get("OTX_API_KEY")
if not OTX_API_KEY:
    raise RuntimeError("OTX_API_KEY environment variable is required!")

ADMIN_KEY = os.environ.get("ADMIN_KEY", "changeme")
DB_FILE = os.environ.get("DB_FILE", "threat_intel.db")
LOGO_FILE = os.environ.get("LOGO_FILE", "static/redshark_logo.png")

REPORT_TITLE = "Sunday Ring With Red Shark – Malaysian Cyber Threat Landscape"
DASHBOARD_TITLE = "Real-Time Malaysia Threat Intelligence Dashboard"
EXECUTIVE_HEADLINE = "Threat Campaigns Impacting the Malaysian Digital Ecosystem"
CONTACT_EMAIL = "darkgrid@redshark.my"

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
            created TEXT,
            UNIQUE(indicator, pulse_name)
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
# Classification Logic
# -----------------------------
def classify_pulse(pulse):
    indicators = pulse.get("indicators", [])
    targeted_countries = [c.lower() for c in pulse.get("targeted_countries", [])]

    has_target_my = any(ind.get("type") == "domain" and ind.get("indicator", "").endswith(".my") for ind in indicators)
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

# -----------------------------
# Fetch OTX Pulses
# -----------------------------
def fetch_otx(limit=100):
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    params = {"limit": limit}
    try:
        r = requests.get("https://otx.alienvault.com/api/v1/pulses/subscribed",
                         headers=headers, params=params, timeout=15)
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
        classification = classify_pulse(pulse)
        for ind in pulse.get("indicators", []):
            try:
                c.execute("""
                    INSERT OR IGNORE INTO indicators (indicator, type, pulse_name, classification, created)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    ind.get("indicator"),
                    ind.get("type"),
                    pulse.get("name"),
                    classification,
                    pulse.get("created")
                ))
                total_indicators += 1
            except Exception as e:
                print("DB Insert Error:", e)

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
        return jsonify({"error": "Unauthorized"}), 403
    ingest()
    return jsonify({"status": "updated", "message": "OTX pulses ingested successfully"})

# -----------------------------
# Generate PDF (Landscape, Wrapped, Margins)
# -----------------------------
def generate_pdf(limit=100):
    buffer = io.BytesIO()
    
    page_width, page_height = landscape(A4)
    margin = 0.5 * inch
    usable_width = page_width - 2 * margin

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

    # Logo
    if os.path.exists(LOGO_FILE):
        try:
            img = Image(LOGO_FILE)
            max_width, max_height = 2*inch, 1*inch
            img.drawWidth = min(img.imageWidth, max_width)
            img.drawHeight = min(img.imageHeight, max_height)
            elements.append(img)
            elements.append(Spacer(1, 12))
        except Exception as e:
            print("Logo error:", e)

    # Title
    title_style = ParagraphStyle("Title", parent=styles["Heading1"], alignment=TA_CENTER,
                                 spaceAfter=12, textColor=colors.darkred)
    elements.append(Paragraph("Sunday Ring With Red Shark<br/>(Malaysian Cyber Threat Landscape)", title_style))
    elements.append(Spacer(1, 8))

    # Headline
    headline_style = ParagraphStyle("Headline", parent=styles["Heading2"], alignment=TA_CENTER, spaceAfter=12)
    elements.append(Paragraph(EXECUTIVE_HEADLINE, headline_style))
    elements.append(Spacer(1, 12))

    # Fetch indicators
    conn = get_db_connection()
    rows = conn.execute("""
        SELECT indicator, type, pulse_name, classification, created
        FROM indicators
        ORDER BY created DESC
        LIMIT ?
    """, (limit,)).fetchall()
    conn.close()

    # Table data
    table_data = [["Indicator", "Type", "Pulse Name", "Classification", "Created"]]
    cell_style = ParagraphStyle('cell', fontSize=9, leading=11, wordWrap='CJK')

    for row in rows:
        table_data.append([
            Paragraph(row["indicator"], cell_style),
            Paragraph(row["type"], cell_style),
            Paragraph(row["pulse_name"], cell_style),
            Paragraph(row["classification"], cell_style),
            Paragraph(row["created"], cell_style)
        ])

    # Dynamic column widths
    col_ratios = [0.25, 0.1, 0.35, 0.15, 0.15]
    col_widths = [usable_width * r for r in col_ratios]

    table = Table(table_data, colWidths=col_widths, repeatRows=1)

    # Table style
    style = TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.red),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
        ('LEFTPADDING', (0,0), (-1,-1), 4),
        ('RIGHTPADDING', (0,0), (-1,-1), 4),
        ('TOPPADDING', (0,0), (-1,-1), 2),
        ('BOTTOMPADDING', (0,0), (-1,-1), 2),
    ])

    color_map = {
        "TARGET_MY": colors.lightcoral,
        "SOURCE_MY": colors.orange,
        "BOTH": colors.darkred,
        "SOURCE_OTHER": colors.lightblue,
        "UNCLASSIFIED": colors.lightgrey
    }
    text_map = {"BOTH": colors.whitesmoke}

    for i, row in enumerate(rows, start=1):
        cls = row["classification"]
        bg = color_map.get(cls, colors.lightgrey)
        style.add('BACKGROUND', (0,i), (-1,i), bg)
        if cls in text_map:
            style.add('TEXTCOLOR', (0,i), (-1,i), text_map[cls])

    table.setStyle(style)

    elements.append(Spacer(1, 12))
    elements.append(table)
    elements.append(Spacer(1, 12))
    elements.append(Paragraph(f"Contact: {CONTACT_EMAIL}", styles["Normal"]))

    doc.build(elements)
    buffer.seek(0)
    return buffer

# -----------------------------
# Dashboard
# -----------------------------
@app.route("/")
def dashboard():
    sort_column = request.args.get("sort", "created")
    sort_order = request.args.get("order", "desc").lower()
    if sort_order not in ["asc", "desc"]:
        sort_order = "desc"

    allowed_sort = ["indicator", "type", "pulse_name", "classification", "created"]
    if sort_column not in allowed_sort:
        sort_column = "created"

    conn = get_db_connection()
    rows = conn.execute(f"""
        SELECT indicator, type, pulse_name, classification, created
        FROM indicators
        ORDER BY {sort_column} {sort_order.upper()}
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
            th { background-color: #222; cursor: pointer; }
            tr:nth-child(even) { background-color: #1a1a1a; }
            .header { display: flex; align-items: center; gap: 15px; }
            img.logo { height: 60px; }
            .headline h3 { color: #ff4d4d; margin-top: 5px; margin-bottom: 15px; font-weight: bold; }
            .email { margin-bottom: 12px; font-size: 0.9em; color: #aaa; }
            .buttons { margin-bottom: 20px; }
            .buttons a { background-color: #222; color: #eee; padding: 8px 12px; text-decoration: none; margin-right: 10px; border-radius: 4px; }
            .buttons a:hover { background-color: #333; }
        </style>
        <script>
            function sortTable(column) {
                const url = new URL(window.location.href);
                let currentOrder = url.searchParams.get("order");
                currentOrder = currentOrder === "asc" ? "desc" : "asc";
                url.searchParams.set("sort", column);
                url.searchParams.set("order", currentOrder);
                window.location.href = url.href;
            }
        </script>
    </head>
    <body>
        <div class="header">
            <img src="/static/redshark_logo.png" class="logo" />
            <h1>{{ dashboard_title }}</h1>
        </div>
        <div class="headline">
            <h3>{{ executive_headline }}</h3>
        </div>
        <div class="email">Contact: {{ contact_email }}</div>
        <div class="buttons">
            <a href="/report/json" target="_blank">Download JSON</a>
            <a href="/report/csv" target="_blank">Download CSV</a>
            <a href="/report/pdf" target="_blank">Download PDF</a>
        </div>
        <table>
            <tr>
                <th onclick="sortTable('indicator')">Indicator</th>
                <th onclick="sortTable('type')">Type</th>
                <th onclick="sortTable('pulse_name')">Pulse Name</th>
                <th onclick="sortTable('classification')">Classification</th>
                <th onclick="sortTable('created')">Created</th>
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
                                  executive_headline=EXECUTIVE_HEADLINE,
                                  contact_email=CONTACT_EMAIL)

# -----------------------------
# Reports Endpoints
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
# CLI Support & Run
# -----------------------------
if __name__ == "__main__":
    init_db()
    if len(sys.argv) > 1:
        if sys.argv[1] in ["ingest", "--update"]:
            ingest()
            sys.exit(0)

    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
