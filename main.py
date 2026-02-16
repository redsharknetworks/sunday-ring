import os
import sqlite3
import requests
import io
import csv
import smtplib
from datetime import datetime, timedelta
from email.message import EmailMessage

from flask import Flask, jsonify, send_file, render_template_string, request

from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.pagesizes import A4, landscape
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfbase import pdfmetrics

# --------------------------
# App Setup
# --------------------------
app = Flask(__name__)
DB_FILE = "threats.db"

OTX_API_KEY = os.environ.get("OTX_API_KEY")
ADMIN_KEY = os.environ.get("ADMIN_KEY", "admin123")

EMAIL_USER = os.environ.get("EMAIL_USER")
EMAIL_PASS = os.environ.get("EMAIL_PASS")
EMAIL_TO = os.environ.get("EMAIL_TO")

# --------------------------
# Database
# --------------------------
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS threats (
            id TEXT PRIMARY KEY,
            pulse_name TEXT,
            indicator TEXT,
            indicator_type TEXT,
            created TEXT,
            classification TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

# --------------------------
# Malaysia Classification
# --------------------------
def classify_indicator(indicator):
    indicator = indicator.lower()

    if ".my" in indicator:
        return "TARGET_MY"
    if indicator.startswith("103.") or indicator.startswith("175."):
        return "SOURCE_MY"
    return "SOURCE_OTHER"

# --------------------------
# Risk Index
# --------------------------
def calculate_risk_index(rows):
    weights = {
        "BOTH": 5,
        "TARGET_MY": 4,
        "SOURCE_MY": 3,
        "SOURCE_OTHER": 1
    }

    score = sum(weights.get(r["classification"], 0) for r in rows)

    if score > 100:
        level = "CRITICAL"
    elif score > 50:
        level = "HIGH"
    elif score > 20:
        level = "MODERATE"
    else:
        level = "LOW"

    return score, level

# --------------------------
# Executive Summary
# --------------------------
def generate_executive_summary(rows, score, level):
    total = len(rows)
    target_my = sum(1 for r in rows if r["classification"] == "TARGET_MY")
    source_my = sum(1 for r in rows if r["classification"] == "SOURCE_MY")

    return f"""
    During this reporting period, {total} indicators were identified.
    {target_my} indicators directly target Malaysian assets.
    {source_my} originated from Malaysian infrastructure.
    The Malaysia Cyber Risk Index is {score}, categorized as {level}.
    Continued monitoring is strongly recommended.
    """

# --------------------------
# Cleanup old data
# --------------------------
def cleanup_old():
    cutoff = datetime.utcnow() - timedelta(days=30)
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("DELETE FROM threats WHERE created < ?", (cutoff.isoformat(),))
    conn.commit()
    conn.close()

# --------------------------
# Fetch OTX Data
# --------------------------
@app.route("/update")
def update_data():
    if request.args.get("key") != ADMIN_KEY:
        return jsonify({"error": "unauthorized"}), 403

    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed"

    r = requests.get(url, headers=headers)
    if r.status_code != 200:
        return jsonify({"error": "OTX fetch failed"})

    data = r.json()
    pulses = data.get("results", [])

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    total = 0

    for pulse in pulses:
        pulse_name = pulse.get("name")
        created = pulse.get("created")

        for ind in pulse.get("indicators", []):
            indicator = ind.get("indicator")
            indicator_type = ind.get("type")
            classification = classify_indicator(indicator)

            try:
                c.execute("""
                    INSERT OR IGNORE INTO threats
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    pulse.get("id") + indicator,
                    pulse_name,
                    indicator,
                    indicator_type,
                    created,
                    classification
                ))
                total += 1
            except:
                pass

    conn.commit()
    conn.close()

    cleanup_old()

    return jsonify({"status": "updated", "total": total})

# --------------------------
# Dashboard
# --------------------------
@app.route("/")
def dashboard():
    page = int(request.args.get("page", 1))
    per_page = 50
    offset = (page - 1) * per_page

    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    c.execute("SELECT * FROM threats ORDER BY created DESC LIMIT ? OFFSET ?", (per_page, offset))
    rows = c.fetchall()

    c.execute("SELECT classification, COUNT(*) as total FROM threats GROUP BY classification")
    stats = c.fetchall()

    conn.close()

    rows = [dict(r) for r in rows]
    score, level = calculate_risk_index(rows)

    html = """
    <html>
    <head>
    <style>
    body { background:#0b0f1a; color:#e0e0e0; font-family:Arial; }
    table { border-collapse: collapse; width:100%; }
    th { background:#001f4d; color:white; padding:8px; }
    td { padding:8px; }
    tr:nth-child(even) { background:#001a33; }
    h1 { color:orange; }
    a { color:orange; }
    </style>
    </head>
    <body>
    <h1>Sunday Ring With Red Shark - Malaysia Threat Dashboard</h1>
    <h2>Malaysia Risk Index: {{score}} ({{level}})</h2>

    <a href="/report/weekly?key={{admin}}">Download Weekly PDF</a> |
    <a href="/export/csv">CSV</a> |
    <a href="/export/json">JSON</a>

    <table>
    <tr>
        <th>Pulse</th>
        <th>Indicator</th>
        <th>Type</th>
        <th>Classification</th>
        <th>Date</th>
    </tr>
    {% for r in rows %}
    <tr>
        <td>{{r.pulse_name}}</td>
        <td>{{r.indicator}}</td>
        <td>{{r.indicator_type}}</td>
        <td>{{r.classification}}</td>
        <td>{{r.created}}</td>
    </tr>
    {% endfor %}
    </table>

    <br>
    <a href="/?page={{page-1}}">Prev</a> |
    <a href="/?page={{page+1}}">Next</a>
    </body>
    </html>
    """

    return render_template_string(html, rows=rows, score=score, level=level, page=page, admin=ADMIN_KEY)

# --------------------------
# CSV Export
# --------------------------
@app.route("/export/csv")
def export_csv():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT * FROM threats")
    rows = c.fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id","pulse_name","indicator","type","created","classification"])
    writer.writerows(rows)

    output.seek(0)

    return send_file(
        io.BytesIO(output.getvalue().encode()),
        mimetype="text/csv",
        as_attachment=True,
        download_name="malaysia_threats.csv"
    )

# --------------------------
# JSON Export
# --------------------------
@app.route("/export/json")
def export_json():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM threats")
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return jsonify(rows)

# --------------------------
# Weekly PDF
# --------------------------
@app.route("/report/weekly")
def weekly_report():
    if request.args.get("key") != ADMIN_KEY:
        return jsonify({"error":"unauthorized"}), 403

    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM threats ORDER BY created DESC")
    rows = [dict(r) for r in c.fetchall()]
    conn.close()

    score, level = calculate_risk_index(rows)
    summary = generate_executive_summary(rows, score, level)

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=landscape(A4),
        leftMargin=40,
        rightMargin=40
    )

    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph("<b>Sunday Ring With Red Shark - Malaysia Weekly Threat Report</b>", styles["Title"]))
    elements.append(Spacer(1,12))
    elements.append(Paragraph(summary, styles["Normal"]))
    elements.append(Spacer(1,12))

    data = [["Pulse","Indicator","Type","Class","Date"]]

    for r in rows:
        data.append([
            Paragraph(r["pulse_name"], styles["Normal"]),
            Paragraph(r["indicator"], styles["Normal"]),
            r["indicator_type"],
            r["classification"],
            r["created"]
        ])

    table = Table(data, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,0),colors.darkblue),
        ("TEXTCOLOR",(0,0),(-1,0),colors.white),
        ("GRID",(0,0),(-1,-1),0.5,colors.grey)
    ]))

    elements.append(table)
    doc.build(elements)

    buffer.seek(0)

    # Send Email if configured
    if EMAIL_USER and EMAIL_PASS and EMAIL_TO:
        msg = EmailMessage()
        msg["Subject"] = "Malaysia Weekly Threat Report"
        msg["From"] = EMAIL_USER
        msg["To"] = EMAIL_TO
        msg.set_content("Attached is the weekly Malaysia threat report.")

        msg.add_attachment(
            buffer.getvalue(),
            maintype="application",
            subtype="pdf",
            filename="weekly_report.pdf"
        )

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(EMAIL_USER, EMAIL_PASS)
            server.send_message(msg)

    return send_file(
        buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name="malaysia_weekly_report.pdf"
    )

# --------------------------
# Run
# --------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
