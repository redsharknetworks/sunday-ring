import os
import io
import csv
import sqlite3
import threading
import time
from datetime import datetime
from flask import Flask, render_template_string, send_file, jsonify, request
import requests
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib import colors, pagesizes
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER

app = Flask(__name__)

DB_FILE = "threats.db"
LOGO_PATH = "logo.png"  # adjust logo if needed

# ------------------ DATABASE ------------------
def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

# ------------------ THREAT FETCH ------------------
def fetch_threats():
    # Simulated threat fetch; replace with API calls (OTX, Talos, AbuseIPDB)
    threats = [
        {"id":1, "indicator":"192.168.1.1", "classification":"Critical", "c2":"malware.com", "recon":"scan"},
        {"id":2, "indicator":"10.0.0.5", "classification":"High", "c2":"badactor.net", "recon":"phish"}
    ]
    conn = get_db_connection()
    c = conn.cursor()
    for t in threats:
        c.execute("INSERT OR IGNORE INTO threats (id, indicator, classification, c2, recon, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                  (t["id"], t["indicator"], t["classification"], t["c2"], t["recon"], datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()

# ------------------ PDF GENERATION ------------------
def generate_pdf(threats):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=pagesizes.landscape(pagesizes.A4),
                            leftMargin=30, rightMargin=30, topMargin=30, bottomMargin=30)
    elements = []
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle('title', parent=styles['Heading1'], alignment=TA_CENTER)
    elements.append(Paragraph("SOC Threat Dashboard Report", title_style))
    elements.append(Spacer(1, 12))

    # Table data
    table_data = [["ID", "Indicator", "Classification", "C2", "Recon", "Created At"]]
    for t in threats:
        table_data.append([
            t["id"],
            Paragraph(t["indicator"], styles["Normal"]),
            Paragraph(t["classification"], styles["Normal"]),
            Paragraph(t["c2"], styles["Normal"]),
            Paragraph(t["recon"], styles["Normal"]),
            Paragraph(t["created_at"], styles["Normal"])
        ])
    table = Table(table_data, repeatRows=1)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.darkblue),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('GRID', (0,0), (-1,-1), 0.5, colors.black),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('FONTSIZE', (0,0), (-1,-1), 9)
    ]))
    elements.append(table)
    doc.build(elements)
    buffer.seek(0)
    return buffer

# ------------------ ROUTES ------------------
@app.route("/")
def index():
    conn = get_db_connection()
    threats = conn.execute("SELECT * FROM threats ORDER BY created_at DESC").fetchall()
    conn.close()
    return render_template_string("""
    <html>
    <head>
    <title>SOC Dashboard 7.2.7</title>
    <style>
        table {border-collapse: collapse; width: 100%;}
        th, td {border:1px solid #ddd; padding:8px;}
        th {background-color:#4CAF50; color:white; cursor:pointer;}
        .critical {color:red; font-weight:bold; animation: blink 1s infinite;}
        @keyframes blink { 50% {opacity:0;} }
    </style>
    <script>
    function sortTable(n) {
      let table = document.getElementById("threatTable");
      let rows = Array.from(table.rows).slice(1);
      let asc = table.dataset.sortAsc === "true";
      rows.sort((a,b) => a.cells[n].innerText.localeCompare(b.cells[n].innerText, undefined, {numeric:true}));
      if(!asc) rows.reverse();
      rows.forEach(r => table.appendChild(r));
      table.dataset.sortAsc = (!asc).toString();
    }
    </script>
    </head>
    <body>
    <h1>SOC Threat Dashboard 7.2.7</h1>
    <table id="threatTable" data-sort-asc="true">
    <tr>
      <th onclick="sortTable(0)">ID</th>
      <th onclick="sortTable(1)">Indicator</th>
      <th onclick="sortTable(2)">Classification</th>
      <th onclick="sortTable(3)">C2</th>
      <th onclick="sortTable(4)">Recon</th>
      <th onclick="sortTable(5)">Created At</th>
    </tr>
    {% for t in threats %}
    <tr>
      <td>{{t['id']}}</td>
      <td>{{t['indicator']}}</td>
      <td class="{{ 'critical' if t['classification']=='Critical' else '' }}">{{t['classification']}}</td>
      <td>{{t['c2']}}</td>
      <td>{{t['recon']}}</td>
      <td>{{t['created_at']}}</td>
    </tr>
    {% endfor %}
    </table>
    <br/>
    <a href="/download/pdf">Download PDF</a> | 
    <a href="/download/csv">Download CSV</a> | 
    <a href="/download/json">Download JSON</a>
    </body>
    </html>
    """, threats=threats)

@app.route("/download/pdf")
def download_pdf():
    conn = get_db_connection()
    threats = conn.execute("SELECT * FROM threats ORDER BY created_at DESC").fetchall()
    conn.close()
    pdf_buffer = generate_pdf(threats)
    return send_file(pdf_buffer, download_name="SOC_Threats_7.2.7.pdf", as_attachment=True)

@app.route("/download/csv")
def download_csv():
    conn = get_db_connection()
    threats = conn.execute("SELECT * FROM threats ORDER BY created_at DESC").fetchall()
    conn.close()
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(threats[0].keys())
    for t in threats:
        writer.writerow(t)
    buffer.seek(0)
    return send_file(io.BytesIO(buffer.getvalue().encode()), download_name="SOC_Threats_7.2.7.csv", as_attachment=True)

@app.route("/download/json")
def download_json():
    conn = get_db_connection()
    threats = conn.execute("SELECT * FROM threats ORDER BY created_at DESC").fetchall()
    conn.close()
    data = [dict(t) for t in threats]
    return jsonify(data)

# ------------------ BACKGROUND THREAD ------------------
def background_fetch():
    while True:
        fetch_threats()
        time.sleep(300)  # every 5 mins

if __name__ == "__main__":
    # Initialize DB if not exists
    conn = get_db_connection()
    conn.execute('''CREATE TABLE IF NOT EXISTS threats (
        id INTEGER PRIMARY KEY,
        indicator TEXT,
        classification TEXT,
        c2 TEXT,
        recon TEXT,
        created_at TEXT
    )''')
    conn.commit()
    conn.close()
    threading.Thread(target=background_fetch, daemon=True).start()
    app.run(host="0.0.0.0", port=5000, debug=True)