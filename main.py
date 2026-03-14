import os
import io
import csv
import json
import sqlite3
import threading
import time
import random
import zipfile
from datetime import datetime

import requests
from flask import Flask, render_template_string, send_file, request, jsonify

from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors

# -----------------------
# Flask app initialization
# -----------------------
app = Flask(__name__)
DB_FILE = "cti_data_v4.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS indicators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator TEXT NOT NULL,
            type TEXT NOT NULL,
            source TEXT,
            severity TEXT,
            first_seen TEXT,
            last_seen TEXT,
            description TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# -----------------------
# Simulated CTI feeds
# -----------------------
def fetch_otx_data():
    data = []
    types = ["IP", "Domain", "Hash"]
    severities = ["Low", "Medium", "High", "Critical"]
    for _ in range(10):
        typ = random.choice(types)
        indicator = ""
        if typ == "IP":
            indicator = f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"
        elif typ == "Domain":
            indicator = f"malicious{random.randint(1,50)}.com"
        else:
            indicator = os.urandom(8).hex()
        data.append({
            "indicator": indicator,
            "type": typ,
            "source": "OTX",
            "severity": random.choice(severities),
            "first_seen": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "last_seen": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "description": f"Simulated {typ} from OTX feed."
        })
    return data

def fetch_abuseipdb_data():
    data = []
    severities = ["Low", "Medium", "High", "Critical"]
    for _ in range(10):
        ip = f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"
        data.append({
            "indicator": ip,
            "type": "IP",
            "source": "AbuseIPDB",
            "severity": random.choice(severities),
            "first_seen": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "last_seen": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "description": "Simulated IP from AbuseIPDB"
        })
    return data

def fetch_talos_data():
    data = []
    types = ["IP", "Domain"]
    severities = ["Low", "Medium", "High", "Critical"]
    for _ in range(10):
        typ = random.choice(types)
        indicator = ""
        if typ == "IP":
            indicator = f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"
        else:
            indicator = f"bad{random.randint(1,50)}.net"
        data.append({
            "indicator": indicator,
            "type": typ,
            "source": "Talos",
            "severity": random.choice(severities),
            "first_seen": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "last_seen": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "description": f"Simulated {typ} from Talos feed."
        })
    return data

# -----------------------
# Save to DB
# -----------------------
def save_data_to_db(records):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    for r in records:
        cursor.execute('''
            INSERT INTO indicators (indicator, type, source, severity, first_seen, last_seen, description)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (r["indicator"], r["type"], r["source"], r["severity"], r["first_seen"], r["last_seen"], r["description"]))
    conn.commit()
    conn.close()

# -----------------------
# Background update thread
# -----------------------
def update_loop(interval=300):
    while True:
        data = fetch_otx_data() + fetch_abuseipdb_data() + fetch_talos_data()
        save_data_to_db(data)
        time.sleep(interval)

threading.Thread(target=update_loop, daemon=True).start()

# -----------------------
# Dashboard Route
# -----------------------
@app.route("/")
def dashboard():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT id, indicator, type, source, severity, first_seen, last_seen FROM indicators ORDER BY last_seen DESC")
    rows = cursor.fetchall()
    conn.close()
    
    map_points = []
    for r in rows:
        lat = random.uniform(1.0, 7.5)
        lon = random.uniform(100.0, 119.0)
        map_points.append({
            "id": r[0],
            "indicator": r[1],
            "type": r[2],
            "source": r[3],
            "severity": r[4],
            "lat": lat,
            "lon": lon
        })
    
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT indicator, type, source, COUNT(*) as freq
        FROM indicators
        GROUP BY indicator
        ORDER BY freq DESC
        LIMIT 10
    ''')
    top10_rows = cursor.fetchall()
    conn.close()

    html_template = """[HTML from Part 2 as previously provided, unchanged]"""
    return render_template_string(html_template, rows=rows, map_points=map_points, top10=top10_rows)

# -----------------------
# Export Routes
# -----------------------
@app.route("/export/csv")
def export_csv():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM indicators")
    rows = cursor.fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID","Indicator","Type","Source","Severity","First Seen","Last Seen","Description"])
    writer.writerows(rows)
    output.seek(0)
    return send_file(io.BytesIO(output.getvalue().encode()), mimetype="text/csv", as_attachment=True, download_name="cti_export.csv")

@app.route("/export/json")
def export_json():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM indicators")
    rows = cursor.fetchall()
    conn.close()

    data = []
    for r in rows:
        data.append({
            "id": r[0],
            "indicator": r[1],
            "type": r[2],
            "source": r[3],
            "severity": r[4],
            "first_seen": r[5],
            "last_seen": r[6],
            "description": r[7]
        })
    return jsonify(data)

@app.route("/export/pdf")
def export_pdf():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT indicator, type, source, severity, first_seen, last_seen, description FROM indicators ORDER BY last_seen DESC")
    rows = cursor.fetchall()
    conn.close()

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    elements = []
    styles = getSampleStyleSheet()
    title_style = styles['Heading1']
    elements.append(Paragraph("CTI Dashboard Export", title_style))
    elements.append(Spacer(1, 12))
    table_data = [["Indicator","Type","Source","Severity","First Seen","Last Seen","Description"]]
    for r in rows:
        table_data.append(list(r))
    table = Table(table_data, repeatRows=1)
    table.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,0),colors.darkblue),
        ('TEXTCOLOR',(0,0),(-1,0),colors.whitesmoke),
        ('ALIGN',(0,0),(-1,-1),'LEFT'),
        ('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'),
        ('BOTTOMPADDING',(0,0),(-1,0),12),
        ('BACKGROUND',(0,1),(-1,-1),colors.HexColor('#2b2b3b')),
        ('GRID',(0,0),(-1,-1),0.5,colors.grey),
    ]))
    elements.append(table)
    doc.build(elements)
    buffer.seek(0)
    return send_file(buffer, mimetype='application/pdf', as_attachment=True, download_name="cti_export.pdf")

# -----------------------
# Manual Refresh
# -----------------------
@app.route("/refresh")
def manual_refresh():
    data = fetch_otx_data() + fetch_abuseipdb_data() + fetch_talos_data()
    save_data_to_db(data)
    return "Data manually refreshed at " + datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

# -----------------------
# Charts
# -----------------------
@app.route("/charts")
def charts_dashboard():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT severity, COUNT(*) FROM indicators GROUP BY severity")
    severity_rows = cursor.fetchall()
    cursor.execute("SELECT type, COUNT(*) FROM indicators GROUP BY type")
    type_rows = cursor.fetchall()
    conn.close()

    severity_data = {row[0]: row[1] for row in severity_rows}
    type_data = {row[0]: row[1] for row in type_rows}

    severities = ["Low", "Medium", "High", "Critical"]
    severity_counts = [severity_data.get(s, 0) for s in severities]
    types = ["IP", "Domain", "Hash"]
    type_counts = [type_data.get(t, 0) for t in types]

    html_template = """[HTML/JS Chart code from Part 3 as previously provided]"""
    return render_template_string(html_template, severities=severities, severity_counts=severity_counts,
                                  types=types, type_counts=type_counts)

# -----------------------
# Compressed IP rules download
# -----------------------
@app.route("/download/rules")
def download_rules():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT indicator, type, source, severity FROM indicators")
    rows = cursor.fetchall()
    conn.close()

    mem_zip = io.BytesIO()
    with zipfile.ZipFile(mem_zip, 'w', zipfile.ZIP_DEFLATED) as zf:
        rules_content = "\n".join([f"{r[0]},{r[1]},{r[2]},{r[3]}" for r in rows])
        zf.writestr("ip_rules.csv", rules_content)
    mem_zip.seek(0)
    return send_file(mem_zip, mimetype='application/zip', as_attachment=True, download_name="ip_rules.zip")

# -----------------------
# Auto-refresh interval
# -----------------------
update_interval = 300
@app.route("/set_interval")
def set_interval():
    global update_interval
    try:
        sec = int(request.args.get("seconds", 300))
        update_interval = sec
        return f"Update interval set to {sec} seconds"
    except Exception as e:
        return str(e)

# -----------------------
# Run app
# -----------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)