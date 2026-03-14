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

# ReportLab for PDF generation
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors

# Flask app initialization
app = Flask(__name__)

# Database
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
    """Simulate OTX feed"""
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
    """Simulate AbuseIPDB feed"""
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
    """Simulate Talos feed"""
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
    
    # Prepare map points with Malaysia lat/lon (approximate)
    map_points = []
    for r in rows:
        lat = random.uniform(1.0, 7.5)      # Malaysia latitude approx
        lon = random.uniform(100.0, 119.0)  # Malaysia longitude approx
        map_points.append({
            "id": r[0],
            "indicator": r[1],
            "type": r[2],
            "source": r[3],
            "severity": r[4],
            "lat": lat,
            "lon": lon
        })
    
    html_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>CTI Dashboard v4</title>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
        <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
        <style>
            body { font-family: Arial, sans-serif; background-color: #1e1e2f; color: #f0f0f0; margin:0; padding:0;}
            #map { width: 100%; height: 500px; }
            table { width: 95%; border-collapse: collapse; margin: 20px auto; }
            th, td { border: 1px solid #444; padding: 8px; text-align: left; }
            th { background-color: #282843; }
            tr:nth-child(even) { background-color: #2b2b3b; }
            .low { color: #00ffcc; }
            .medium { color: #ffa500; }
            .high { color: #ff4c4c; font-weight: bold; }
            .critical { color: #ff0000; font-weight: bold; animation: blink 1s infinite; }
            @keyframes blink { 50% { opacity: 0; } }
            .refresh-btn { background-color: #282843; color: #f0f0f0; padding: 8px 12px; border:none; cursor:pointer; margin:10px; border-radius:5px; }
            .refresh-btn:hover { background-color: #3c3c5c; }
        </style>
    </head>
    <body>
        <h1 style="text-align:center;">CTI Dashboard v4</h1>
        <button class="refresh-btn" onclick="manualRefresh()">Manual Refresh</button>
        <div id="map"></div>

        <h2 style="text-align:center;">Latest Indicators</h2>
        <table>
            <tr>
                <th>Indicator</th><th>Type</th><th>Source</th><th>Severity</th><th>First Seen</th><th>Last Seen</th>
            </tr>
            {% for r in rows %}
            <tr>
                <td>{{ r[1] }}</td>
                <td>{{ r[2] }}</td>
                <td>{{ r[3] }}</td>
                <td class="{{ r[4]|lower }}">{{ r[4] }}</td>
                <td>{{ r[5] }}</td>
                <td>{{ r[6] }}</td>
            </tr>
            {% endfor %}
        </table>

        <h2 style="text-align:center;">Top 10 Indicators</h2>
        <table>
            <tr>
                <th>Indicator</th><th>Type</th><th>Source</th><th>Frequency</th>
            </tr>
            {% for t in top10 %}
            <tr>
                <td>{{ t[0] }}</td>
                <td>{{ t[1] }}</td>
                <td>{{ t[2] }}</td>
                <td>{{ t[3] }}</td>
            </tr>
            {% endfor %}
        </table>

        <p style="text-align:center;">Disclaimer: Developed and analysed by darkgrid@redshark.my using publicly available sources.</p>

        <script>
            var map = L.map('map').setView([4.0, 102.0], 6);
            L.tileLayer('https://tile.openstreetmap.org/{z}/{x}/{y}.png', { maxZoom: 18 }).addTo(map);

            var points = {{ map_points|tojson }};
            points.forEach(function(p) {
                var color = "blue";
                if(p.severity.toLowerCase() === "low") color = "#00ffcc";
                if(p.severity.toLowerCase() === "medium") color = "#ffa500";
                if(p.severity.toLowerCase() === "high") color = "#ff4c4c";
                if(p.severity.toLowerCase() === "critical") color = "#ff0000";

                var marker = L.circleMarker([p.lat, p.lon], {
                    radius: 10,
                    color: color,
                    fillColor: color,
                    fillOpacity: 0.7
                }).bindPopup("<b>Indicator:</b> " + p.indicator + "<br><b>Type:</b> " + p.type + "<br><b>Severity:</b> " + p.severity);
                marker.addTo(map);
                if(p.severity.toLowerCase() === "critical") {
                    var el = marker.getElement();
                    if(el) el.style.animation = "blink 1s infinite";
                }
            });

            function manualRefresh() {
                fetch("/refresh").then(resp => resp.text()).then(data => alert(data));
            }
        </script>
    </body>
    </html>
    """

    # Compute top 10 indicators
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
# Manual refresh route
# -----------------------
@app.route("/refresh")
def manual_refresh():
    data = fetch_otx_data() + fetch_abuseipdb_data() + fetch_talos_data()
    save_data_to_db(data)
    return "Data manually refreshed at " + datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

# -----------------------
# Dynamic Charts Route
# -----------------------
@app.route("/charts")
def charts_dashboard():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    # Severity counts
    cursor.execute("SELECT severity, COUNT(*) FROM indicators GROUP BY severity")
    severity_rows = cursor.fetchall()
    # Type counts
    cursor.execute("SELECT type, COUNT(*) FROM indicators GROUP BY type")
    type_rows = cursor.fetchall()
    conn.close()

    severity_data = {row[0]: row[1] for row in severity_rows}
    type_data = {row[0]: row[1] for row in type_rows}

    severities = ["Low", "Medium", "High", "Critical"]
    severity_counts = [severity_data.get(s, 0) for s in severities]

    types = ["IP", "Domain", "Hash"]
    type_counts = [type_data.get(t, 0) for t in types]

    html_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>CTI Charts v4</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            body { font-family: Arial, sans-serif; background-color: #1e1e2f; color: #f0f0f0; text-align:center; }
            canvas { max-width: 800px; margin: 30px auto; background-color: #2b2b3b; padding: 20px; border-radius: 10px; }
        </style>
    </head>
    <body>
        <h1>CTI Dashboard Charts</h1>

        <h2>Severity Distribution</h2>
        <canvas id="severityChart"></canvas>

        <h2>Indicator Type Distribution</h2>
        <canvas id="typeChart"></canvas>

        <p>Disclaimer: Developed and analysed by darkgrid@redshark.my using publicly available sources.</p>

        <script>
            var ctx1 = document.getElementById('severityChart').getContext('2d');
            new Chart(ctx1, {
                type: 'bar',
                data: {
                    labels: {{ severities|tojson }},
                    datasets: [{
                        label: 'Number of Indicators',
                        data: {{ severity_counts|tojson }},
                        backgroundColor: ['#00ffcc','#ffa500','#ff4c4c','#8b0000'],
                        borderColor: ['#00ffcc','#ffa500','#ff4c4c','#8b0000'],
                        borderWidth: 1
                    }]
                },
                options: { responsive: true, scales: { y: { beginAtZero: true } } }
            });

            var ctx2 = document.getElementById('typeChart').getContext('2d');
            new Chart(ctx2, {
                type: 'pie',
                data: {
                    labels: {{ types|tojson }},
                    datasets: [{
                        label: 'Type Distribution',
                        data: {{ type_counts|tojson }},
                        backgroundColor: ['#00ffcc','#ffa500','#ff4c4c'],
                        borderWidth: 1
                    }]
                },
                options: { responsive: true }
            });
        </script>
    </body>
    </html>
    """
    return render_template_string(html_template, severities=severities, severity_counts=severity_counts,
                                  types=types, type_counts=type_counts)

# -----------------------
# Compressed IP Rules Download
# -----------------------
@app.route("/download/rules")
def download_rules():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT indicator, type, source, severity FROM indicators")
    rows = cursor.fetchall()
    conn.close()

    # Create in-memory zip
    mem_zip = io.BytesIO()
    with zipfile.ZipFile(mem_zip, 'w', zipfile.ZIP_DEFLATED) as zf:
        rules_content = "\n".join([f"{r[0]},{r[1]},{r[2]},{r[3]}" for r in rows])
        zf.writestr("ip_rules.csv", rules_content)
    mem_zip.seek(0)
    return send_file(mem_zip, mimetype='application/zip', as_attachment=True, download_name="ip_rules.zip")

# -----------------------
# Auto-refresh interval control
# -----------------------
update_interval = 300  # default 5 min

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
# Run Flask App
# -----------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)