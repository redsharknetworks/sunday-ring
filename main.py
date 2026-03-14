import os
import io
import csv
import json
import sqlite3
import threading
import time
import random
from datetime import datetime, timedelta

import requests
from flask import Flask, render_template_string, send_file, request, jsonify

# ReportLab for PDF generation
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors

# Initialize Flask app
app = Flask(__name__)

# Database setup
DB_FILE = "cti_data.db"

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

# Helper functions
def fetch_external_data():
    """Simulate fetching CTI data from external sources"""
    sources = ["OTX", "AbuseIPDB", "Talos"]
    types = ["IP", "Domain", "Hash"]
    severities = ["Low", "Medium", "High", "Critical"]
    
    data = []
    for _ in range(20):
        indicator_type = random.choice(types)
        indicator = ""
        if indicator_type == "IP":
            indicator = f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"
        elif indicator_type == "Domain":
            indicator = f"malicious{random.randint(1,100)}.com"
        else:
            indicator = f"{os.urandom(8).hex()}"
        
        record = {
            "indicator": indicator,
            "type": indicator_type,
            "source": random.choice(sources),
            "severity": random.choice(severities),
            "first_seen": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "last_seen": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "description": f"Sample {indicator_type} from CTI feed."
        }
        data.append(record)
    
    return data

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

# Background thread to fetch and update data periodically
def update_data_loop(interval=300):
    while True:
        data = fetch_external_data()
        save_data_to_db(data)
        time.sleep(interval)

threading.Thread(target=update_data_loop, daemon=True).start()

# Flask routes
@app.route("/")
def dashboard():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT indicator, type, source, severity, first_seen, last_seen FROM indicators ORDER BY last_seen DESC")
    rows = cursor.fetchall()
    conn.close()
    
    html_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>CTI Dashboard v3</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #1e1e2f; color: #f0f0f0; }
            table { width: 100%; border-collapse: collapse; margin-top: 20px; }
            th, td { border: 1px solid #444; padding: 8px; text-align: left; }
            th { background-color: #282843; }
            tr:nth-child(even) { background-color: #2b2b3b; }
            .high { color: #ff4c4c; font-weight: bold; }
            .medium { color: #ffa500; }
            .low { color: #00ffcc; }
        </style>
    </head>
    <body>
        <h1>CTI Dashboard v3</h1>
        <table>
            <tr>
                <th>Indicator</th>
                <th>Type</th>
                <th>Source</th>
                <th>Severity</th>
                <th>First Seen</th>
                <th>Last Seen</th>
            </tr>
            {% for row in rows %}
            <tr>
                <td>{{ row[0] }}</td>
                <td>{{ row[1] }}</td>
                <td>{{ row[2] }}</td>
                <td class="{{ row[3]|lower }}">{{ row[3] }}</td>
                <td>{{ row[4] }}</td>
                <td>{{ row[5] }}</td>
            </tr>
            {% endfor %}
        </table>
        <p>Disclaimer: Developed and analysed by darkgrid@redshark.my using publicly available sources.</p>
    </body>
    </html>
    """
    return render_template_string(html_template, rows=rows)

# Export routes
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

# PDF export route
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
    normal_style = styles['Normal']
    
    elements.append(Paragraph("CTI Dashboard Export", title_style))
    elements.append(Spacer(1, 12))
    
    # Build table data
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


# Route for top 10 indicators by frequency
@app.route("/top10")
def top10():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT indicator, type, source, COUNT(*) as freq
        FROM indicators
        GROUP BY indicator
        ORDER BY freq DESC
        LIMIT 10
    ''')
    rows = cursor.fetchall()
    conn.close()
    
    html_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Top 10 CTI Indicators</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #1e1e2f; color: #f0f0f0; }
            table { width: 60%; border-collapse: collapse; margin: 30px auto; }
            th, td { border: 1px solid #444; padding: 8px; text-align: left; }
            th { background-color: #282843; }
            tr:nth-child(even) { background-color: #2b2b3b; }
        </style>
    </head>
    <body>
        <h1 style="text-align:center;">Top 10 CTI Indicators</h1>
        <table>
            <tr>
                <th>Indicator</th>
                <th>Type</th>
                <th>Source</th>
                <th>Frequency</th>
            </tr>
            {% for row in rows %}
            <tr>
                <td>{{ row[0] }}</td>
                <td>{{ row[1] }}</td>
                <td>{{ row[2] }}</td>
                <td>{{ row[3] }}</td>
            </tr>
            {% endfor %}
        </table>
    </body>
    </html>
    """
    return render_template_string(html_template, rows=rows)


# Interactive map route
@app.route("/map")
def map_dashboard():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT indicator, type, severity FROM indicators")
    rows = cursor.fetchall()
    conn.close()
    
    # Prepare map points for JS (dummy lat/lon for demonstration)
    points = []
    for r in rows:
        lat = random.uniform(-5, 5) + 3  # Adjust for Malaysia-like region
        lon = random.uniform(100, 120) + 101
        points.append({
            "indicator": r[0],
            "type": r[1],
            "severity": r[2],
            "lat": lat,
            "lon": lon
        })
    
    html_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>CTI Map Dashboard</title>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
        <style>
            body { margin:0; padding:0; }
            #map { width: 100%; height: 90vh; }
            .high { color: red; font-weight:bold; }
            .medium { color: orange; }
            .low { color: green; }
            .critical { color: darkred; font-weight:bold; text-decoration: blink; }
        </style>
        <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
    </head>
    <body>
        <h2 style="text-align:center;">CTI Map Dashboard</h2>
        <div id="map"></div>
        <script>
            var map = L.map('map').setView([4.0, 102.0], 6);
            L.tileLayer('https://tile.openstreetmap.org/{z}/{x}/{y}.png', {
                maxZoom: 18
            }).addTo(map);

            var points = {{ points|tojson }};

            points.forEach(function(p) {
                var color = "blue";
                if(p.severity.toLowerCase() === "high") color = "orange";
                if(p.severity.toLowerCase() === "critical") color = "red";
                if(p.severity.toLowerCase() === "medium") color = "yellow";
                if(p.severity.toLowerCase() === "low") color = "green";

                L.circleMarker([p.lat, p.lon], {
                    radius: 8,
                    color: color,
                    fillColor: color,
                    fillOpacity: 0.7
                }).bindPopup("<b>Indicator:</b> " + p.indicator + "<br><b>Type:</b> " + p.type + "<br><b>Severity:</b> " + p.severity)
                  .addTo(map);
            });
        </script>
        <p style="text-align:center;">Disclaimer: Developed and analysed by darkgrid@redshark.my using publicly available sources.</p>
    </body>
    </html>
    """
    return render_template_string(html_template, points=points)

# Route for dynamic charts (bar chart for severity counts)
@app.route("/charts")
def charts_dashboard():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT severity, COUNT(*) FROM indicators GROUP BY severity")
    rows = cursor.fetchall()
    conn.close()
    
    # Prepare data for JS chart
    chart_data = {row[0]: row[1] for row in rows}
    severities = ["Low", "Medium", "High", "Critical"]
    counts = [chart_data.get(s, 0) for s in severities]
    
    html_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>CTI Severity Chart</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            body { font-family: Arial, sans-serif; background-color: #1e1e2f; color: #f0f0f0; text-align:center; }
            canvas { max-width: 800px; margin: 50px auto; background-color: #2b2b3b; padding: 20px; border-radius: 10px; }
        </style>
    </head>
    <body>
        <h1>CTI Indicators Severity Chart</h1>
        <canvas id="severityChart"></canvas>
        <script>
            var ctx = document.getElementById('severityChart').getContext('2d');
            var chart = new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: {{ severities|tojson }},
                    datasets: [{
                        label: 'Number of Indicators',
                        data: {{ counts|tojson }},
                        backgroundColor: ['#00ffcc','#ffa500','#ff4c4c','#8b0000'],
                        borderColor: ['#00ffcc','#ffa500','#ff4c4c','#8b0000'],
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    scales: {
                        y: { beginAtZero: true }
                    }
                }
            });
        </script>
        <p>Disclaimer: Developed and analysed by darkgrid@redshark.my using publicly available sources.</p>
    </body>
    </html>
    """
    return render_template_string(html_template, severities=severities, counts=counts)


# Route for manual refresh
@app.route("/refresh")
def manual_refresh():
    data = fetch_external_data()
    save_data_to_db(data)
    return "Data manually refreshed at " + datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")


# Auto-refresh interval control route (optional, can set via query)
@app.route("/set_interval")
def set_interval():
    try:
        interval = int(request.args.get("seconds", 300))
        global update_interval
        update_interval = interval
        return f"Update interval set to {interval} seconds"
    except Exception as e:
        return str(e)


# Home route redirect helper (optional)
@app.route("/home")
def home_redirect():
    return dashboard()


# Run Flask app
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)