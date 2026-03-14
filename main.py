import os
import io
import csv
import json
import zipfile
import threading
import requests
import sqlite3
from datetime import datetime
from flask import Flask, render_template_string, send_file, jsonify, request
from reportlab.platypus import SimpleDocTemplate, Table
from reportlab.lib.pagesizes import landscape, letter

app = Flask(__name__)

# ====== CONFIG ======
THREAT_FEEDS = {
    "otx": "https://otx.alienvault.com/api/v1/indicators/export",
    "abuseipdb": "https://api.abuseipdb.com/api/v2/check",
    "talos": "https://talosintelligence.com/some_endpoint"
}
DISCLAIMER = "Developed and analysed by darkgrid@redshark.my using publicly available sources"

DB_PATH = "soc_data.db"

# ====== DATABASE ======
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS threats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            domain TEXT,
            severity TEXT,
            source TEXT,
            lat REAL,
            lon REAL,
            timestamp TEXT
        )
    ''')
    conn.commit()
    conn.close()

def insert_threat(ip, domain, severity, source, lat=0.0, lon=0.0):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        INSERT INTO threats (ip, domain, severity, source, lat, lon, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (ip, domain, severity, source, lat, lon, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()

def get_threats():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM threats ORDER BY timestamp DESC")
    rows = c.fetchall()
    conn.close()
    return rows

# ====== FETCH THREAT INTEL (PLACEHOLDERS) ======
def fetch_otx():
    try:
        r = requests.get(THREAT_FEEDS['otx'])
        if r.status_code == 200:
            data = r.json()
            for item in data.get("indicators", []):
                insert_threat(item.get("ip"), item.get("domain"), "Medium", "OTX", lat=0.0, lon=0.0)
    except Exception as e:
        print("OTX fetch error:", e)

def fetch_abuseipdb(ip_list=None):
    headers = {"Key": "", "Accept": "application/json"}
    ips = ip_list or ["8.8.8.8"]
    for ip in ips:
        try:
            r = requests.get(f"{THREAT_FEEDS['abuseipdb']}?ipAddress={ip}", headers=headers)
            if r.status_code == 200:
                insert_threat(ip, "", "High", "AbuseIPDB", lat=0.0, lon=0.0)
        except Exception as e:
            print("AbuseIPDB fetch error:", e)

def start_fetch_thread():
    def fetch_loop():
        while True:
            fetch_otx()
            fetch_abuseipdb()
            threading.Event().wait(3600)
    t = threading.Thread(target=fetch_loop, daemon=True)
    t.start()

# ====== PDF & CSV Export ======
def generate_pdf():
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=landscape(letter))
    data = [["ID", "IP", "Domain", "Severity", "Source", "Lat", "Lon", "Timestamp"]]
    for row in get_threats():
        data.append(list(row))
    table = Table(data)
    doc.build([table])
    buffer.seek(0)
    return buffer

def generate_csv_zip():
    csv_buffer = io.StringIO()
    writer = csv.writer(csv_buffer)
    writer.writerow(["ID","IP","Domain","Severity","Source","Lat","Lon","Timestamp"])
    for row in get_threats():
        writer.writerow(list(row))
    csv_bytes = csv_buffer.getvalue().encode()
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("threats.csv", csv_bytes)
    zip_buffer.seek(0)
    return zip_buffer

# ====== ROUTES ======
@app.route("/")
def dashboard():
    threats = get_threats()
    html = '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <title>Advanced SOC Dashboard</title>
        <meta charset="utf-8">
        <link rel="stylesheet" href="https://unpkg.com/leaflet/dist/leaflet.css"/>
        <script src="https://unpkg.com/leaflet/dist/leaflet.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            body {background: #0f0f0f; color: #f0f0f0; font-family: Arial;}
            table {border-collapse: collapse; width: 100%;}
            th, td {border: 1px solid #444; padding: 6px; text-align: left; word-wrap: break-word;}
            th {background: #222;}
            .blink {animation: blinker 1s linear infinite; color: #ff4d4d; font-weight: bold;}
            @keyframes blinker {50% {opacity: 0;}}
            #map {height: 400px; margin-bottom: 20px;}
            canvas {background: #111; color: #f0f0f0; margin-bottom: 20px;}
        </style>
    </head>
    <body>
        <h1>CTI HIGHLIGHTS AT {{ timestamp }}</h1>
        <p>{{ disclaimer }}</p>

        <div id="map"></div>
        <script>
            var map = L.map('map').setView([20,0], 2);
            L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {attribution: ''}).addTo(map);
            var threats = {{ threats_json|safe }};
            threats.forEach(function(t){
                var color = t.severity=="High"?"red":"orange";
                var circle = L.circle([t.lat, t.lon], {color: color, radius:50000}).addTo(map);
                if(t.severity=="High"){
                    circle.bindPopup("Critical: "+t.ip).openPopup();
                }
            });
        </script>

        <canvas id="severityChart" width="400" height="150"></canvas>
        <script>
            var ctx = document.getElementById('severityChart').getContext('2d');
            var threatData = {{ chart_data|safe }};
            var severityChart = new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: Object.keys(threatData),
                    datasets: [{
                        label: 'Threat Count',
                        data: Object.values(threatData),
                        backgroundColor: ['#ff4d4d','#ffa500','#00bfff']
                    }]
                },
                options: {responsive:true, plugins:{legend:{display:false}}, scales:{y:{beginAtZero:true}}}
            });
        </script>

        <table>
            <tr><th>ID</th><th>IP</th><th>Domain</th><th>Severity</th><th>Source</th><th>Lat</th><th>Lon</th><th>Timestamp</th></tr>
            {% for t in threats %}
            <tr>
                <td>{{ t[0] }}</td>
                <td>{% if t[3]=="High" %}<span class="blink">{{ t[1] }}</span>{% else %}{{ t[1] }}{% endif %}</td>
                <td>{{ t[2] }}</td>
                <td>{{ t[3] }}</td>
                <td>{{ t[4] }}</td>
                <td>{{ t[5] }}</td>
                <td>{{ t[6] }}</td>
                <td>{{ t[7] }}</td>
            </tr>
            {% endfor %}
        </table>

        <a href="/export/pdf" target="_blank">Download PDF Report</a> |
        <a href="/export/csvzip" target="_blank">Download CSV (ZIP)</a>
    </body>
    </html>
    '''
    # Prepare chart data
    chart_data = {}
    for t in threats:
        severity = t[3]
        chart_data[severity] = chart_data.get(severity,0)+1
    return render_template_string(html, threats=threats, threats_json=json.dumps([{"ip":t[1],"lat":t[5],"lon":t[6],"severity":t[3]} for t in threats]), chart_data=json.dumps(chart_data), timestamp=datetime.utcnow().isoformat(), disclaimer=DISCLAIMER)

@app.route("/export/pdf")
def export_pdf():
    pdf_buffer = generate_pdf()
    return send_file(pdf_buffer, as_attachment=True, download_name="threats_report.pdf", mimetype="application/pdf")

@app.route("/export/csvzip")
def export_csv_zip():
    zip_buffer = generate_csv_zip()
    return send_file(zip_buffer, as_attachment=True, download_name="threats.zip", mimetype="application/zip")

@app.route("/api/threats")
def api_threats():
    data = [{"id": t[0], "ip": t[1], "domain": t[2], "severity": t[3], "source": t[4], "lat": t[5], "lon": t[6], "timestamp": t[7]} for t in get_threats()]
    return jsonify(data)

# ====== START SERVER ======
if __name__ == "__main__":
    init_db()
    start_fetch_thread()
    app.run(host="0.0.0.0", port=5000, debug=True)