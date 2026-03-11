import os
import random
from datetime import datetime, timedelta
from flask import Flask, jsonify, render_template_string, send_file, request
import csv, io, json
import requests

app = Flask(__name__)

# --------- Config ---------
OTX_API_KEY = os.environ.get("OTX_API_KEY")  # AlienVault OTX API
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY")  # AbuseIPDB API

# For demo: Malaysian coordinates (lat/lng roughly for cities)
MALAYSIA_COORDS = [
    {"city": "Kuala Lumpur", "lat": 3.1390, "lng": 101.6869},
    {"city": "Penang", "lat": 5.4164, "lng": 100.3327},
    {"city": "Johor Bahru", "lat": 1.4927, "lng": 103.7414},
    {"city": "Kota Kinabalu", "lat": 5.9804, "lng": 116.0735},
    {"city": "Kuching", "lat": 1.5533, "lng": 110.3592}
]

# --------- Simulated SOC Events ---------
ASSETS = ["Server-1", "Server-2", "Laptop-1", "Firewall-1", "DB-Prod"]
EVENT_TYPES = ["Malware", "Suspicious Login", "Phishing", "Port Scan", "Data Exfiltration"]

def generate_events(n=50):
    events = []
    now = datetime.utcnow()
    for _ in range(n):
        event_time = now - timedelta(minutes=random.randint(0, 720))
        events.append({
            "timestamp": event_time.strftime("%Y-%m-%d %H:%M:%S"),
            "asset": random.choice(ASSETS),
            "type": random.choice(EVENT_TYPES),
            "severity": random.choice(["Low","Medium","High","Critical"]),
            "source_ip": f"103.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}",
            "city": random.choice(MALAYSIA_COORDS)["city"]
        })
    return events

EVENTS = generate_events(100)

# --------- OTX Lookup ---------
def check_otx(ip):
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    headers = {"X-OTX-API-KEY": OTX_KEY} if OTX_KEY else {}
    try:
        resp = requests.get(url, headers=headers, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            pulses = [p["name"] for p in data.get("pulse_info", {}).get("pulses", [])]
            return pulses[:5]  # top 5 pulses
    except Exception as e:
        return []
    return []

# --------- AbuseIPDB Lookup ---------
def check_abuseipdb(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": ABUSEIP_KEY,
        "Accept": "application/json"
    }
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=5)
        if resp.status_code == 200:
            data = resp.json()["data"]
            return {"abuseConfidence": data["abuseConfidenceScore"], "country": data["countryCode"]}
    except Exception as e:
        return {}
    return {}

# --------- Routes ---------
@app.route("/")
def dashboard():
    # Chart severity counts
    severity_count = {"Low":0, "Medium":0, "High":0, "Critical":0}
    for e in EVENTS:
        severity_count[e["severity"]] += 1

    template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>SOC Dashboard - Malaysia</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
        <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
        <style>
            body { font-family: Arial; background-color: #0b1f3f; color: #ffffff; margin: 0; padding: 0;}
            h1 { text-align: center; color: #00bfff; padding: 20px 0; }
            .container { width: 90%; margin: auto; }
            canvas { background-color: #112d4e; border-radius: 8px; margin-bottom: 40px; }
            table { width: 100%; border-collapse: collapse; margin-bottom: 40px; }
            th, td { border: 1px solid #00bfff; padding: 8px; text-align: left; }
            th { background-color: #0b3d91; }
            tr:nth-child(even) { background-color: #0e4a6b; }
            #map { height: 400px; border-radius: 8px; margin-bottom: 40px; }
            a.button { padding: 10px 20px; background-color: #00bfff; color: #000; border-radius: 5px; text-decoration: none; margin-right: 10px;}
        </style>
    </head>
    <body>
        <h1>SOC Monitoring Dashboard - Malaysia</h1>
        <div class="container">
            <canvas id="severityChart" height="100"></canvas>
            <div id="map"></div>
            <table>
                <tr>
                    <th>Timestamp</th>
                    <th>Asset</th>
                    <th>Event Type</th>
                    <th>Severity</th>
                    <th>Source IP</th>
                    <th>OTX Pulses</th>
                    <th>AbuseIPDB</th>
                </tr>
                {% for e in events %}
                <tr>
                    <td>{{ e.timestamp }}</td>
                    <td>{{ e.asset }}</td>
                    <td>{{ e.type }}</td>
                    <td>{{ e.severity }}</td>
                    <td>{{ e.source_ip }}</td>
                    <td>{{ e.otx|join(', ') }}</td>
                    <td>{{ e.abuse.get('abuseConfidence', '') }}%</td>
                </tr>
                {% endfor %}
            </table>
            <a href="/download/csv" class="button">Download CSV</a>
            <a href="/download/json" class="button">Download JSON</a>
        </div>

        <script>
        const ctx = document.getElementById('severityChart').getContext('2d');
        new Chart(ctx, {
            type: 'bar',
            data: {
                labels: {{ severity_labels|tojson }},
                datasets: [{
                    label: 'Event Count by Severity',
                    data: {{ severity_values|tojson }},
                    backgroundColor: ['#00ff00','#ffff00','#ff8000','#ff0000']
                }]
            },
            options: {
                responsive: true,
                plugins: { legend: { display: false } },
                scales: { y: { beginAtZero: true, ticks: { color: '#ffffff' } },
                          x: { ticks: { color: '#ffffff' } } }
            }
        });

        // Malaysia Heatmap using Leaflet
        var map = L.map('map').setView([4.2105, 101.9758], 6);
        L.tileLayer('https://tile.openstreetmap.org/{z}/{x}/{y}.png', { maxZoom: 18 }).addTo(map);
        var events = {{ events|tojson }};
        events.forEach(e => {
            const city_coords = {{ city_coords|tojson }};
            const coord = city_coords.find(c => c.city === e.city);
            if(coord) {
                L.circle([coord.lat, coord.lng], {
                    color: 'red',
                    fillColor: '#f03',
                    fillOpacity: 0.5,
                    radius: 5000
                }).addTo(map).bindPopup(`${e.asset}<br>${e.type}<br>${e.severity}`);
            }
        });
        </script>
    </body>
    </html>
    """
    # Fetch OTX / AbuseIPDB data for each event
    for e in EVENTS:
        e["otx"] = check_otx(e["source_ip"])
        e["abuse"] = check_abuseipdb(e["source_ip"])

    return render_template_string(template, 
                                  events=sorted(EVENTS, key=lambda x:x["timestamp"], reverse=True),
                                  severity_labels=list(severity_count.keys()),
                                  severity_values=list(severity_count.values()),
                                  city_coords=MALAYSIA_COORDS
                                 )

@app.route("/download/csv")
def download_csv():
    si = io.StringIO()
    cw = csv.DictWriter(si, fieldnames=["timestamp","asset","type","severity","source_ip","otx","abuse"])
    cw.writeheader()
    cw.writerows(EVENTS)
    output = io.BytesIO()
    output.write(si.getvalue().encode("utf-8"))
    output.seek(0)
    return send_file(output, mimetype="text/csv", download_name="soc_events.csv", as_attachment=True)

@app.route("/download/json")
def download_json():
    output = io.BytesIO()
    output.write(json.dumps(EVENTS, indent=2).encode("utf-8"))
    output.seek(0)
    return send_file(output, mimetype="application/json", download_name="soc_events.json", as_attachment=True)

# ------------------ Run ------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))  # Railway uses PORT env
    app.run(host="0.0.0.0", port=port, debug=True)