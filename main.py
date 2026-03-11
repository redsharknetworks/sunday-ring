import os
import random
from datetime import datetime, timedelta
from flask import Flask, jsonify, render_template_string, send_file
import csv
import io
import json

app = Flask(__name__)

# Simulate SOC events (for demo purposes)
ASSETS = ["Server-1", "Server-2", "Laptop-1", "Firewall-1", "DB-Prod"]
EVENT_TYPES = ["Malware", "Suspicious Login", "Phishing", "Port Scan", "Data Exfiltration"]

def generate_events(n=50):
    """Generate random SOC events"""
    events = []
    now = datetime.utcnow()
    for _ in range(n):
        event_time = now - timedelta(minutes=random.randint(0, 720))
        events.append({
            "timestamp": event_time.strftime("%Y-%m-%d %H:%M:%S"),
            "asset": random.choice(ASSETS),
            "type": random.choice(EVENT_TYPES),
            "severity": random.choice(["Low", "Medium", "High", "Critical"])
        })
    return events

# In-memory store
EVENTS = generate_events(100)

# ------------------ Routes ------------------

@app.route("/")
def dashboard():
    """Render SOC dashboard with charts"""
    # Prepare chart data
    severity_count = {"Low":0, "Medium":0, "High":0, "Critical":0}
    for e in EVENTS:
        severity_count[e["severity"]] += 1

    template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>SOC Monitoring Dashboard</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            body { font-family: Arial; background-color: #0b1f3f; color: #ffffff; margin: 0; padding: 0;}
            h1 { text-align: center; color: #00bfff; padding: 20px 0; }
            .container { width: 90%; margin: auto; }
            canvas { background-color: #112d4e; border-radius: 8px; margin-bottom: 40px; }
            table { width: 100%; border-collapse: collapse; margin-bottom: 40px; }
            th, td { border: 1px solid #00bfff; padding: 8px; text-align: left; }
            th { background-color: #0b3d91; }
            tr:nth-child(even) { background-color: #0e4a6b; }
            a.button { padding: 10px 20px; background-color: #00bfff; color: #000; border-radius: 5px; text-decoration: none; margin-right: 10px;}
        </style>
    </head>
    <body>
        <h1>SOC Monitoring Dashboard</h1>
        <div class="container">
            <canvas id="severityChart" height="100"></canvas>
            <table>
                <tr>
                    <th>Timestamp</th>
                    <th>Asset</th>
                    <th>Event Type</th>
                    <th>Severity</th>
                </tr>
                {% for e in events %}
                <tr>
                    <td>{{ e.timestamp }}</td>
                    <td>{{ e.asset }}</td>
                    <td>{{ e.type }}</td>
                    <td>{{ e.severity }}</td>
                </tr>
                {% endfor %}
            </table>
            <a href="/download/csv" class="button">Download CSV</a>
            <a href="/download/json" class="button">Download JSON</a>
        </div>

        <script>
        const ctx = document.getElementById('severityChart').getContext('2d');
        const severityChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: {{ severity_labels|tojson }},
                datasets: [{
                    label: 'Event Count by Severity',
                    data: {{ severity_values|tojson }},
                    backgroundColor: ['#00ff00','#ffff00','#ff8000','#ff0000'],
                    borderColor: '#ffffff',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                plugins: { legend: { display: false } },
                scales: { y: { beginAtZero: true, ticks: { color: '#ffffff' } },
                          x: { ticks: { color: '#ffffff' } } }
            }
        });
        </script>
    </body>
    </html>
    """
    return render_template_string(template, 
                                  events=sorted(EVENTS, key=lambda x: x["timestamp"], reverse=True),
                                  severity_labels=list(severity_count.keys()),
                                  severity_values=list(severity_count.values())
                                 )

@app.route("/download/csv")
def download_csv():
    """Download events as CSV"""
    si = io.StringIO()
    cw = csv.DictWriter(si, fieldnames=["timestamp","asset","type","severity"])
    cw.writeheader()
    cw.writerows(EVENTS)
    output = io.BytesIO()
    output.write(si.getvalue().encode("utf-8"))
    output.seek(0)
    return send_file(output, mimetype="text/csv", download_name="soc_events.csv", as_attachment=True)

@app.route("/download/json")
def download_json():
    """Download events as JSON"""
    output = io.BytesIO()
    output.write(json.dumps(EVENTS, indent=2).encode("utf-8"))
    output.seek(0)
    return send_file(output, mimetype="application/json", download_name="soc_events.json", as_attachment=True)

# ------------------ Run ------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))  # Railway uses PORT env variable
    app.run(host="0.0.0.0", port=port, debug=True)