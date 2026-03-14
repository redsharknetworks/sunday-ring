import os
import io
import csv
import json
import sqlite3
import threading
import time
import random
from datetime import datetime

from flask import Flask, render_template_string, send_file, jsonify
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors

app = Flask(__name__)

DB_FILE = "redshark_v5.db"

# ---------------- DATABASE ----------------
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS indicators (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        indicator TEXT,
        type TEXT,
        source TEXT,
        severity TEXT,
        first_seen TEXT,
        last_seen TEXT,
        description TEXT
    )
    """)
    conn.commit()
    conn.close()

init_db()

# ---------------- FEED SIMULATION ----------------
def generate_feed():
    data = []
    severities = ["Low", "Medium", "High", "Critical"]
    sources = ["OTX", "Talos", "AbuseIPDB"]

    for _ in range(25):
        ip = f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"
        severity = random.choice(severities)
        source = random.choice(sources)

        data.append({
            "indicator": ip,
            "type": "IP",
            "source": source,
            "severity": severity,
            "first_seen": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "last_seen": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "description": f"{severity} threat from {source}"
        })
    return data

def save_feed(records):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    for r in records:
        c.execute("""
        INSERT INTO indicators (indicator,type,source,severity,first_seen,last_seen,description)
        VALUES (?,?,?,?,?,?,?)
        """, (
            r["indicator"],
            r["type"],
            r["source"],
            r["severity"],
            r["first_seen"],
            r["last_seen"],
            r["description"]
        ))
    conn.commit()
    conn.close()

def loop():
    while True:
        save_feed(generate_feed())
        time.sleep(300)

threading.Thread(target=loop, daemon=True).start()

# ---------------- DYNAMIC BULLETIN ----------------
def generate_highlight():
    highlights = [
        "Increased high-severity IP activity detected across monitored feeds.",
        "Critical indicators mainly sourced from Talos and AbuseIPDB.",
        "Emerging threat clusters concentrated around Malaysian network zones.",
        "Hash-based indicators remain stable while IP threats continue rising."
    ]
    return random.choice(highlights)

# ---------------- DASHBOARD ----------------
@app.route("/")
def dashboard():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT indicator,type,source,severity,last_seen FROM indicators ORDER BY id DESC LIMIT 50")
    rows = c.fetchall()

    c.execute("""
    SELECT indicator, COUNT(*) freq
    FROM indicators
    GROUP BY indicator
    ORDER BY freq DESC
    LIMIT 10
    """)
    top10 = c.fetchall()

    c.execute("""
    SELECT severity, COUNT(*)
    FROM indicators
    GROUP BY severity
    """)
    severity = c.fetchall()

    conn.close()

    malaysia_time = datetime.now().strftime("%d %B %Y %H:%M:%S")

    points = []
    for r in rows:
        points.append({
            "lat": random.uniform(1.2, 7.2),
            "lon": random.uniform(100.0, 119.0),
            "severity": r[3],
            "indicator": r[0]
        })

    return render_template_string("""
<!DOCTYPE html>
<html>
<head>
<title>RedShark Threat Intelligence Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<link rel="stylesheet" href="https://unpkg.com/leaflet/dist/leaflet.css"/>
<script src="https://unpkg.com/leaflet/dist/leaflet.js"></script>
<script src="https://leaflet.github.io/Leaflet.heat/dist/leaflet-heat.js"></script>

<style>
body {
background:#0b1220;
color:white;
font-family:Arial;
}
h1,h2 {text-align:center;}
#map {height:500px;}
table {
width:95%;
margin:auto;
border-collapse:collapse;
}
th,td {
border:1px solid #333;
padding:8px;
}
th {background:#111827;}
tr:nth-child(even){background:#1f2937;}
.critical {
color:red;
animation: blink 1s infinite;
font-weight:bold;
}
@keyframes blink {
50% {opacity:0;}
}
button {
background:red;
color:white;
padding:10px;
border:none;
cursor:pointer;
margin:5px;
}
</style>
</head>

<body>

<h1>RedShark Threat Intelligence Dashboard</h1>

<h2>RedShark Highlight at {{ malaysia_time }}</h2>
<p style="text-align:center;">{{ highlight }}</p>

<div style="text-align:center;">
<button onclick="location.href='/refresh'">Manual Refresh</button>
<button onclick="location.href='/download_rules'">Download IDS Rule</button>
<button onclick="location.href='/export/pdf'">PDF</button>
<button onclick="location.href='/export/csv'">CSV</button>
</div>

<div id="map"></div>

<h2>Latest Indicators</h2>
<table>
<tr>
<th>Indicator</th>
<th>Type</th>
<th>Source</th>
<th>Severity</th>
<th>Last Seen</th>
</tr>
{% for r in rows %}
<tr>
<td>{{ r[0] }}</td>
<td>{{ r[1] }}</td>
<td>{{ r[2] }}</td>
<td class="{{ 'critical' if r[3]=='Critical' else '' }}">{{ r[3] }}</td>
<td>{{ r[4] }}</td>
</tr>
{% endfor %}
</table>

<h2>Top 10 Threats</h2>
<table>
<tr><th>Indicator</th><th>Count</th></tr>
{% for t in top10 %}
<tr><td>{{ t[0] }}</td><td>{{ t[1] }}</td></tr>
{% endfor %}
</table>

<h2>Severity Chart</h2>
<canvas id="chart"></canvas>

<script>
var map = L.map('map').setView([4.5,102],6);

L.tileLayer('https://tile.openstreetmap.org/{z}/{x}/{y}.png').addTo(map);

var heat = [
{% for p in points %}
[{{ p.lat }}, {{ p.lon }}, 0.7],
{% endfor %}
];

L.heatLayer(heat).addTo(map);

var ctx = document.getElementById('chart');

new Chart(ctx,{
type:'bar',
data:{
labels:[
{% for s in severity %}
'{{ s[0] }}',
{% endfor %}
],
datasets:[{
data:[
{% for s in severity %}
{{ s[1] }},
{% endfor %}
]
}]
}
});
</script>

<p style="text-align:center;">
Developed and analysed by darkgrid@redshark.my using publicly available sources
</p>

</body>
</html>
""",
rows=rows,
top10=top10,
severity=severity,
points=points,
highlight=generate_highlight(),
malaysia_time=malaysia_time)

# ---------------- EXPORT CSV ----------------
@app.route("/export/csv")
def export_csv():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT * FROM indicators")
    rows = c.fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerows(rows)

    return send_file(
        io.BytesIO(output.getvalue().encode()),
        mimetype="text/csv",
        as_attachment=True,
        download_name="redshark.csv"
    )

# ---------------- EXPORT PDF ----------------
@app.route("/export/pdf")
def export_pdf():
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    elements = []

    styles = getSampleStyleSheet()
    elements.append(Paragraph("RedShark Threat Intelligence Report", styles['Heading1']))

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT indicator,severity,source FROM indicators LIMIT 20")
    rows = c.fetchall()
    conn.close()

    data = [["Indicator","Severity","Source"]] + list(rows)

    table = Table(data)
    table.setStyle(TableStyle([
        ('GRID',(0,0),(-1,-1),1,colors.black)
    ]))

    elements.append(table)
    doc.build(elements)

    buffer.seek(0)

    return send_file(buffer, as_attachment=True, download_name="report.pdf")

# ---------------- DOWNLOAD IDS RULE ----------------
@app.route("/download_rules")
def download_rules():
    content = "alert ip any any -> any any (msg:\"RedShark Threat Rule\"; sid:1000001; rev:1;)"
    return send_file(
        io.BytesIO(content.encode()),
        as_attachment=True,
        download_name="ids.rules"
    )

# ---------------- REFRESH ----------------
@app.route("/refresh")
def refresh():
    save_feed(generate_feed())
    return "Refreshed"

# ---------------- JSON ----------------
@app.route("/json")
def json_data():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT * FROM indicators")
    rows = c.fetchall()
    conn.close()
    return jsonify(rows)

# ---------------- RUN ----------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)