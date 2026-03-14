import os
import sqlite3
import random
import requests
from datetime import datetime
from flask import Flask, render_template_string

app = Flask(__name__)

# ===============================
# Database Setup
# ===============================

DB_DIR = "data"
DB_PATH = os.path.join(DB_DIR, "cti.db")
if not os.path.exists(DB_DIR):
    os.makedirs(DB_DIR)

MALAYSIA_LOCATIONS = [
    ("Kangar", 6.4414, 100.1986),
    ("Alor Setar", 6.1248, 100.3678),
    ("George Town", 5.4141, 100.3288),
    ("Ipoh", 4.5975, 101.0901),
    ("Shah Alam", 3.0738, 101.5183),
    ("Kuala Lumpur", 3.1390, 101.6869),
    ("Seremban", 2.7297, 101.9381),
    ("Melaka", 2.1896, 102.2501),
    ("Johor Bahru", 1.4927, 103.7414),
    ("Kuantan", 3.8168, 103.3317),
    ("Kuala Terengganu", 5.3302, 103.1408),
    ("Kota Bharu", 6.1254, 102.2386),
    ("Kuching", 1.5533, 110.3592),
    ("Kota Kinabalu", 5.9804, 116.0735),
    ("Putrajaya", 2.9264, 101.6964),
]

COUNTRIES = ["Russia","China","USA","Brazil","Iran","India","Germany","Vietnam"]

SOURCES = ["OTX", "AbuseIPDB", "Spamhaus", "EmergingThreats"]

SEVERITIES = ["High","Medium","Low"]

# CTI API Keys
OTX_API_KEY = "aa94a69a780ed789016bb72d51d9b58b823eb1e6173f6fffc34530693dacb03b"
ABUSEIPDB_KEY = "08cf00dc25d22cbd0f45ec5ebb87cb61e289533bd33bceb9b93c22349a6eb8674d52aaf14544a100"
OTX_EXPORT_URL = "https://otx.alienvault.com/api/v1/indicators/export"
ABUSE_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
SPAMHAUS_DROP_URL = "https://www.spamhaus.org/drop/drop.txt"
EMERGINGTHREATS_URL = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"

# ===============================
# Database functions
# ===============================

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS events(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT,
        source TEXT,
        severity TEXT,
        country TEXT,
        rule TEXT,
        description TEXT,
        lat REAL,
        lon REAL,
        timestamp TEXT
    )
    """)
    conn.commit()
    conn.close()

def get_events():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    rows = c.execute("SELECT * FROM events ORDER BY id DESC").fetchall()
    conn.close()
    return rows

# ===============================
# Fetch OTX + AbuseIPDB + Spamhaus + EmergingThreats
# ===============================

def fetch_cti_combined():
    headers_otx = {"X-OTX-API-KEY": OTX_API_KEY}
    headers_abuse = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}

    feeds = []

    # --- OTX IOC ---
    try:
        r = requests.get(OTX_EXPORT_URL, headers=headers_otx, timeout=30)
        iocs = r.text.splitlines()
        feeds += iocs[:120]
    except Exception as e:
        print("OTX error:", e)

    # --- Spamhaus DROP ---
    try:
        r = requests.get(SPAMHAUS_DROP_URL, timeout=15)
        feeds += [line.strip().split()[0] for line in r.text.splitlines() if line and not line.startswith(";")]
    except:
        pass

    # --- EmergingThreats ---
    try:
        r = requests.get(EMERGINGTHREATS_URL, timeout=15)
        feeds += [line.strip() for line in r.text.splitlines() if line and not line.startswith("#")]
    except:
        pass

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    for ip in feeds:
        ip = ip.strip()
        if not ip:
            continue

        # avoid duplicates
        exist = c.execute("SELECT id FROM events WHERE ip=?", (ip,)).fetchone()
        if exist:
            continue

        severity = "Low"
        try:
            params = {"ipAddress": ip, "maxAgeInDays": 90}
            rep = requests.get(ABUSE_CHECK_URL, headers=headers_abuse, params=params, timeout=15)
            score = rep.json().get("data", {}).get("abuseConfidenceScore", 0)
            if score >= 80:
                severity = "High"
            elif score >= 40:
                severity = "Medium"
        except:
            severity = "Medium"

        loc = random.choice(MALAYSIA_LOCATIONS)

        c.execute("""
        INSERT INTO events(
            ip,source,severity,country,rule,description,lat,lon,timestamp
        ) VALUES(?,?,?,?,?,?,?,?,?)
        """, (
            ip,
            "CTI Combined",
            severity,
            "External",
            f"RSK-{random.randint(1000,9999)}",
            "Threat IOC detected",
            loc[1],
            loc[2],
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))

    conn.commit()
    conn.close()

# ===============================
# Initialize Database + Fetch Feeds
# ===============================
init_db()
fetch_cti_combined()

# ===============================
# Flask Dashboard
# ===============================

@app.route("/")
def dashboard():
    events = get_events()

    severity = {s:0 for s in SEVERITIES}
    sources = {}
    countries = {}
    timeline = {}
    mapdata = []

    for e in events:
        severity[e[3]] = severity.get(e[3],0)+1
        sources[e[2]] = sources.get(e[2],0)+1
        countries[e[4]] = countries.get(e[4],0)+1
        hour = e[9][0:13]
        timeline[hour] = timeline.get(hour,0)+1
        mapdata.append({"lat": e[7], "lon": e[8], "sev": e[3], "ip": e[1]})

    return render_template_string("""
<html>
<head>
<title>RedShark CTI v19</title>
<script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
<style>
body{background:#0f1720;color:#e5e7eb;font-family:Arial;}
.header{font-size:28px;padding:15px;background:#111827;}
.section{background:#111827;margin:20px;padding:20px;border-radius:10px;}
table{width:100%;border-collapse:collapse;}
th,td{padding:10px;border-bottom:1px solid #1f2937;}
.high{color:red;font-weight:bold;animation: blink 1s infinite;}
@keyframes blink{50%{opacity:0.3;}}
.footer{text-align:center;font-size:12px;color:#9ca3af;}
</style>
</head>
<body>
<div class="header">
RedShark Cyber Threat Intelligence Platform v19
<div style="font-size:12px">CTI Highlight {{time}}</div>
</div>

<div class="section"><h3>Malaysia Threat Map</h3><div id="map"></div></div>

<div class="section"><h3>CTI Analytics</h3>
<div id="sev"></div><br>
<div id="src"></div><br>
<div id="country"></div></div>

<div class="section"><h3>Threat Timeline</h3><div id="timeline"></div></div>

<div class="section"><h3>Threat Events</h3>
<table>
<tr><th>ID</th><th>IP</th><th>Source</th><th>Severity</th><th>Country</th><th>Rule</th><th>Timestamp</th></tr>
{% for e in events %}
<tr class="{{'high' if e[3]=='High' else ''}}">
<td>{{e[0]}}</td><td>{{e[1]}}</td><td>{{e[2]}}</td><td>{{e[3]}}</td><td>{{e[4]}}</td><td>{{e[5]}}</td><td>{{e[9]}}</td>
</tr>
{% endfor %}
</table></div>

<div class="section"><h3>Firewall Block Rules</h3><pre>
{% for e in events %}
{% if e[3]=='High' %}
iptables -A INPUT -s {{e[1]}} -j DROP
{% endif %}
{% endfor %}
</pre></div>

<div class="footer">
Developed and analysed by darkgrid@redshark.my using publicly available sources
</div>

<script>
var map={{mapdata|tojson}};
Plotly.newPlot("map",[{
type:"scattergeo",mode:"markers",
lat:map.map(x=>x.lat),lon:map.map(x=>x.lon),
text:map.map(x=>x.ip),
marker:{size:10,color:map.map(x=>x.sev=="High"?"red":x.sev=="Medium"?"orange":"cyan")}
}],{geo:{scope:"asia",center:{lat:4,lon:109},projection:{scale:7}},paper_bgcolor:"#0f1720"});

var sev={{severity|tojson}};
Plotly.newPlot("sev",[{
values:Object.values(sev),labels:Object.keys(sev),type:"pie",hole:.5
}]);

var src={{sources|tojson}};
Plotly.newPlot("src",[{
x:Object.keys(src),y:Object.values(src),type:"bar"
}]);

var country={{countries|tojson}};
Plotly.newPlot("country",[{
x:Object.keys(country),y:Object.values(country),type:"bar"
}]);

var tl={{timeline|tojson}};
Plotly.newPlot("timeline",[{
x:Object.keys(tl),y:Object.values(tl),type:"scatter"
}]);
</script>
</body></html>
""", events=events, mapdata=mapdata, severity=severity, sources=sources,
countries=countries, timeline=timeline, time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

# ===============================
# Run
# ===============================
if __name__=="__main__":
    app.run(host="0.0.0.0", port=5000)