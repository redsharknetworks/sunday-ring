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

SOURCES = ["OTX", "AbuseIPDB", "Spamhaus", "EmergingThreats"]
SEVERITIES = ["High","Medium","Low"]

OTX_API_KEY = "aa94a69a780ed789016bb72d51d9b58b823eb1e6173f6fffc34530693dacb03b"
ABUSEIPDB_KEY = "08cf00dc25d22cbd0f45ec5ebb87cb61e289533bd33bceb9b93c22349a6eb8674d52aaf14544a100"
OTX_EXPORT_URL = "https://otx.alienvault.com/api/v1/indicators/export"
ABUSE_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
SPAMHAUS_DROP_URL = "https://www.spamhaus.org/drop/drop.txt"
EMERGINGTHREATS_URL = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"

# ===============================
# Database Functions
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
    c.execute("""
    CREATE TABLE IF NOT EXISTS geo_cache(
        ip TEXT PRIMARY KEY,
        country TEXT,
        lat REAL,
        lon REAL
    )
    """)
    conn.commit()
    conn.close()

def get_events(limit=300):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    rows = c.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return rows

# ===============================
# Geolocation with caching
# ===============================
def get_country_from_ip(ip):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    cached = c.execute("SELECT country,lat,lon FROM geo_cache WHERE ip=?", (ip,)).fetchone()
    if cached:
        conn.close()
        return cached[0], cached[1], cached[2]
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = r.json()
        country = data.get("country","Unknown")
        lat = data.get("lat",0.0)
        lon = data.get("lon",0.0)
    except:
        country = "Unknown"
        lat = 0.0
        lon = 0.0
    # cache
    c.execute("INSERT OR REPLACE INTO geo_cache(ip,country,lat,lon) VALUES(?,?,?,?)",(ip,country,lat,lon))
    conn.commit()
    conn.close()
    return country, lat, lon

# ===============================
# Fetch CTI Feeds
# ===============================
def fetch_cti_combined():
    headers_otx = {"X-OTX-API-KEY": OTX_API_KEY}
    headers_abuse = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}

    feeds = []

    try:
        r = requests.get(OTX_EXPORT_URL, headers=headers_otx, timeout=30)
        feeds += r.text.splitlines()[:100]
    except: pass

    try:
        r = requests.get(SPAMHAUS_DROP_URL, timeout=15)
        feeds += [line.split()[0] for line in r.text.splitlines() if line and not line.startswith(";")][:100]
    except: pass

    try:
        r = requests.get(EMERGINGTHREATS_URL, timeout=15)
        feeds += [line.strip() for line in r.text.splitlines() if line and not line.startswith("#")][:100]
    except: pass

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    for ip in feeds:
        ip = ip.strip()
        if not ip: continue
        exist = c.execute("SELECT id FROM events WHERE ip=?", (ip,)).fetchone()
        if exist: continue

        severity = "Low"
        try:
            rep = requests.get(ABUSE_CHECK_URL, headers=headers_abuse, params={"ipAddress": ip,"maxAgeInDays":90}, timeout=15)
            score = rep.json().get("data", {}).get("abuseConfidenceScore", 0)
            if score >= 80: severity="High"
            elif score >= 40: severity="Medium"
        except:
            severity = "Medium"

        country, src_lat, src_lon = get_country_from_ip(ip)

        if country=="Malaysia":
            loc = random.choice(MALAYSIA_LOCATIONS)
            lat = loc[1]
            lon = loc[2]
        else:
            lat = src_lat
            lon = src_lon

        c.execute("""
        INSERT INTO events(ip,source,severity,country,rule,description,lat,lon,timestamp)
        VALUES(?,?,?,?,?,?,?,?,?)
        """,(ip,"CTI Combined",severity,country,f"RSK-{random.randint(1000,9999)}","Threat IOC detected",lat,lon,datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()

# ===============================
# Initialize DB + Fetch
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
    lines = []
    aggregation = {}  # for ticker line aggregation

    for e in events:
        severity[e[3]] = severity.get(e[3],0)+1
        sources[e[2]] = sources.get(e[2],0)+1
        countries[e[4]] = countries.get(e[4],0)+1
        hour = e[9][0:13]
        timeline[hour] = timeline.get(hour,0)+1

        if e[4]=="Malaysia":
            mapdata.append({"lat":e[7],"lon":e[8],"sev":e[3],"ip":e[1]})
        else:
            key = e[1]
            if key not in aggregation:
                aggregation[key] = {"from_lat": e[7],"from_lon": e[8],"targets":[],"severity": e[3]}
            aggregation[key]["targets"].append(random.choice(MALAYSIA_LOCATIONS))

    for a in aggregation.values():
        for t in a["targets"]:
            lines.append({"from_lat": a["from_lat"],"from_lon":a["from_lon"],"to_lat": t[1],"to_lon":t[2],"severity": a["severity"]})

    return render_template_string("""
<html>
<head>
<title>RedShark Cyber Threat Intelligence Platform</title>
<script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
<style>
body{background:#0f1720;color:#e5e7eb;font-family:Arial;}
.header{font-size:28px;padding:15px;background:#111827;}
.section{background:#111827;margin:20px;padding:20px;border-radius:10px;}
table{width:100%;border-collapse:collapse;}
th,td{padding:10px;border-bottom:1px solid #1f2937;}
.high{color:red;font-weight:bold;animation: blink 1s infinite;}
@keyframes blink{50%{opacity:0.3;}}
.footer{text-align:center;font-size:12px;color:#9ca3af;margin-top:20px;}
input{margin-bottom:10px;padding:5px;width:100%;}
</style>
</head>
<body>
<div class="header">
RedShark Cyber Threat Intelligence Platform
<div style="font-size:12px">CTI Highlight {{time}}</div>
</div>

<div class="section"><h3>Malaysia Threat Map (2D Heat + Attack Vectors)</h3>
<div id="map"></div></div>

<div class="section"><h3>CTI Analytics</h3>
<div id="sev"></div><br>
<div id="src"></div><br>
<div id="country"></div></div>

<div class="section"><h3>Threat Timeline</h3><div id="timeline"></div></div>

<div class="section"><h3>Threat Events</h3>
<input id="search" placeholder="Search by IP, source, country" onkeyup="filterTable()">
<table id="eventsTable">
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
var lines={{lines|tojson}};

var traces = [];

lines.forEach(function(l){
    traces.push({
        type:'scattergeo',
        mode:'lines',
        lon:[l.from_lon,l.to_lon],
        lat:[l.from_lat,l.to_lat],
        line:{width:l.severity=="High"?3:1,color:l.severity=="High"?"red":"orange"},
        opacity:0.7
    });
});

traces.push({
    type:'scattergeo',
    mode:'markers',
    lon: map.map(x=>x.lon),
    lat: map.map(x=>x.lat),
    text: map.map(x=>x.ip),
    marker:{size:15,color:map.map(x=>x.sev=="High"?"red":x.sev=="Medium"?"orange":"cyan"),opacity:0.7}
});

Plotly.newPlot("map",traces,{
    geo:{scope:"asia",center:{lat:4,lon:109},projection:{scale:7}},
    paper_bgcolor:"#0f1720"
});

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

function filterTable(){
    var input=document.getElementById("search").value.toUpperCase();
    var table=document.getElementById("eventsTable");
    var tr=table.getElementsByTagName("tr");
    for(var i=1;i<tr.length;i++){
        var tds=tr[i].getElementsByTagName("td");
        var show=false;
        for(var j=0;j<tds.length;j++){
            if(tds[j].innerHTML.toUpperCase().indexOf(input)>-1){show=true;break;}
        }
        tr[i].style.display=show?"":"none";
    }
}
</script>
</body></html>
""", events=events, mapdata=mapdata, lines=lines, severity=severity, sources=sources, countries=countries, timeline=timeline, time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

# ===============================
# Run
# ===============================
if __name__=="__main__":
    app.run(host="0.0.0.0", port=5000)