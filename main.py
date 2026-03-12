import os
import sqlite3
import requests
import json
import csv
import io
import random
import threading
from datetime import datetime
from flask import Flask, render_template_string, send_file
import plotly.graph_objs as go
import plotly

app = Flask(__name__)

DB="/tmp/threats.db"
RULE_FILE="/tmp/redshark.rules"


# ---------------- DATABASE ----------------

def db():
    conn=sqlite3.connect(DB)
    conn.row_factory=sqlite3.Row
    return conn


def init_db():
    conn=db()

    conn.execute("""
    CREATE TABLE IF NOT EXISTS threats(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        indicator TEXT,
        type TEXT,
        mitre TEXT,
        sector TEXT,
        severity INTEGER,
        lat REAL,
        lon REAL,
        created TEXT
    )
    """)

    conn.execute("""
    CREATE TABLE IF NOT EXISTS rules(
        indicator TEXT UNIQUE
    )
    """)

    conn.commit()


init_db()

# ---------------- MALAYSIA STATES ----------------

states={
"Johor":[1.49,103.74],
"Kedah":[6.11,100.36],
"Kelantan":[6.12,102.23],
"Melaka":[2.18,102.25],
"Negeri Sembilan":[2.72,101.94],
"Pahang":[3.81,103.32],
"Perak":[4.59,101.09],
"Perlis":[6.44,100.20],
"Pulau Pinang":[5.41,100.33],
"Sabah":[5.98,116.07],
"Sarawak":[1.55,110.35],
"Selangor":[3.07,101.51],
"Terengganu":[5.33,103.14],
"Kuala Lumpur":[3.13,101.68]
}

sectors=[
"Government","Banking","Telecommunications","Energy",
"Healthcare","Education","Manufacturing",
"Transportation","Retail","Technology"
]

mitre=[
"Reconnaissance","Initial Access","Execution","Persistence",
"Privilege Escalation","Defense Evasion","Credential Access",
"Discovery","Lateral Movement","Collection",
"Command and Control","Exfiltration","Impact"
]


# ---------------- RANDOM HELPERS ----------------

def rand_loc():
    return random.choice(list(states.values()))

def rand_sector():
    return random.choice(sectors)

def rand_mitre():
    return random.choice(mitre)


# ---------------- INSERT THREAT ----------------

def insert_threat(indicator,typ,severity):

    lat,lon=rand_loc()

    conn=db()

    conn.execute("""
    INSERT INTO threats(indicator,type,mitre,sector,severity,lat,lon,created)
    VALUES(?,?,?,?,?,?,?,?)
    """,(
        indicator,
        typ,
        rand_mitre(),
        rand_sector(),
        severity,
        lat,
        lon,
        datetime.utcnow()
    ))

    conn.commit()

    create_rule(indicator,severity)



# ---------------- SURICATA RULE ----------------

def create_rule(indicator,severity):

    if severity<85:
        return

    conn=db()

    r=conn.execute("SELECT indicator FROM rules WHERE indicator=?",(indicator,)).fetchone()

    if r:
        return

    sid=random.randint(1000000,9999999)

    rule=f'alert ip any any -> any any (msg:"RedShark CTI"; content:"{indicator}"; sid:{sid}; rev:1;)'

    with open(RULE_FILE,"a") as f:
        f.write(rule+"\n")

    conn.execute("INSERT INTO rules VALUES(?)",(indicator,))
    conn.commit()


# ---------------- FETCH FEEDS ----------------

def fetch_threatfox():

    try:

        url="https://threatfox.abuse.ch/export/json/recent/"
        r=requests.get(url,timeout=10).json()

        for i in r.get("data",[])[:15]:

            insert_threat(
                i.get("ioc","unknown"),
                i.get("ioc_type","unknown"),
                85
            )

    except:
        pass


def fetch_feodo():

    try:

        url="https://feodotracker.abuse.ch/downloads/ipblocklist.json"
        data=requests.get(url,timeout=10).json()

        for i in data[:15]:

            insert_threat(
                i.get("ip_address","0.0.0.0"),
                "ip",
                90
            )

    except:
        pass


def fetch_feeds():

    fetch_threatfox()
    fetch_feodo()



def scheduler():

    fetch_feeds()

    threading.Timer(600,scheduler).start()


scheduler()


# ---------------- SECURENATION INDEX ----------------

def securenation():

    rows=db().execute("""
    SELECT severity FROM threats ORDER BY id DESC LIMIT 100
    """).fetchall()

    if not rows:
        return 0

    score=sum([r["severity"] for r in rows])/len(rows)

    return round(score,1)


# ---------------- MALAYSIA HEATMAP ----------------

def malaysia_map():

    rows=db().execute("""
    SELECT lat,lon,severity FROM threats
    """).fetchall()

    lat=[r["lat"] for r in rows]
    lon=[r["lon"] for r in rows]
    sev=[r["severity"] for r in rows]

    fig=go.Figure(go.Densitymapbox(
        lat=lat,
        lon=lon,
        z=sev,
        radius=25
    ))

    fig.update_layout(
        mapbox_style="carto-darkmatter",
        mapbox_center={"lat":4.5,"lon":102},
        mapbox_zoom=4,
        margin=dict(l=0,r=0,t=0,b=0),
        paper_bgcolor="#0b1b2a"
    )

    return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)



# ---------------- TREND CHART ----------------

def trend_chart():

    rows=db().execute("""
    SELECT substr(created,1,10) d,
    SUM(CASE WHEN severity>=85 THEN 1 ELSE 0 END) c,
    SUM(CASE WHEN severity>=70 AND severity<85 THEN 1 ELSE 0 END) m,
    SUM(CASE WHEN severity<70 THEN 1 ELSE 0 END) l
    FROM threats GROUP BY d
    """).fetchall()

    d=[r["d"] for r in rows]
    c=[r["c"] for r in rows]
    m=[r["m"] for r in rows]
    l=[r["l"] for r in rows]

    fig=go.Figure()

    fig.add_trace(go.Scatter(x=d,y=c,name="Critical",line=dict(color="red",width=3)))
    fig.add_trace(go.Scatter(x=d,y=m,name="Medium",line=dict(color="orange")))
    fig.add_trace(go.Scatter(x=d,y=l,name="Low",line=dict(color="cyan")))

    fig.update_layout(
        plot_bgcolor="#0b1b2a",
        paper_bgcolor="#0b1b2a",
        font_color="#00eaff"
    )

    return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)


# ---------------- DASHBOARD HTML ----------------

HTML="""
<html>

<head>
<title>RedShark CTI Dashboard v3.1</title>

<script src="https://cdn.plot.ly/plotly-latest.min.js"></script>

<style>

body{
background:#0b1b2a;
color:white;
font-family:Arial;
}

.card{
background:#13263b;
padding:20px;
margin:15px;
border-radius:8px;
}

table{
width:100%;
border-collapse:collapse;
}

td,th{
padding:8px;
border-bottom:1px solid #1f3d5c;
}

th{cursor:pointer;}

</style>

</head>

<body>

<h2>SUNDAY-RING Executive Intelligence Bulletin</h2>

<div class="card">

SecureNation Index:
<b style="color:orange">{{index}}</b>

</div>


<div class="card">
<h3>Malaysia Threat Heatmap</h3>
<div id="map"></div>
</div>

<div class="card">
<h3>Threat Trend</h3>
<div id="trend"></div>
</div>


<div class="card">

<h3>Latest Threat Indicators</h3>

<table id="tbl">

<tr>
<th onclick="sortTable(0)">ID</th>
<th onclick="sortTable(1)">Indicator</th>
<th onclick="sortTable(2)">Type</th>
<th onclick="sortTable(3)">Sector</th>
<th onclick="sortTable(4)">Severity</th>
</tr>

{% for r in rows %}

<tr>
<td>{{r.id}}</td>
<td>{{r.indicator}}</td>
<td>{{r.type}}</td>
<td>{{r.sector}}</td>
<td>{{r.severity}}</td>
</tr>

{% endfor %}

</table>

</div>


<div class="card">

<a href="/csv">CSV</a> |
<a href="/json">JSON</a> |
<a href="/rules">Download IPS Signatures</a>

</div>


<script>

var map={{map|safe}}
var trend={{trend|safe}}

Plotly.newPlot("map",map.data,map.layout)
Plotly.newPlot("trend",trend.data,trend.layout)

function sortTable(n){

var table=document.getElementById("tbl")
var switching=true

while(switching){

switching=false
var rows=table.rows

for(var i=1;i<rows.length-1;i++){

var a=rows[i].getElementsByTagName("TD")[n].innerText
var b=rows[i+1].getElementsByTagName("TD")[n].innerText

if(a>b){

rows[i].parentNode.insertBefore(rows[i+1],rows[i])
switching=true
}

}

}

}

</script>

</body>
</html>
"""


# ---------------- ROUTES ----------------

@app.route("/")
def home():

    rows=db().execute("SELECT * FROM threats ORDER BY id DESC LIMIT 50").fetchall()

    return render_template_string(
        HTML,
        rows=rows,
        index=securenation(),
        map=malaysia_map(),
        trend=trend_chart()
    )


@app.route("/csv")
def csv_export():

    rows=db().execute("SELECT * FROM threats").fetchall()

    out=io.StringIO()
    w=csv.writer(out)

    w.writerow(rows[0].keys())

    for r in rows:
        w.writerow(list(r))

    mem=io.BytesIO()
    mem.write(out.getvalue().encode())
    mem.seek(0)

    return send_file(mem,download_name="redshark-cti.csv",as_attachment=True)



@app.route("/json")
def json_export():

    rows=db().execute("SELECT * FROM threats").fetchall()

    data=[dict(r) for r in rows]

    mem=io.BytesIO()
    mem.write(json.dumps(data,indent=2).encode())
    mem.seek(0)

    return send_file(mem,download_name="redshark-cti.json",as_attachment=True)



@app.route("/rules")
def rules():

    if not os.path.exists(RULE_FILE):
        open(RULE_FILE,"w").close()

    return send_file(RULE_FILE,download_name="redshark-ips-signatures.rules",as_attachment=True)



# ---------------- RUN ----------------

if __name__=="__main__":

    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT",5000))
    )