import os
import sqlite3
import requests
import json
import csv
import io
from datetime import datetime
from flask import Flask, render_template_string, send_file
import plotly.graph_objs as go
import plotly

app = Flask(__name__)
DB="threats.db"

# ---------------- DATABASE ----------------

def db():
    conn=sqlite3.connect(DB)
    conn.row_factory=sqlite3.Row
    return conn

def init_db():
    c=db().cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS threats(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    indicator TEXT,
    type TEXT,
    source TEXT,
    mitre TEXT,
    severity INTEGER,
    created TEXT
    )
    """)
    c.connection.commit()

# ---------------- FEEDS ----------------

def fetch_urlhaus():
    try:
        url="https://urlhaus.abuse.ch/downloads/csv_recent/"
        r=requests.get(url,timeout=10)
        lines=r.text.splitlines()
        reader=csv.reader(lines)
        conn=db()
        for row in reader:
            if len(row)>2 and row[2].startswith("http"):
                conn.execute(
                "INSERT INTO threats(indicator,type,source,mitre,severity,created) VALUES (?,?,?,?,?,?)",
                (row[2],"url","feed","Command & Control",80,datetime.utcnow())
                )
        conn.commit()
    except:
        pass


def fetch_threatfox():
    try:
        url="https://threatfox.abuse.ch/export/json/recent/"
        r=requests.get(url,timeout=10).json()
        conn=db()
        for item in r["data"][:20]:
            conn.execute(
            "INSERT INTO threats(indicator,type,source,mitre,severity,created) VALUES (?,?,?,?,?,?)",
            (item["ioc"],item["ioc_type"],"feed","Execution",70,datetime.utcnow())
            )
        conn.commit()
    except:
        pass


def fetch_phishtank():
    try:
        url="https://data.phishtank.com/data/online-valid.json"
        r=requests.get(url,timeout=10).json()
        conn=db()
        for item in r[:20]:
            conn.execute(
            "INSERT INTO threats(indicator,type,source,mitre,severity,created) VALUES (?,?,?,?,?,?)",
            (item["url"],"phishing","feed","Credential Access",75,datetime.utcnow())
            )
        conn.commit()
    except:
        pass


def fetch_feodo():
    try:
        url="https://feodotracker.abuse.ch/downloads/ipblocklist.json"
        r=requests.get(url,timeout=10).json()
        conn=db()
        for item in r[:20]:
            conn.execute(
            "INSERT INTO threats(indicator,type,source,mitre,severity,created) VALUES (?,?,?,?,?,?)",
            (item["ip_address"],"ip","feed","Command & Control",90,datetime.utcnow())
            )
        conn.commit()
    except:
        pass


def update_feeds():
    fetch_urlhaus()
    fetch_threatfox()
    fetch_phishtank()
    fetch_feodo()


# ---------------- METRICS ----------------

def securenation():
    rows=db().execute("SELECT severity FROM threats ORDER BY id DESC LIMIT 100").fetchall()
    if not rows:
        return 0
    score=sum([r["severity"] for r in rows])/len(rows)
    return round(score,2)


def timeline_chart():

    rows=db().execute(
    "SELECT substr(created,1,10) d, count(*) c FROM threats GROUP BY d ORDER BY d"
    ).fetchall()

    x=[r["d"] for r in rows]
    y=[r["c"] for r in rows]

    fig=go.Figure()
    fig.add_trace(go.Scatter(x=x,y=y,mode="lines+markers"))

    return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)


def mitre_chart():

    rows=db().execute(
    "SELECT mitre,count(*) c FROM threats GROUP BY mitre"
    ).fetchall()

    labels=[r["mitre"] for r in rows]
    values=[r["c"] for r in rows]

    fig=go.Figure(data=[go.Pie(labels=labels,values=values)])

    return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)


# ---------------- DASHBOARD ----------------

HTML="""
<html>
<head>
<title>RedShark Threat Intelligence Dashboard</title>
<script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
<style>
body{background:#0b1b2a;color:#00eaff;font-family:Arial}
.card{background:#13263b;padding:20px;margin:15px;border-radius:8px}
table{width:100%;border-collapse:collapse}
td,th{padding:6px;border-bottom:1px solid #1f3d5c}
</style>
</head>
<body>

<h2>RedShark Threat Intelligence Dashboard</h2>

<div class="card">
SecureNation Index: <b>{{index}}</b>
</div>

<div class="card">
<h3>Threat Timeline</h3>
<div id="timeline"></div>
</div>

<div class="card">
<h3>MITRE ATT&CK Distribution</h3>
<div id="mitre"></div>
</div>

<div class="card">
<h3>Latest Indicators</h3>
<table>
<tr>
<th>ID</th>
<th>Indicator</th>
<th>Type</th>
<th>MITRE</th>
<th>Severity</th>
</tr>

{% for r in rows %}
<tr>
<td>{{r.id}}</td>
<td>{{r.indicator}}</td>
<td>{{r.type}}</td>
<td>{{r.mitre}}</td>
<td>{{r.severity}}</td>
</tr>
{% endfor %}

</table>
</div>

<div class="card">
<a href="/csv">Download CSV</a> |
<a href="/json">Download JSON</a>
</div>

<script>
var timeline={{timeline|safe}};
var mitre={{mitre|safe}};

Plotly.newPlot("timeline",timeline.data,timeline.layout);
Plotly.newPlot("mitre",mitre.data,mitre.layout);
</script>

<p style="opacity:0.6">
Developed and analyzed by darkgrid@redshark.my using publicly available threat intelligence sources.
</p>

</body>
</html>
"""


@app.route("/")
def dashboard():

    rows=db().execute(
    "SELECT * FROM threats ORDER BY id DESC LIMIT 50"
    ).fetchall()

    return render_template_string(
        HTML,
        rows=rows,
        index=securenation(),
        timeline=timeline_chart(),
        mitre=mitre_chart()
    )


# ---------------- EXPORT ----------------

@app.route("/csv")
def csv_export():

    rows=db().execute("SELECT * FROM threats").fetchall()

    out=io.StringIO()
    writer=csv.writer(out)
    writer.writerow(rows[0].keys())

    for r in rows:
        writer.writerow(list(r))

    mem=io.BytesIO()
    mem.write(out.getvalue().encode())
    mem.seek(0)

    return send_file(mem,download_name="threats.csv",as_attachment=True)


@app.route("/json")
def json_export():

    rows=db().execute("SELECT * FROM threats").fetchall()
    data=[dict(r) for r in rows]

    mem=io.BytesIO()
    mem.write(json.dumps(data,indent=2).encode())
    mem.seek(0)

    return send_file(mem,download_name="threats.json",as_attachment=True)


# ---------------- START ----------------

if __name__=="__main__":

    init_db()
    update_feeds()

    app.run(host="0.0.0.0",port=int(os.environ.get("PORT",5000)))