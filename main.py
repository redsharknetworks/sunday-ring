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

DB_PATH="/tmp/threats.db"


def db():
    conn=sqlite3.connect(DB_PATH)
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
        severity INTEGER,
        created TEXT
    )
    """)
    conn.commit()


# ---------------- FEEDS ----------------

def fetch_feeds():

    conn=db()

    try:
        url="https://threatfox.abuse.ch/export/json/recent/"
        r=requests.get(url,timeout=10)
        data=r.json()

        for item in data.get("data",[])[:30]:

            conn.execute(
            "INSERT INTO threats(indicator,type,mitre,severity,created) VALUES(?,?,?,?,?)",
            (
                item.get("ioc","unknown"),
                item.get("ioc_type","ioc"),
                "Command & Control",
                80,
                datetime.utcnow()
            )
            )

        conn.commit()

    except Exception as e:
        print("Feed error:",e)



# ---------------- METRICS ----------------

def securenation():

    rows=db().execute(
        "SELECT severity FROM threats ORDER BY id DESC LIMIT 100"
    ).fetchall()

    if not rows:
        return 0

    score=sum([r["severity"] for r in rows])/len(rows)
    return round(score,2)



def timeline_chart():

    rows=db().execute(
    "SELECT substr(created,1,10) d,count(*) c FROM threats GROUP BY d"
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
table{width:100%}
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
<h3>MITRE ATT&CK</h3>
<div id="mitre"></div>
</div>

<div class="card">
<h3>Latest Indicators</h3>

<table>
<tr>
<th>ID</th>
<th>Indicator</th>
<th>Type</th>
<th>Severity</th>
</tr>

{% for r in rows %}

<tr>
<td>{{r.id}}</td>
<td>{{r.indicator}}</td>
<td>{{r.type}}</td>
<td>{{r.severity}}</td>
</tr>

{% endfor %}

</table>
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

    output=io.StringIO()
    writer=csv.writer(output)

    writer.writerow(["id","indicator","type","mitre","severity","created"])

    for r in rows:
        writer.writerow(list(r))

    mem=io.BytesIO()
    mem.write(output.getvalue().encode())
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
    fetch_feeds()

    app.run(host="0.0.0.0",port=int(os.environ.get("PORT",5000)))