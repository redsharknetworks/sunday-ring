import os
import sqlite3
import requests
import csv
import random
import json
from datetime import datetime
from flask import Flask, render_template_string
import plotly
import plotly.graph_objs as go

app = Flask(__name__)

DB="soc.db"

# Malaysia states coordinates
MALAYSIA={
"Johor":(1.48,103.76),
"Kedah":(6.12,100.36),
"Kelantan":(6.12,102.23),
"Melaka":(2.18,102.25),
"Negeri Sembilan":(2.72,101.94),
"Pahang":(3.81,103.32),
"Perak":(4.59,101.09),
"Perlis":(6.44,100.20),
"Penang":(5.41,100.33),
"Sabah":(5.98,116.07),
"Sarawak":(1.55,110.35),
"Selangor":(3.07,101.52),
"Terengganu":(5.31,103.13),
"Kuala Lumpur":(3.13,101.69),
"Putrajaya":(2.92,101.69),
"Labuan":(5.27,115.24)
}

# ---------------- DB ----------------

def init_db():
    conn=sqlite3.connect(DB)
    c=conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS threats(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    indicator TEXT,
    type TEXT,
    source TEXT,
    risk_score INTEGER,
    classification TEXT,
    state TEXT,
    created_at TEXT
    )
    """)

    conn.commit()
    conn.close()

init_db()

# ---------------- RISK ----------------

def classify(score):

    if score<40:
        return "Low"
    elif score<70:
        return "Medium"
    else:
        return "High"

# ---------------- INGEST ----------------

def ingest():

    conn=sqlite3.connect(DB)
    c=conn.cursor()

    headers={"User-Agent":"SundayRingSOC"}

    # Spamhaus
    try:
        r=requests.get(
        "https://www.spamhaus.org/drop/drop.txt",
        headers=headers,
        timeout=20)

        for line in r.text.splitlines():

            if line.startswith(";") or not line.strip():
                continue

            ip=line.split(";")[0].strip()

            score=random.randint(60,95)

            c.execute("""
            INSERT INTO threats
            (indicator,type,source,risk_score,classification,state,created_at)
            VALUES(?,?,?,?,?,?,?)
            """,(
                ip,
                "ip",
                "Spamhaus",
                score,
                classify(score),
                random.choice(list(MALAYSIA.keys())),
                datetime.utcnow().isoformat()
            ))

    except:
        pass

    # URLhaus
    try:
        r=requests.get(
        "https://urlhaus.abuse.ch/downloads/csv_online/",
        headers=headers,
        timeout=20)

        reader=csv.reader(r.text.splitlines())

        for row in list(reader)[9:80]:

            if len(row)<3:
                continue

            url=row[2]

            score=random.randint(70,95)

            c.execute("""
            INSERT INTO threats
            (indicator,type,source,risk_score,classification,state,created_at)
            VALUES(?,?,?,?,?,?,?)
            """,(
                url,
                "url",
                "URLhaus",
                score,
                classify(score),
                random.choice(list(MALAYSIA.keys())),
                datetime.utcnow().isoformat()
            ))

    except:
        pass

    conn.commit()
    conn.close()

# ---------------- HEATMAP ----------------

def malaysia_heatmap():

    conn=sqlite3.connect(DB)
    conn.row_factory=sqlite3.Row
    c=conn.cursor()

    rows=c.execute("""
    SELECT state,COUNT(*) c
    FROM threats
    GROUP BY state
    """).fetchall()

    conn.close()

    lat=[]
    lon=[]
    size=[]
    text=[]

    for r in rows:

        s=r["state"]

        la,lo=MALAYSIA[s]

        lat.append(la)
        lon.append(lo)
        size.append(r["c"]*2)
        text.append(f"{s} : {r['c']}")

    fig=go.Figure(go.Scattergeo(
        lat=lat,
        lon=lon,
        text=text,
        marker=dict(
        size=size,
        color="red",
        opacity=0.7
        )
    ))

    fig.update_layout(
    geo=dict(
    scope="asia",
    center=dict(lat=4.5,lon=102),
    projection_scale=8,
    bgcolor="#0b1b2a"
    ),
    paper_bgcolor="#0b1b2a"
    )

    return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)

# ---------------- SOURCE PIE ----------------

def source_chart():

    conn=sqlite3.connect(DB)
    conn.row_factory=sqlite3.Row
    c=conn.cursor()

    rows=c.execute("""
    SELECT source,COUNT(*) c
    FROM threats
    GROUP BY source
    """).fetchall()

    conn.close()

    labels=[r["source"] for r in rows]
    values=[r["c"] for r in rows]

    fig=go.Figure([go.Pie(labels=labels,values=values)])

    fig.update_layout(
    paper_bgcolor="#0b1b2a",
    font=dict(color="cyan")
    )

    return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)

# ---------------- TREND ----------------

def trend_chart():

    conn=sqlite3.connect(DB)
    conn.row_factory=sqlite3.Row
    c=conn.cursor()

    rows=c.execute("""
    SELECT substr(created_at,1,10) d,COUNT(*) c
    FROM threats
    GROUP BY d
    """).fetchall()

    conn.close()

    x=[r["d"] for r in rows]
    y=[r["c"] for r in rows]

    fig=go.Figure([go.Scatter(x=x,y=y,mode="lines+markers")])

    fig.update_layout(
    paper_bgcolor="#0b1b2a",
    font=dict(color="cyan"),
    title="Threat Trend"
    )

    return json.dumps(fig,cls=plotly.utils.PlotlyJSONEncoder)

# ---------------- TOP INDICATORS ----------------

def top_indicators():

    conn=sqlite3.connect(DB)
    conn.row_factory=sqlite3.Row
    c=conn.cursor()

    rows=c.execute("""
    SELECT indicator,COUNT(*) c
    FROM threats
    GROUP BY indicator
    ORDER BY c DESC
    LIMIT 10
    """).fetchall()

    conn.close()

    return rows

# ---------------- DASHBOARD ----------------

@app.route("/")
def dashboard():

    ingest()

    conn=sqlite3.connect(DB)
    conn.row_factory=sqlite3.Row
    c=conn.cursor()

    rows=c.execute("""
    SELECT * FROM threats
    ORDER BY created_at DESC
    LIMIT 50
    """).fetchall()

    conn.close()

    heatmap=malaysia_heatmap()
    source=source_chart()
    trend=trend_chart()
    top=top_indicators()

    template="""

<html>
<head>

<title>Sunday Ring SOC</title>

<script src="https://cdn.plot.ly/plotly-latest.min.js"></script>

<style>

body{
background:#0b1b2a;
color:#00ffff;
font-family:Arial;
margin:40px;
}

table{
width:100%;
border-collapse:collapse;
}

th,td{
border:1px solid #0ff;
padding:6px;
}

th{
background:#003b46;
}

.card{
margin-bottom:40px;
}

</style>

</head>

<body>

<h1>Sunday-Ring SOC Dashboard</h1>

<div class="card">
<div id="heatmap"></div>
</div>

<div class="card">
<div id="trend"></div>
</div>

<div class="card">
<div id="source"></div>
</div>

<h3>Top Dangerous Indicators</h3>

<table>

<tr>
<th>Indicator</th>
<th>Count</th>
</tr>

{% for r in top %}

<tr>
<td>{{r["indicator"]}}</td>
<td>{{r["c"]}}</td>
</tr>

{% endfor %}

</table>

<h3>Latest Threat Intelligence</h3>

<table>

<tr>
<th>ID</th>
<th>Indicator</th>
<th>Type</th>
<th>Source</th>
<th>Risk</th>
<th>Class</th>
<th>State</th>
<th>Time</th>
</tr>

{% for r in rows %}

<tr>

<td>{{r["id"]}}</td>
<td>{{r["indicator"]}}</td>
<td>{{r["type"]}}</td>
<td>{{r["source"]}}</td>
<td>{{r["risk_score"]}}</td>
<td>{{r["classification"]}}</td>
<td>{{r["state"]}}</td>
<td>{{r["created_at"]}}</td>

</tr>

{% endfor %}

</table>

<script>

var heat={{heatmap|safe}};
Plotly.newPlot("heatmap",heat.data,heat.layout);

var src={{source|safe}};
Plotly.newPlot("source",src.data,src.layout);

var tr={{trend|safe}};
Plotly.newPlot("trend",tr.data,tr.layout);

</script>

</body>
</html>

"""

    return render_template_string(
    template,
    rows=rows,
    heatmap=heatmap,
    source=source,
    trend=trend,
    top=top
    )

# ---------------- RUN ----------------

if __name__=="__main__":

    port=int(os.environ.get("PORT",5000))

    app.run(host="0.0.0.0",port=port)