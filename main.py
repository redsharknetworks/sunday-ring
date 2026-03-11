import os, io, csv, json, sqlite3, threading, time, random
from datetime import datetime, timedelta
import requests
from flask import Flask, render_template_string, send_file
import plotly.graph_objs as go
import base64
import folium
from folium.plugins import HeatMap

app = Flask(__name__)
DB = os.getenv("DB_PATH","/tmp/sundayring.db")
SURICATA_FILE = os.getenv("SURICATA_FILE","/tmp/suricata/eve.json")
DUMMY_IPS = ["8.8.8.8","1.1.1.1","9.9.9.9"]

# Malaysia states coordinates
MALAYSIA_STATES = {
    "Johor":[1.4927,103.7414],"Kedah":[6.1164,100.3678],"Kelantan":[6.1254,102.2381],
    "Melaka":[2.1896,102.2501],"Negeri Sembilan":[2.7290,101.9383],"Pahang":[3.8167,103.3333],
    "Perak":[4.5929,101.0900],"Perlis":[6.4400,100.2000],"Penang":[5.4164,100.3327],
    "Sabah":[5.9804,116.0735],"Sarawak":[1.5533,110.3592],"Selangor":[3.1390,101.6869],
    "Terengganu":[5.3300,103.1400],"Kuala Lumpur":[3.1390,101.6869],"Putrajaya":[2.9264,101.6981],
    "Labuan":[5.2833,115.2333]
}

# ---------------- DATABASE ----------------
def ensure_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS threats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pulse TEXT,
        indicator TEXT UNIQUE,
        type TEXT,
        classification TEXT,
        mitre TEXT,
        risk_score INTEGER,
        source TEXT,
        created_at TEXT
    )
    """)
    conn.commit(); conn.close()

def cleanup_old_records():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    cutoff = (datetime.utcnow()-timedelta(days=60)).isoformat()
    c.execute("DELETE FROM threats WHERE created_at<?",(cutoff,))
    conn.commit(); conn.close()

def classify_risk(score):
    if score>=70: return "High"
    elif score>=40: return "Medium"
    else: return "Low"

def insert_dummy_data(n=50):
    conn=sqlite3.connect(DB); c=conn.cursor()
    for i in range(n):
        created=datetime.utcnow().isoformat()
        score=random.randint(10,95)
        pulse=f"Dummy Pulse {i+1}"
        indicator=f"malicious{i+1}.com"
        c.execute("""INSERT OR IGNORE INTO threats
        (pulse,indicator,type,classification,mitre,risk_score,source,created_at)
        VALUES (?,?,?,?,?,?,?,?)""",
        (pulse,indicator,"domain",classify_risk(score),"Dummy",score,"Dummy",created))
    conn.commit(); conn.close()

# ---------------- SURICATA LOG ----------------
def parse_suricata():
    if not os.path.exists(SURICATA_FILE): return
    try: lines=open(SURICATA_FILE).readlines()
    except: return
    conn=sqlite3.connect(DB); c=conn.cursor()
    for line in lines:
        try:
            data=json.loads(line)
            alert=data.get("alert")
            if not alert: continue
            indicator=data.get("src_ip","unknown")
            pulse=alert.get("signature","Suricata Alert")
            score=random.randint(40,90)
            created=data.get("timestamp",datetime.utcnow().isoformat())
            c.execute("""INSERT OR IGNORE INTO threats
            (pulse,indicator,type,classification,mitre,risk_score,source,created_at)
            VALUES (?,?,?,?,?,?,?,?)""",
            (pulse,indicator,"ip",classify_risk(score),"Suricata",score,"Suricata",created))
        except: continue
    conn.commit(); conn.close()

# ---------------- TALOS LOOKUP ----------------
def fetch_talos_lookup():
    conn=sqlite3.connect(DB); c=conn.cursor()
    for ip in DUMMY_IPS:
        try:
            # Example dummy Talos lookup, replace with actual API if available
            score=random.randint(10,95)
            c.execute("""INSERT OR IGNORE INTO threats
            (pulse,indicator,type,classification,mitre,risk_score,source,created_at)
            VALUES (?,?,?,?,?,?,?,?)""",
            (f"Talos Lookup {ip}",ip,"ip",classify_risk(score),"Talos",score,"Talos",datetime.utcnow().isoformat()))
        except: continue
    conn.commit(); conn.close()

# ---------------- SCHEDULER ----------------
def scheduler():
    while True:
        insert_dummy_data(10)
        parse_suricata()
        fetch_talos_lookup()
        cleanup_old_records()
        time.sleep(3600)

# ---------------- DASHBOARD ----------------
@app.route("/")
def dashboard():
    conn=sqlite3.connect(DB); conn.row_factory=sqlite3.Row; c=conn.cursor()
    table_data=c.execute("SELECT * FROM threats ORDER BY created_at DESC LIMIT 50").fetchall()
    top20=c.execute("SELECT indicator,count(*) cnt FROM threats GROUP BY indicator ORDER BY cnt DESC LIMIT 20").fetchall()
    trend_rows=c.execute("SELECT substr(created_at,1,10) date,COUNT(*) cnt FROM threats GROUP BY date ORDER BY date").fetchall()
    type_rows=c.execute("SELECT type,COUNT(*) cnt FROM threats GROUP BY type").fetchall()
    conn.close()

    # Trend chart using Plotly
    trend_img=None
    if trend_rows:
        dates=[r["date"] for r in trend_rows]; counts=[r["cnt"] for r in trend_rows]
        fig=go.Figure(go.Scatter(x=dates,y=counts,mode="lines+markers",line=dict(color="#00FFFF")))
        fig.update_layout(plot_bgcolor="#0b1b2a",paper_bgcolor="#0b1b2a",font_color="#00FFFF")
        buf=io.BytesIO()
        fig.write_image(buf,format="png")
        trend_img=base64.b64encode(buf.getvalue()).decode()

    # Type chart
    type_img=None
    if type_rows:
        labels=[r["type"] for r in type_rows]; values=[r["cnt"] for r in type_rows]
        fig=go.Figure(go.Bar(x=labels,y=values,marker_color="#00FFFF"))
        fig.update_layout(plot_bgcolor="#0b1b2a",paper_bgcolor="#0b1b2a",font_color="#00FFFF")
        buf=io.BytesIO()
        fig.write_image(buf,format="png")
        type_img=base64.b64encode(buf.getvalue()).decode()

    # Malaysia Heatmap
    timestamp=(datetime.utcnow()+timedelta(hours=8)).strftime("%Y-%m-%d %H:%M:%S GMT+8")
    m=folium.Map(location=[4.2105,101.9758], zoom_start=6, tiles="CartoDB dark_matter")
    heat_data=[[coords[0],coords[1],random.randint(1,10)] for state, coords in MALAYSIA_STATES.items()]
    HeatMap(heat_data,radius=30,gradient={0.2:'blue',0.4:'cyan',0.6:'yellow',0.8:'orange',1:'red'}).add_to(m)
    heatmap=m._repr_html_()

    # SecureNation Index
    conn=sqlite3.connect(DB); c=conn.cursor()
    rows=c.execute("SELECT risk_score FROM threats").fetchall(); conn.close()
    gauge=round(sum([(r[0]*1.0 if r[0]>=70 else r[0]*0.5 if r[0]>=40 else r[0]*0.2) for r in rows])/ (len(rows)*100)*100,1) if rows else 0

    template = """
    <html>
    <head>
    <title>Sunday-Ring Dashboard</title>
    <link href="https://fonts.googleapis.com/css?family=Roboto:400,700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.datatables.net/1.13.6/css/jquery.dataTables.min.css"/>
    <style>
    body{margin:0;font-family:'Roboto',sans-serif;background:#0b1b2a;color:#00FFFF;}
    h1,h3{color:#00FFFF;}
    .card{background:#0d1b2a;padding:15px;margin:15px;border-radius:15px;box-shadow:0 0 20px #00FFFF;}
    table{border-collapse:collapse;width:100%;word-wrap:break-word;color:#00FFFF;}
    th{background:#0a1b3a;color:#00FFFF;padding:8px;}
    td{padding:8px;}
    tr:nth-child(even){background:#0b1b2a;}
    tr:nth-child(odd){background:#0d2a4a;}
    a.button{background:#00FFFF;color:#0b1b2a;padding:6px 12px;text-decoration:none;border-radius:4px;}
    </style>
    </head>
    <body>
    <h1>Sunday-Ring Dashboard</h1>
    <p class="card">Disclaimer: Developed and analysed by <b>darkgrid@redshark.my</b> from publicly available sources.</p>
    <div class="card">
    <h3>SecureNation Index</h3>
    <div style="width:300px;background:#0d1b2a;height:25px;border-radius:5px;">
      <div style="width:{{gauge}}%;background:#00FFFF;height:25px;text-align:center;color:#0b1b2a;font-weight:bold;">{{gauge}}/100</div>
    </div>
    </div>
    <div class="card">
    <h3>Malaysia Heatmap (Last Update: {{heat_time}})</h3>{{heatmap|safe}}
    </div>
    <div class="card">
    <h3>Trend (Last 7 Days)</h3>{% if trend %}<img src="data:image/png;base64,{{trend}}">{% endif %}
    </div>
    <div class="card">
    <h3>Indicator Types</h3>{% if type_chart %}<img src="data:image/png;base64,{{type_chart}}">{% endif %}
    </div>
    <div class="card">
    <h3>Latest Indicators</h3><table id="indicators"><thead>
    <tr><th>ID</th><th>Pulse</th><th>Indicator</th><th>Type</th><th>Class</th><th>Risk</th><th>Source</th><th>Created</th></tr>
    </thead><tbody>{% for row in table_data %}
    <tr><td>{{row['id']}}</td><td>{{row['pulse']}}</td><td>{{row['indicator']}}</td><td>{{row['type']}}</td>
    <td>{{row['classification']}}</td><td>{{row['risk_score']}}</td><td>{{row['source']}}</td><td>{{row['created_at']}}</td></tr>{% endfor %}
    </tbody></table>
    </div>
    <div class="card">
    <h3>Top 20 Indicators</h3><ul>{% for t in top20 %}<li>{{t[0]}} ({{t[1]}})</li>{% endfor %}</ul>
    </div>
    <div class="card">
    <h3>Download Reports</h3>
    <a class="button" href="/export/csv">CSV</a> <a class="button" href="/export/json">JSON</a>
    </div>
    <script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js"></script>
    <script>$(document).ready(function(){$('#indicators').DataTable({"pageLength":50,"scrollX":true});});</script>
    </body></html>
    """
    return render_template_string(template,gauge=gauge,trend=trend_img,type_chart=type_img,
                                  heatmap=heatmap,heat_time=timestamp,table_data=table_data,top20=top20)

# ---------------- EXPORT ----------------
@app.route("/export/csv")
def export_csv():
    conn=sqlite3.connect(DB); c=conn.cursor()
    threats=c.execute("SELECT * FROM threats").fetchall(); conn.close()
    si=io.StringIO(); cw=csv.writer(si)
    cw.writerow(["ID","Pulse","Indicator","Type","Class","MITRE","Risk","Source","Created"])
    cw.writerows(threats)
    output=io.BytesIO(); output.write(si.getvalue().encode()); output.seek(0)
    return send_file(output,as_attachment=True,download_name="sundayring_threats.csv",mimetype="text/csv")

@app.route("/export/json")
def export_json():
    conn=sqlite3.connect(DB); conn.row_factory=sqlite3.Row; c=conn.cursor()
    threats=c.execute("SELECT * FROM threats").fetchall(); conn.close()
    data=[dict(x) for x in threats]
    output=io.BytesIO(); output.write(json.dumps(data,indent=2).encode()); output.seek(0)
    return send_file(output,as_attachment=True,download_name="sundayring_threats.json",mimetype="application/json")

# ---------------- START ----------------
ensure_db()
insert_dummy_data(50)
cleanup_old_records()
if not os.getenv("RUN_MAIN"): threading.Thread(target=scheduler,daemon=True).start()
if __name__=="__main__": app.run(host="0.0.0.0",port=int(os.getenv("PORT",5000)))