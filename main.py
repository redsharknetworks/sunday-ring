import os, io, csv, json, sqlite3, threading, time, random
from datetime import datetime, timedelta
import requests
from flask import Flask, render_template_string, send_file
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.pagesizes import landscape, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT
from reportlab.lib import colors
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import base64
import folium
from folium.plugins import HeatMap

# ---------------- CONFIG ----------------
app = Flask(__name__)
PORT = int(os.getenv("PORT",5000))
DB = os.getenv("DB_PATH","/tmp/sundayring.db")
OTX_KEY = os.getenv("OTX_KEY")
SURICATA_FILE = os.getenv("SURICATA_FILE","/tmp/suricata/eve.json")
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY")
OTX_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"

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
    conn = sqlite3.connect(DB); c=conn.cursor()
    cutoff = (datetime.utcnow()-timedelta(days=60)).isoformat()
    c.execute("DELETE FROM threats WHERE created_at<?",(cutoff,))
    conn.commit(); conn.close()

def classify_risk(score):
    if score>=70: return "High"
    elif score>=40: return "Medium"
    else: return "Low"

def insert_dummy_data():
    conn=sqlite3.connect(DB); c=conn.cursor()
    for i in range(20):
        created=datetime.utcnow().isoformat()
        score=random.randint(10,95)
        c.execute("""INSERT OR IGNORE INTO threats 
        (pulse,indicator,type,classification,mitre,risk_score,source,created_at)
        VALUES (?,?,?,?,?,?,?,?)""",
        (f"Dummy Pulse {i+1}",f"malicious{i+1}.com","domain",classify_risk(score),"OTX",score,"Dummy",created))
    conn.commit(); conn.close()

# ---------------- OTX ----------------
def fetch_otx_data():
    ensure_db()
    if not OTX_KEY: insert_dummy_data(); return
    headers={"X-OTX-API-KEY":OTX_KEY}
    try: pulses=requests.get(OTX_URL,headers=headers,timeout=15).json().get("results",[])
    except: insert_dummy_data(); return
    conn=sqlite3.connect(DB); c=conn.cursor()
    for pulse in pulses[:50]:
        name=pulse.get("name","OTX Pulse")
        for ind in pulse.get("indicators",[]):
            val=ind.get("indicator"); typ=ind.get("type","domain")
            if not val: continue
            score=random.randint(10,95)
            c.execute("""INSERT OR IGNORE INTO threats
            (pulse,indicator,type,classification,mitre,risk_score,source,created_at)
            VALUES (?,?,?,?,?,?,?,?)""",(name,val,typ,classify_risk(score),"OTX",score,"OTX",datetime.utcnow().isoformat()))
    conn.commit(); conn.close()

# ---------------- SURICATA ----------------
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

# ---------------- ABUSEIPDB ----------------
def fetch_abuseipdb_data():
    if not ABUSEIPDB_KEY: return
    conn=sqlite3.connect(DB); c=conn.cursor()
    sample_ips=["8.8.8.8","1.1.1.1"]  # dynamic later
    headers={"Key":ABUSEIPDB_KEY,"Accept":"application/json"}
    for ip in sample_ips:
        try:
            r=requests.get("https://api.abuseipdb.com/api/v2/check",
            headers=headers,params={"ipAddress":ip,"maxAgeInDays":30},timeout=10).json()
            confidence=r["data"]["abuseConfidenceScore"]
            c.execute("""INSERT OR IGNORE INTO threats
            (pulse,indicator,type,classification,mitre,risk_score,source,created_at)
            VALUES (?,?,?,?,?,?,?,?)""",
            (f"AbuseIPDB Lookup {ip}",ip,"ip",classify_risk(confidence),"AbuseIPDB",confidence,"AbuseIPDB",datetime.utcnow().isoformat()))
        except: continue
    conn.commit(); conn.close()

# ---------------- SCHEDULER ----------------
def scheduler():
    while True:
        fetch_otx_data(); parse_suricata(); fetch_abuseipdb_data(); cleanup_old_records()
        time.sleep(3600)

# ---------------- CHARTS ----------------
def generate_charts():
    conn=sqlite3.connect(DB); conn.row_factory=sqlite3.Row; c=conn.cursor()
    trend_rows=c.execute("SELECT substr(created_at,1,10) date,COUNT(*) cnt FROM threats GROUP BY date ORDER BY date").fetchall()
    type_rows=c.execute("SELECT type,COUNT(*) cnt FROM threats GROUP BY type").fetchall()
    conn.close()
    trend_img,type_img=None,None
    if trend_rows:
        d=dict([(r["date"],r["cnt"]) for r in trend_rows])
        today=datetime.utcnow(); dates,counts=[],[]
        for i in range(6,-1,-1):
            x=(today-timedelta(days=i)).strftime("%Y-%m-%d")
            dates.append(x); counts.append(d.get(x,0))
        plt.figure(figsize=(6,3))
        plt.plot(dates,counts,marker="o",color="#00ff90")
        plt.title("Threat Trend (Last 7 Days)",color="#00fff0")
        plt.xticks(rotation=45); plt.tight_layout()
        buf=io.BytesIO(); plt.savefig(buf,format="png",facecolor="#0b0f17"); plt.close()
        trend_img=base64.b64encode(buf.getvalue()).decode()
    if type_rows:
        labels=[r["type"] for r in type_rows]; values=[r["cnt"] for r in type_rows]
        plt.figure(figsize=(6,4))
        plt.bar(labels,values,color="#00ff90")
        plt.title("Indicator Types",color="#00fff0"); plt.xticks(rotation=30); plt.tight_layout()
        buf=io.BytesIO(); plt.savefig(buf,format="png",facecolor="#0b0f17"); plt.close()
        type_img=base64.b64encode(buf.getvalue()).decode()
    return trend_img,type_img

# ---------------- MALAYSIA HEATMAP ----------------
def generate_malaysia_heatmap():
    timestamp=(datetime.utcnow()+timedelta(hours=8)).strftime("%Y-%m-%d %H:%M:%S GMT+8")
    m=folium.Map(location=[4.2105,101.9758],zoom_start=6,tiles="CartoDB dark_matter")
    heat_data=[[v[0],v[1],random.randint(1,10)] for v in MALAYSIA_STATES.values()]
    HeatMap(heat_data,radius=25).add_to(m)
    return m._repr_html_(),timestamp

# ---------------- SECURENATION INDEX ----------------
def calculate_secure_index():
    conn=sqlite3.connect(DB); c=conn.cursor()
    rows=c.execute("SELECT risk_score FROM threats").fetchall(); conn.close()
    if not rows: return 0
    total,max_possible=0,len(rows)*100
    for (score,) in rows: w=1.0 if score>=70 else 0.5 if score>=40 else 0.2; total+=score*w
    return round(total/max_possible*100,1)

# ---------------- DASHBOARD TEMPLATE ----------------
TEMPLATE="""<html><head><title>Sunday-Ring Dashboard</title>
<link rel="stylesheet" href="https://cdn.datatables.net/1.13.6/css/jquery.dataTables.min.css"/>
<style>
body{background:#0b0f17;color:#00fff0;font-family:sans-serif;}
table{border-collapse:collapse;width:100%;word-wrap:break-word;}
th,td{padding:8px;text-align:left;}
th{background:#101728;color:#00fff0;}
tr:nth-child(even){background:#101728;}
tr:nth-child(odd){background:#0b0f17;}
a.button{background:#00ff90;color:#0b0f17;padding:6px 12px;text-decoration:none;border-radius:4px;}
</style></head><body>
<h1>Sunday-Ring Dashboard</h1>
<p>Disclaimer: Developed and analysed by <b>darkgrid@redshark.my</b> from publicly available sources.</p>
<h3>SecureNation Index</h3>
<div style="width:300px;background:#101728;height:25px;border-radius:5px;">
<div style="width:{{ gauge }}%;background:#00ff90;height:25px;text-align:center;color:#0b0f17;font-weight:bold;">{{ gauge }}/100</div>
</div>
<h3>Malaysia Heatmap (Last Update: {{ heatmap_time }})</h3>{{ heatmap|safe }}
<h3>Trend</h3>{% if trend %}<img src="data:image/png;base64,{{ trend }}">{% else %}<p>No data</p>{% endif %}
<h3>Indicator Types</h3>{% if type_chart %}<img src="data:image/png;base64,{{ type_chart }}">{% else %}<p>No data</p>{% endif %}
<h3>Latest Indicators</h3><table id="indicators"><thead>
<tr><th>ID</th><th>Pulse</th><th>Indicator</th><th>Type</th><th>Class</th><th>Risk</th><th>Source</th><th>Created</th></tr>
</thead><tbody>{% for row in table_data %}
<tr><td>{{ row['id'] }}</td><td>{{ row['pulse'] }}</td><td>{{ row['indicator'] }}</td><td>{{ row['type'] }}</td>
<td>{{ row['classification'] }}</td><td>{{ row['risk_score'] }}</td><td>{{ row['source'] }}</td><td>{{ row['created_at'] }}</td></tr>{% endfor %}
</tbody></table>
<h3>Top 20 Indicators</h3><ul>{% for t in top20 %}<li>{{ t[0] }} ({{ t[1] }})</li>{% endfor %}</ul>
<h3>Download Reports</h3>
<a class="button" href="/export/csv">CSV</a> <a class="button" href="/export/json">JSON</a> <a class="button" href="/export/pdf">PDF</a>
<script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
<script src="https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js"></script>
<script>$(document).ready(function(){$('#indicators').DataTable({"pageLength":50,"scrollX":true});});</script>
</body></html>"""

@app.route("/")
def dashboard():
    trend,type_chart=generate_charts()
    heatmap,heat_time=generate_malaysia_heatmap()
    gauge=calculate_secure_index()
    conn=sqlite3.connect(DB); conn.row_factory=sqlite3.Row; c=conn.cursor()
    table_data=c.execute("SELECT * FROM threats ORDER BY created_at DESC LIMIT 50").fetchall()
    top20=c.execute("SELECT indicator,count(*) cnt FROM threats GROUP BY indicator ORDER BY cnt DESC LIMIT 20").fetchall()
    conn.close()
    return render_template_string(TEMPLATE,trend=trend,type_chart=type_chart,heatmap=heatmap,
                                  heatmap_time=heat_time,gauge=gauge,table_data=table_data,top20=top20)

# ---------------- EXPORT ROUTES ----------------
def export_csv(): conn=sqlite3.connect(DB); c=conn.cursor(); threats=c.execute("SELECT * FROM threats").fetchall(); conn.close(); si=io.StringIO(); cw=csv.writer(si); cw.writerow(["ID","Pulse","Indicator","Type","Class","MITRE","Risk","Source","Created"]); cw.writerows(threats); output=io.BytesIO(); output.write(si.getvalue().encode()); output.seek(0); return output
def export_json(): conn=sqlite3.connect(DB); conn.row_factory=sqlite3.Row; c=conn.cursor(); threats=c.execute("SELECT * FROM threats").fetchall(); conn.close(); data=[dict(x) for x in threats]; output=io.BytesIO(); output.write(json.dumps(data,indent=2).encode()); output.seek(0); return output
@app.route("/export/csv"); def csv_route(): return send_file(export_csv(),as_attachment=True,download_name="sundayring_threats.csv",mimetype="text/csv")
@app.route("/export/json"); def json_route(): return send_file(export_json(),as_attachment=True,download_name="sundayring_threats.json",mimetype="application/json")

# ---------------- START ----------------
ensure_db(); fetch_otx_data(); parse_suricata(); fetch_abuseipdb_data(); cleanup_old_records()
if not os.getenv("RUN_MAIN"): threading.Thread(target=scheduler,daemon=True).start()
if __name__=="__main__": app.run(host="0.0.0.0",port=PORT)