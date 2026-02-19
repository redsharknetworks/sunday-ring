import os, io, csv, base64, sqlite3, threading, time, random, smtplib
from datetime import datetime
from functools import wraps
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

import requests
from flask import Flask, render_template_string, send_file, jsonify, request
from flask_socketio import SocketIO, emit

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

import folium
from folium.plugins import HeatMap

from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors

# ---------------- CONFIG ----------------
app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")
DB = os.getenv("DB_PATH", "/tmp/threats.db")
OTX_KEY = os.getenv("OTX_KEY")
OTX_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"
BOXING_RING = "boxing_ring.png"

SMTP_SERVER = os.getenv("SMTP_SERVER")
SMTP_PORT = int(os.getenv("SMTP_PORT","587"))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")
ALERT_EMAIL = os.getenv("ALERT_EMAIL")
ALERT_SMS_ENABLED = os.getenv("ALERT_SMS_ENABLED","false").lower()=="true"
TWILIO_SID = os.getenv("TWILIO_SID")
TWILIO_TOKEN = os.getenv("TWILIO_TOKEN")
TWILIO_FROM = os.getenv("TWILIO_FROM")
TWILIO_TO = os.getenv("TWILIO_TO")

# ---------------- DATABASE ----------------
def ensure_database():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS tenants (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        token TEXT UNIQUE
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS threats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tenant_id INTEGER,
        pulse TEXT,
        signal TEXT,
        type TEXT,
        classification TEXT,
        mitre TEXT,
        risk_score INTEGER,
        created_at TEXT
    )""")
    conn.commit()
    conn.close()

def get_conn(): return sqlite3.connect(DB)

def token_required():
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            token = request.args.get("token") or request.headers.get("Authorization")
            if not token: return "Unauthorized: missing token", 401
            conn = get_conn()
            c = conn.cursor()
            c.execute("SELECT id, name FROM tenants WHERE token=?", (token,))
            tenant = c.fetchone()
            conn.close()
            if not tenant: return "Unauthorized: invalid token", 401
            request.user = {"tenant_id": tenant[0], "tenant_name": tenant[1]}
            return f(*args, **kwargs)
        return wrapped
    return decorator

# ---------------- DUMMY DATA ----------------
def insert_dummy_data(tenant_id):
    conn = get_conn()
    c = conn.cursor()
    for i in range(5):
        pulse = f"Dummy Pulse {i+1}"
        signal = f"malicious{i+1}.com"
        score = random.randint(60,95)
        created = datetime.utcnow().isoformat()
        c.execute("""INSERT INTO threats
        (tenant_id,pulse,signal,type,classification,mitre,risk_score,created_at)
        VALUES (?,?,?,?,?,?,?,?)""",
        (tenant_id,pulse,signal,"domain","Medium","OTX",score,created))
    conn.commit()
    conn.close()

# ---------------- OTX FETCH ----------------
def fetch_otx_data():
    ensure_database()
    conn = get_conn()
    c = conn.cursor()
    tenants = c.execute("SELECT id,name FROM tenants").fetchall()
    conn.close()
    for tenant in tenants:
        tenant_id = tenant[0]
        tenant_name = tenant[1]
        if not OTX_KEY:
            insert_dummy_data(tenant_id)
            continue
        headers = {"X-OTX-API-KEY": OTX_KEY}
        try:
            r = requests.get(OTX_URL, headers=headers, timeout=15)
            r.raise_for_status()
            pulses = r.json().get("results",[])
        except:
            insert_dummy_data(tenant_id)
            continue
        conn = get_conn()
        c = conn.cursor()
        high_risk_signals = []
        for pulse in pulses[:10]:
            name = pulse.get("name","OTX Pulse")
            for ind in pulse.get("indicators",[]):
                val = ind.get("indicator")
                typ = ind.get("type","domain")
                if not val: continue
                score = random.randint(60,95)
                created = datetime.utcnow().isoformat()
                c.execute("""INSERT INTO threats
                (tenant_id,pulse,signal,type,classification,mitre,risk_score,created_at)
                VALUES (?,?,?,?,?,?,?,?)""",
                (tenant_id,name,val,typ,"Medium","OTX",score,created))
                if score>=85: high_risk_signals.append((val,score))
        conn.commit()
        conn.close()
        socketio.emit("update", {"tenant": tenant_id})
        if high_risk_signals: send_alerts(tenant_name, high_risk_signals)

def scheduler():
    while True:
        fetch_otx_data()
        time.sleep(3600)
threading.Thread(target=scheduler, daemon=True).start()

# ---------------- ALERTS ----------------
def send_alerts(tenant_name, high_risk_list):
    body = f"Tenant: {tenant_name}\nHigh-risk signals detected:\n"
    for val, score in high_risk_list:
        body += f"{val} (risk {score})\n"
    # Email
    if SMTP_SERVER and ALERT_EMAIL:
        msg = MIMEMultipart()
        msg['From'] = SMTP_USER
        msg['To'] = ALERT_EMAIL
        msg['Subject'] = f"[RedShark] High-risk alerts for {tenant_name}"
        msg.attach(MIMEText(body,'plain'))
        try:
            s = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
            s.starttls()
            s.login(SMTP_USER, SMTP_PASS)
            s.send_message(msg)
            s.quit()
        except Exception as e:
            print("Email alert failed:", e)
    # SMS placeholder (Twilio)
    if ALERT_SMS_ENABLED:
        try:
            from twilio.rest import Client
            client = Client(TWILIO_SID,TWILIO_TOKEN)
            client.messages.create(
                to=TWILIO_TO, from_=TWILIO_FROM, body=body
            )
        except Exception as e:
            print("SMS alert failed:", e)

# ---------------- CHARTS ----------------
def generate_trend_chart(tenant_id):
    conn = get_conn(); c = conn.cursor()
    c.execute("SELECT DATE(created_at), COUNT(*) FROM threats WHERE tenant_id=? GROUP BY DATE(created_at) ORDER BY DATE(created_at)", (tenant_id,))
    rows = c.fetchall(); conn.close()
    if not rows: return None
    dates, counts = zip(*rows)
    plt.figure(figsize=(6,3))
    plt.plot(dates, counts, marker="o", color="#d90429")
    plt.xticks(rotation=45)
    buf = io.BytesIO(); plt.tight_layout()
    plt.savefig(buf, format="png", facecolor="#0d1b2a"); plt.close()
    return base64.b64encode(buf.getvalue()).decode()

def generate_type_chart(tenant_id):
    conn = get_conn(); c = conn.cursor()
    c.execute("SELECT type, COUNT(*) FROM threats WHERE tenant_id=? GROUP BY type", (tenant_id,))
    rows = c.fetchall(); conn.close()
    if not rows: return None
    labels, values = zip(*rows)
    plt.figure(figsize=(4,3))
    plt.bar(labels, values, color="#ff7f50")
    buf = io.BytesIO(); plt.tight_layout()
    plt.savefig(buf, format="png", facecolor="#0d1b2a"); plt.close()
    return base64.b64encode(buf.getvalue()).decode()

# ---------------- SECURE INDEX ----------------
def secure_index(tenant_id):
    conn = get_conn(); c = conn.cursor()
    c.execute("SELECT AVG(risk_score) FROM threats WHERE tenant_id=?", (tenant_id,))
    avg = c.fetchone()[0] or 0; conn.close()
    return round(avg,1)

# ---------------- HEATMAP ----------------
MALAYSIA_STATES = {"Johor":[1.4927,103.7414],"Kedah":[6.1164,100.3678],"Kelantan":[6.1254,102.2381],
"Melaka":[2.1896,102.2501],"Negeri Sembilan":[2.7290,101.9383],"Pahang":[3.8167,103.3333],
"Perak":[4.5929,101.0900],"Perlis":[6.4400,100.2000],"Penang":[5.4164,100.3327],
"Sabah":[5.9804,116.0735],"Sarawak":[1.5533,110.3592],"Selangor":[3.1390,101.6869],
"Terengganu":[5.3300,103.1400],"Kuala Lumpur":[3.1390,101.6869],
"Putrajaya":[2.9264,101.6981],"Labuan":[5.2833,115.2333]}
def generate_heatmap(tenant_id):
    m = folium.Map(location=[4.2105,101.9758], zoom_start=6, tiles="CartoDB dark_matter")
    heat_data = [[coords[0], coords[1], random.randint(1,10)] for coords in MALAYSIA_STATES.values()]
    HeatMap(heat_data, radius=25).add_to(m)
    return m._repr_html_()

# ---------------- DASHBOARD ----------------
DASHBOARD_TEMPLATE = """
<html><head><title>RedShark SaaS Dashboard</title>
<script src="https://cdn.socket.io/4.6.0/socket.io.min.js"></script>
<script>
var socket = io(); socket.on('update', function(msg){if(msg.tenant=={{ tenant_id }}) location.reload();});
</script>
<style>
body {background:#0d1b2a;color:white;font-family:sans-serif;}
table{border-collapse: collapse;width:100%;}
th,td{padding:6px;text-align:left;}
tr:nth-child(even){background:#1b2a44;}
tr:nth-child(odd){background:#0d1b2a;}
th{background:#d90429;color:white;}
</style></head><body>
<h2>RedShark SaaS Dashboard</h2>
<p>Tenant: {{ tenant_name }} | SecureNation Index: {{ secure_index }}</p>
<h3>Malaysia Heatmap</h3>{{ heatmap|safe }}
<h3>Trend Chart</h3>{% if trend %}<img src="data:image/png;base64,{{ trend }}">{% endif %}
<h3>Signal Types</h3>{% if type_chart %}<img src="data:image/png;base64,{{ type_chart }}">{% endif %}
<h3>Top 10 Signals</h3><table><tr><th>Signal</th><th>Count</th></tr>{% for row in top10 %}<tr><td>{{ row.signal }}</td><td>{{ row.count }}</td></tr>{% endfor %}</table>
<h3>MITRE ATT&CK Matrix</h3><table><tr><th>Technique</th><th>Count</th></tr>{% for mitre,count in mitre_matrix.items() %}<tr><td>{{ mitre }}</td><td>{{ count }}</td></tr>{% endfor %}</table>
</body></html>
"""

@app.route("/dashboard")
@token_required()
def dashboard():
    tenant_id = request.user["tenant_id"]; tenant_name = request.user["tenant_name"]
    conn = get_conn(); c = conn.cursor()
    c.execute("SELECT signal, COUNT(*) FROM threats WHERE tenant_id=? GROUP BY signal ORDER BY COUNT(*) DESC LIMIT 10",(tenant_id,))
    top10 = [{"signal":r[0],"count":r[1]} for r in c.fetchall()]
    c.execute("SELECT mitre, COUNT(*) FROM threats WHERE tenant_id=? GROUP BY mitre",(tenant_id,))
    mitre_matrix = dict(c.fetchall()); conn.close()
    return render_template_string(DASHBOARD_TEMPLATE,
                                  tenant_name=tenant_name,
                                  tenant_id=tenant_id,
                                  secure_index=secure_index(tenant_id),
                                  top10=top10,
                                  mitre_matrix=mitre_matrix,
                                  trend=generate_trend_chart(tenant_id),
                                  type_chart=generate_type_chart(tenant_id),
                                  heatmap=generate_heatmap(tenant_id))

# ---------------- REPORT ROUTES ----------------
@app.route("/report/csv")
@token_required()
def csv_report():
    tenant_id = request.user["tenant_id"]
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    filename = f"RedShark_{timestamp}.csv"
    conn = get_conn(); c = conn.cursor()
    c.execute("SELECT * FROM threats WHERE tenant_id=?",(tenant_id,))
    rows = c.fetchall(); conn.close()
    si = io.StringIO(); cw=csv.writer(si)
    cw.writerow(["ID","Pulse","Signal","Type","Class","MITRE","Risk","Created"])
    cw.writerows(rows)
    buf = io.BytesIO(); buf.write(si.getvalue().encode()); buf.seek(0)
    return send_file(buf, as_attachment=True, download_name=filename)

@app.route("/report/json")
@token_required()
def json_report():
    tenant_id = request.user["tenant_id"]
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    filename = f"RedShark_{timestamp}.json"
    conn = get_conn(); c=conn.cursor(); c.execute("SELECT * FROM threats WHERE tenant_id=?",(tenant_id,))
    rows=[dict(zip([column[0] for column in c.description],r)) for r in c.fetchall()]
    conn.close()
    buf = io.BytesIO(); buf.write(str(rows).encode()); buf.seek(0)
    return send_file(buf, as_attachment=True, download_name=filename)

@app.route("/report/pdf")
@token_required()
def pdf_report():
    tenant_id = request.user["tenant_id"]; tenant_name=request.user["tenant_name"]
    timestamp=datetime.now().strftime("%Y%m%d%H%M%S"); filename=f"RedShark_{timestamp}.pdf"
    buffer=io.BytesIO(); doc=SimpleDocTemplate(buffer,pagesize=letter); styles=getSampleStyleSheet()
    elements=[]
    elements.append(Paragraph(f"RedShark Threat Intelligence Report - {tenant_name}",styles["Title"]))
    elements.append(Spacer(1,12))
    elements.append(Paragraph(f"SecureNation Index: {secure_index(tenant_id)} /100",styles["Normal"]))
    elements.append(PageBreak())
    # Table
    conn=get_conn(); c=conn.cursor(); c.execute("SELECT * FROM threats WHERE tenant_id=?",(tenant_id,))
    rows=c.fetchall(); conn.close()
    data=[["ID","Pulse","Signal","Type","Class","MITRE","Risk","Created"]]+[list(r) for r in rows]
    t=Table(data,repeatRows=1)
    t.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,0),colors.darkblue),
        ('TEXTCOLOR',(0,0),(-1,0),colors.white),
        ('GRID',(0,0),(-1,-1),0.5,colors.white),
        ('BACKGROUND',(0,1),(-1,-1),colors.HexColor("#1b2a44")),
        ('ALIGN',(0,0),(-1,-1),'CENTER')
    ]))
    elements.append(t); doc.build(elements); buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name=filename)

# ---------------- START ----------------
if __name__=="__main__":
    ensure_database()
    fetch_otx_data()
    socketio.run(app, host="0.0.0.0", port=int(os.getenv("PORT",5000)))
