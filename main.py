import os
import io
import csv
import base64
import sqlite3
import threading
import time
import random
from datetime import datetime
from functools import wraps

import requests
from flask import Flask, render_template_string, send_file, jsonify, request, redirect, url_for, session

from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle, PageBreak
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

import folium
from folium.plugins import HeatMap

# ---------------- CONFIG ----------------
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET", "supersecretkey")
DB = os.getenv("DB_PATH", "/tmp/threats.db")
OTX_KEY = os.getenv("OTX_KEY")
OTX_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"
BOXING_RING = "boxing_ring.png"

# ---------------- LOGIN ----------------
USERNAME = os.getenv("DASH_USER", "admin")
PASSWORD = os.getenv("DASH_PASS", "password")

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return decorated

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method=="POST":
        if request.form.get("username")==USERNAME and request.form.get("password")==PASSWORD:
            session["logged_in"] = True
            return redirect(request.args.get("next") or url_for("dashboard"))
        return "Invalid credentials", 401
    return """
    <form method="post">
    <input name="username" placeholder="Username"/>
    <input name="password" type="password" placeholder="Password"/>
    <input type="submit"/>
    </form>
    """

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ---------------- DATABASE ----------------
def ensure_database():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS threats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
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

def insert_dummy_data():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    for i in range(5):
        pulse = f"Dummy Pulse {i+1}"
        signal = f"malicious{i+1}.com"
        score = random.randint(60,95)
        created = datetime.utcnow().isoformat()
        c.execute("""INSERT INTO threats (pulse,signal,type,classification,mitre,risk_score,created_at)
        VALUES (?,?,?,?,?,?,?)""",(pulse,signal,"domain","Medium","OTX",score,created))
    conn.commit()
    conn.close()

def fetch_otx_data():
    ensure_database()
    if not OTX_KEY:
        insert_dummy_data()
        return
    headers = {"X-OTX-API-KEY": OTX_KEY}
    try:
        r = requests.get(OTX_URL, headers=headers, timeout=15)
        r.raise_for_status()
        pulses = r.json().get("results", [])
    except:
        insert_dummy_data()
        return
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    for pulse in pulses[:10]:
        name = pulse.get("name","OTX Pulse")
        for ind in pulse.get("indicators",[]):
            val = ind.get("indicator")
            typ = ind.get("type","domain")
            if not val: continue
            score = random.randint(60,95)
            created = datetime.utcnow().isoformat()
            c.execute("""INSERT INTO threats (pulse,signal,type,classification,mitre,risk_score,created_at)
            VALUES (?,?,?,?,?,?,?)""",(name,val,typ,"Medium","OTX",score,created))
    conn.commit()
    conn.close()

# ---------------- SCHEDULER ----------------
def scheduler():
    while True:
        fetch_otx_data()
        time.sleep(3600)

threading.Thread(target=scheduler, daemon=True).start()

# ---------------- CHARTS ----------------
def generate_trend_chart():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    trend = c.execute("SELECT substr(created_at,1,10) as date, COUNT(*) as cnt FROM threats GROUP BY date ORDER BY date").fetchall()
    conn.close()
    if not trend: return None
    dates = [x["date"] for x in trend]
    counts = [x["cnt"] for x in trend]
    plt.figure(figsize=(6,3))
    ax = plt.gca()
    if os.path.exists(BOXING_RING):
        bg = plt.imread(BOXING_RING)
        ax.imshow(bg,extent=[0,len(dates)-1,0,max(counts)+5],aspect='auto',alpha=0.2)
    plt.plot(dates,counts,marker="o",color="#d90429")
    plt.xticks(rotation=45)
    plt.title("Threat Trend")
    buf = io.BytesIO()
    plt.tight_layout()
    plt.savefig(buf,format="png",facecolor="#0d1b2a")
    plt.close()
    buf.seek(0)
    return base64.b64encode(buf.getvalue()).decode()

def generate_type_chart():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    types = c.execute("SELECT type,COUNT(*) as cnt FROM threats GROUP BY type").fetchall()
    conn.close()
    if not types: return None
    labels = [x["type"] for x in types]
    values = [x["cnt"] for x in types]
    plt.figure(figsize=(4,3))
    plt.bar(labels,values,color="#ff7f50")
    plt.title("Signal Types")
    buf=io.BytesIO()
    plt.tight_layout()
    plt.savefig(buf,format="png",facecolor="#0d1b2a")
    plt.close()
    buf.seek(0)
    return base64.b64encode(buf.getvalue()).decode()

# ---------------- MALAYSIA HEATMAP ----------------
MALAYSIA_STATES = {
    "Johor":[1.4927,103.7414],"Kedah":[6.1164,100.3678],"Kelantan":[6.1254,102.2381],
    "Melaka":[2.1896,102.2501],"Negeri Sembilan":[2.7290,101.9383],"Pahang":[3.8167,103.3333],
    "Perak":[4.5929,101.0900],"Perlis":[6.4400,100.2000],"Penang":[5.4164,100.3327],
    "Sabah":[5.9804,116.0735],"Sarawak":[1.5533,110.3592],"Selangor":[3.1390,101.6869],
    "Terengganu":[5.3300,103.1400],"Kuala Lumpur":[3.1390,101.6869],"Putrajaya":[2.9264,101.6981],
    "Labuan":[5.2833,115.2333]
}

def generate_malaysia_heatmap():
    m = folium.Map(location=[4.2105,101.9758], zoom_start=6, tiles="CartoDB dark_matter")
    heat_data=[]
    for state,coords in MALAYSIA_STATES.items():
        count = random.randint(1,10)
        heat_data.append([coords[0],coords[1],count])
    HeatMap(heat_data,radius=25).add_to(m)
    return m._repr_html_()

# ---------------- SECURENATION INDEX ----------------
def calculate_secure_index():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT AVG(risk_score) FROM threats")
    avg = c.fetchone()[0] or 0
    conn.close()
    return round(avg,1)

def generate_secure_gauge():
    index = calculate_secure_index()
    plt.figure(figsize=(4,2))
    plt.barh([0],[index],color="#d90429")
    plt.xlim(0,100)
    plt.yticks([])
    plt.title(f"SecureNation Index: {index}",color="white")
    buf = io.BytesIO()
    plt.tight_layout()
    plt.savefig(buf,format="png",facecolor="#0d1b2a")
    plt.close()
    buf.seek(0)
    return base64.b64encode(buf.getvalue()).decode()

# ---------------- DASHBOARD ----------------
TEMPLATE = """<html><head><title>RedShark Dashboard</title></head><body style='background:#0d1b2a;color:white;font-family:sans-serif;'>
<h2>RedShark Threat Intelligence</h2>
<p>SecureNation Index:</p>
<img src="data:image/png;base64,{{ gauge }}">
<h3>Malaysia Heatmap</h3>{{ heatmap | safe }}
<h3>Trend</h3>{% if trend %}<img src="data:image/png;base64,{{ trend }}">{% endif %}
<h3>Signal Types</h3>{% if type_chart %}<img src="data:image/png;base64,{{ type_chart }}">{% endif %}
<h3>Latest Signals</h3>
<table border=1 style='color:white'><tr><th>ID</th><th>Pulse</th><th>Signal</th><th>Type</th><th>Risk</th><th>Created</th></tr>
{% for row in table_data %}
<tr><td>{{ row['id'] }}</td><td>{{ row['pulse'] }}</td><td>{{ row['signal'] }}</td><td>{{ row['type'] }}</td><td>{{ row['risk_score'] }}</td><td>{{ row['created_at'] }}</td></tr>
{% endfor %}
</table></body></html>"""

@app.route("/")
@login_required
def dashboard():
    trend = generate_trend_chart()
    type_chart = generate_type_chart()
    heatmap = generate_malaysia_heatmap()
    gauge = generate_secure_gauge()
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    table_data = conn.cursor().execute("SELECT * FROM threats ORDER BY created_at DESC LIMIT 50").fetchall()
    conn.close()
    return render_template_string(TEMPLATE, trend=trend, type_chart=type_chart, heatmap=heatmap, gauge=gauge, table_data=table_data)

# ---------------- REPORTS ----------------
@app.route("/report/csv")
@login_required
def report_csv():
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    rows = c.execute("SELECT * FROM threats").fetchall()
    conn.close()
    si=io.StringIO()
    cw=csv.writer(si)
    cw.writerow(["ID","Pulse","Signal","Type","Class","MITRE","Risk","Created"])
    cw.writerows(rows)
    buf=io.BytesIO()
    buf.write(si.getvalue().encode())
    buf.seek(0)
    return send_file(buf,as_attachment=True,download_name=f"report_{timestamp}.csv")

@app.route("/report/json")
@login_required
def report_json():
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    rows = conn.cursor().execute("SELECT * FROM threats").fetchall()
    conn.close()
    data=[dict(x) for x in rows]
    return jsonify(data)

@app.route("/report/pdf")
@login_required
def report_pdf():
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    buffer=io.BytesIO()
    doc=SimpleDocTemplate(buffer,pagesize=letter)
    styles=getSampleStyleSheet()
    elements=[]
    elements.append(Paragraph("RedShark Threat Intelligence Report",styles["Title"]))
    elements.append(Spacer(1,12))
    elements.append(Paragraph(f"SecureNation Index: {calculate_secure_index()}/100",styles["Normal"]))
    doc.build(elements)
    buffer.seek(0)
    return send_file(buffer,as_attachment=True,download_name=f"report_{timestamp}.pdf")

# ---------------- 404 ----------------
@app.errorhandler(404)
def page_not_found(e):
    return "<h1>404 Not Found</h1><p>The requested page does not exist.</p>",404

# ---------------- START ----------------
ensure_database()
fetch_otx_data()

if __name__=="__main__":
    app.run(host="0.0.0.0",port=int(os.getenv("PORT",5000)))
