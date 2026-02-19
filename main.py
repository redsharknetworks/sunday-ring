import os
import io
import csv
import json
import base64
import random
import threading
import time
from datetime import datetime, timedelta

import requests
from flask import (
    Flask, render_template_string, send_file,
    jsonify, request, redirect, session, abort
)

from werkzeug.security import generate_password_hash, check_password_hash

from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle, PageBreak
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

import folium
from folium.plugins import HeatMap

# ================= CONFIG =================

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "super-secret")

DATABASE_URL = os.getenv("DATABASE_URL")  # PostgreSQL if set
OTX_KEY = os.getenv("OTX_KEY")
API_KEY = os.getenv("API_KEY", "redshark-secure")
OTX_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"
RETENTION_DAYS = int(os.getenv("RETENTION_DAYS", 30))

# ================= DATABASE =================

if DATABASE_URL:
    import psycopg2
    def get_conn():
        return psycopg2.connect(DATABASE_URL)
else:
    import sqlite3
    DB = "threats.db"
    def get_conn():
        return sqlite3.connect(DB, timeout=30, check_same_thread=False)


def ensure_database():
    conn = get_conn()
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS threats (
        id SERIAL PRIMARY KEY,
        pulse TEXT,
        signal TEXT,
        type TEXT,
        classification TEXT,
        mitre TEXT,
        risk_score INTEGER,
        created_at TEXT,
        UNIQUE(signal, type)
    )
    """)
    conn.commit()
    conn.close()


# ================= AUTH (RBAC) =================

USERS = {
    "admin": generate_password_hash("admin123"),
    "analyst": generate_password_hash("analyst123")
}

def login_required(role=None):
    if "user" not in session:
        return False
    if role and session.get("role") != role:
        return False
    return True


@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        user = request.form["username"]
        pw = request.form["password"]
        if user in USERS and check_password_hash(USERS[user], pw):
            session["user"] = user
            session["role"] = "admin" if user=="admin" else "analyst"
            return redirect("/")
    return """
    <form method='post'>
    <input name='username'>
    <input name='password' type='password'>
    <button>Login</button>
    </form>
    """


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


# ================= RISK ENGINE =================

def calculate_risk(indicator_type):
    base = {"domain":70,"ip":80,"url":85,"file_hash":90}.get(indicator_type,65)
    return min(100, base + random.randint(0,10))


def classify(score):
    if score >= 85: return "High"
    if score >= 70: return "Medium"
    return "Low"


# ================= INSERT =================

def insert_threat(pulse, signal, typ):
    score = calculate_risk(typ)
    classification = classify(score)

    conn = get_conn()
    c = conn.cursor()
    try:
        c.execute("""
        INSERT INTO threats
        (pulse, signal, type, classification, mitre, risk_score, created_at)
        VALUES (%s,%s,%s,%s,%s,%s,%s)
        ON CONFLICT (signal,type) DO NOTHING
        """ if DATABASE_URL else """
        INSERT OR IGNORE INTO threats
        (pulse, signal, type, classification, mitre, risk_score, created_at)
        VALUES (?,?,?,?,?,?,?)
        """,
        (pulse, signal, typ, classification, "OTX",
         score, datetime.utcnow().isoformat()))
    except:
        pass
    conn.commit()
    conn.close()


# ================= OTX FETCH =================

def fetch_otx_data():
    ensure_database()
    if not OTX_KEY:
        for i in range(5):
            insert_threat("Dummy", f"malicious{i}.com","domain")
        return

    headers = {"X-OTX-API-KEY": OTX_KEY}
    try:
        r = requests.get(OTX_URL, headers=headers, timeout=20)
        pulses = r.json().get("results", [])
    except:
        return

    for pulse in pulses[:10]:
        for ind in pulse.get("indicators", []):
            if ind.get("indicator"):
                insert_threat(pulse.get("name","OTX"),
                              ind["indicator"],
                              ind.get("type","domain"))


# ================= SECURENATION INDEX =================

def secure_index():
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM threats")
    total = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM threats WHERE risk_score>=85")
    high = c.fetchone()[0]
    conn.close()

    if total==0: return 100
    return max(0,100-int((high/total)*100))


# ================= ANOMALY DETECTION =================

def detect_spike():
    conn = get_conn()
    c = conn.cursor()
    c.execute("""
    SELECT substr(created_at,1,10), COUNT(*)
    FROM threats GROUP BY substr(created_at,1,10)
    ORDER BY substr(created_at,1,10) DESC LIMIT 2
    """)
    rows = c.fetchall()
    conn.close()
    if len(rows)==2 and rows[0][1] > rows[1][1]*1.5:
        return True
    return False


# ================= MALAYSIA HEATMAP =================

MALAYSIA_STATES = {
    "Johor":[1.4927,103.7414],
    "Selangor":[3.1390,101.6869],
    "Penang":[5.4164,100.3327],
    "Sabah":[5.9804,116.0735],
    "Sarawak":[1.5533,110.3592]
}

def generate_heatmap():
    m = folium.Map(location=[4.2,101.9], zoom_start=6,
                   tiles="CartoDB dark_matter")
    heat=[]
    for coords in MALAYSIA_STATES.values():
        heat.append([coords[0],coords[1],random.randint(1,10)])
    HeatMap(heat,radius=25).add_to(m)
    return m._repr_html_()


# ================= ASEAN INDEX =================

ASEAN = ["Malaysia","Singapore","Thailand","Indonesia","Vietnam"]

def asean_comparison():
    base = secure_index()
    return {c: max(40,min(95,base+random.randint(-10,10)))
            for c in ASEAN}


# ================= DASHBOARD =================

@app.route("/")
def dashboard():
    if not login_required():
        return redirect("/login")

    index = secure_index()
    spike = detect_spike()
    heatmap = generate_heatmap()
    asean = asean_comparison()

    return render_template_string("""
    <h2>SecureNation Dashboard</h2>
    <p>User: {{session['user']}} ({{session['role']}})</p>
    <p>SecureNation Index: {{index}}</p>
    {% if spike %}<p style='color:red'>⚠ Risk Spike Detected</p>{% endif %}
    <h3>Malaysia Heatmap</h3>
    {{heatmap|safe}}
    <h3>ASEAN Comparison</h3>
    <ul>{% for k,v in asean.items() %}
    <li>{{k}} : {{v}}</li>{% endfor %}</ul>
    <a href='/report/pdf'>Download PDF</a>
    <a href='/logout'>Logout</a>
    """, index=index, spike=spike,
       heatmap=heatmap, asean=asean)


# ================= PDF EXPORT =================

@app.route("/report/pdf")
def pdf_report():
    if not login_required("admin"):
        abort(403)

    buffer=io.BytesIO()
    doc=SimpleDocTemplate(buffer,pagesize=letter)
    styles=getSampleStyleSheet()
    elements=[]

    elements.append(Paragraph("SecureNation Executive Report", styles["Title"]))
    elements.append(Spacer(1,12))
    elements.append(Paragraph(f"Index: {secure_index()}", styles["Normal"]))
    elements.append(PageBreak())

    conn=get_conn()
    c=conn.cursor()
    c.execute("SELECT signal,risk_score FROM threats LIMIT 50")
    rows=c.fetchall()
    conn.close()

    table_data=[["Signal","Risk"]]
    for r in rows:
        table_data.append([r[0],r[1]])

    t=Table(table_data)
    t.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,0),colors.darkblue),
        ('TEXTCOLOR',(0,0),(-1,0),colors.white),
        ('GRID',(0,0),(-1,-1),0.5,colors.grey)
    ]))
    elements.append(t)

    doc.build(elements)
    buffer.seek(0)
    return send_file(buffer,as_attachment=True,
                     download_name="SecureNation_Report.pdf")


# ================= START =================

ensure_database()
fetch_otx_data()

def scheduler():
    while True:
        fetch_otx_data()
        time.sleep(3600)

if os.environ.get("WERKZEUG_RUN_MAIN") == "true":
    threading.Thread(target=scheduler,daemon=True).start()

if __name__=="__main__":
    app.run(host="0.0.0.0",port=5000)
