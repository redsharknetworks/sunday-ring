import os
import sqlite3
import random
import requests
from datetime import datetime, timedelta
from flask import Flask, jsonify, request, render_template_string, send_file
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import io
import csv
import base64
import folium
from folium.plugins import HeatMap
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import A4, landscape
import ipaddress
import re

app = Flask(__name__)

DB = "threats.db"
PAGE_SIZE = 50
DISCLAIMER = "Information and analysis are derived from publicly available sources and developed by DarkGrid (darkgrid@redshark.my)."

OTX_API_KEY = os.environ.get("OTX_API_KEY")
OTX_URL = "https://otx.alienvault.com/api/v1/indicators/export"

# ------------------ DATABASE ------------------
def init_db():
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
        created_at TEXT
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS threat_hashes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pulse TEXT,
        hash TEXT,
        classification TEXT,
        mitre TEXT,
        risk_score INTEGER,
        created_at TEXT
    )
    """)

    conn.commit()
    conn.close()

# ------------------ VALIDATION ------------------
def is_valid_ipv4(addr):
    try:
        ipaddress.IPv4Address(addr)
        return True
    except:
        return False

def is_valid_domain(domain):
    pattern = re.compile(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")
    return bool(pattern.match(domain))

def is_valid_url(url):
    return url.startswith("http://") or url.startswith("https://")

# ------------------ RISK ENGINE ------------------
def calculate_risk(classification, mitre):
    base = {"Low":30,"Medium":60,"High":80}.get(classification,50)
    mitre_weight = 15 if "T1566" in mitre else 10
    return min(base + mitre_weight + random.randint(5,15), 100)

# ------------------ OTX FETCH ------------------
def fetch_otx(limit=40):
    if not OTX_API_KEY:
        return []
    try:
        r = requests.get(
            OTX_URL,
            headers={"X-OTX-API-KEY": OTX_API_KEY},
            params={"limit": limit, "types":"IPv4,domain,url"},
            timeout=20
        )
        return r.json().get("results", [])
    except:
        return []

def insert_otx(items):
    conn = sqlite3.connect(DB)
    c = conn.cursor()

    for item in items:
        indicator = item.get("indicator")
        typ = item.get("type","").lower()

        if not indicator:
            continue
        if typ == "ipv4" and not is_valid_ipv4(indicator):
            continue
        if typ == "domain" and not is_valid_domain(indicator):
            continue
        if typ == "url" and not is_valid_url(indicator):
            continue

        try:
            c.execute("""
            INSERT INTO threats (pulse,indicator,type,classification,mitre,risk_score,created_at)
            VALUES (?,?,?,?,?,?,?)
            """,(
                "OTX Pulse",
                indicator,
                typ,
                "High",
                "T1071 C2",
                calculate_risk("High","T1071"),
                datetime.utcnow().isoformat()
            ))
        except:
            pass

    conn.commit()
    conn.close()

# ------------------ SEED ------------------
def seed_data():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    if c.execute("SELECT COUNT(*) FROM threats").fetchone()[0] > 0:
        conn.close()
        return
    for i in range(50):
        c.execute("""
        INSERT INTO threats (pulse,indicator,type,classification,mitre,risk_score,created_at)
        VALUES (?,?,?,?,?,?,?)
        """,(
            f"Campaign {i%5}",
            f"malicious{i}.com",
            "domain",
            "Medium",
            "T1566 Phishing",
            calculate_risk("Medium","T1566"),
            datetime.utcnow().isoformat()
        ))
    conn.commit()
    conn.close()

def ensure_database():
    init_db()
    seed_data()
    insert_otx(fetch_otx())

ensure_database()

# ------------------ ANALYTICS ------------------
def risk_index():
    conn = sqlite3.connect(DB)
    scores = [x[0] for x in conn.execute("SELECT risk_score FROM threats").fetchall()]
    conn.close()
    return int(sum(scores)/len(scores)) if scores else 0

def executive_summary():
    conn = sqlite3.connect(DB)
    total = conn.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
    high = conn.execute("SELECT COUNT(*) FROM threats WHERE risk_score>=70").fetchone()[0]
    conn.close()
    return f"{total} indicators detected. {high} high risk. National Index: {risk_index()}."

# ------------------ DASHBOARD ------------------
@app.route("/")
def dashboard():
    conn = sqlite3.connect(DB)
    rows = conn.execute("""
    SELECT pulse,indicator,type,classification,mitre,risk_score,created_at
    FROM threats ORDER BY risk_score DESC LIMIT 100
    """).fetchall()
    conn.close()

    return render_template_string(TEMPLATE,
        data=rows,
        total=len(rows),
        summary=executive_summary(),
        disclaimer=DISCLAIMER
    )

# ------------------ REPORT JSON ------------------
@app.route("/report/json")
def json_report():
    conn = sqlite3.connect(DB)
    rows = conn.execute("SELECT * FROM threats").fetchall()
    conn.close()
    return jsonify(rows)

# ------------------ RUN ------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)

# ------------------ TEMPLATE ------------------
TEMPLATE = """
<html>
<body style='background:#0a1f44;color:white;font-family:Arial'>
<h1 style='color:crimson;text-align:center;'>Threat Dashboard</h1>
<p style='text-align:center;'>{{ summary }}</p>
<table border=1 width=100%>
<tr><th>Pulse</th><th>Indicator</th><th>Type</th><th>Risk</th></tr>
{% for r in data %}
<tr><td>{{ r[0] }}</td><td>{{ r[1] }}</td><td>{{ r[2] }}</td><td>{{ r[5] }}</td></tr>
{% endfor %}
</table>
<p style='text-align:center;'>{{ disclaimer }}</p>
</body>
</html>
"""
