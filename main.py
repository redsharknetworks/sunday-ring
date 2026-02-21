import os
import io
import csv
import base64
import sqlite3
import threading
import time
import random
from datetime import datetime, timedelta

import requests
from flask import Flask, render_template_string, send_file

from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer,
    Image, Table, TableStyle, PageBreak
)
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from reportlab.lib.units import inch

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

import folium
from folium.plugins import HeatMap


# ---------------- CONFIG ----------------
app = Flask(__name__)
DB = os.getenv("DB_PATH", "/tmp/threats.db")
OTX_KEY = os.getenv("OTX_KEY")
OTX_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"
BOXING_RING = "boxing_ring.png"
RETENTION_DAYS = 60


# ---------------- DATABASE ----------------
def ensure_database():
    conn = sqlite3.connect(DB)
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS threats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pulse TEXT,
        indicator TEXT,
        type TEXT,
        classification TEXT,
        mitre TEXT,
        risk_score INTEGER,
        created_at TEXT
    )
    """)

    c.execute("""
    CREATE INDEX IF NOT EXISTS idx_created_at
    ON threats(created_at)
    """)

    conn.commit()
    conn.close()


def apply_retention_policy():
    cutoff = (datetime.utcnow() - timedelta(days=RETENTION_DAYS)).isoformat()

    conn = sqlite3.connect(DB)
    c = conn.cursor()

    c.execute("DELETE FROM threats WHERE created_at < ?", (cutoff,))
    deleted = c.rowcount

    conn.commit()
    conn.execute("VACUUM")
    conn.close()

    if deleted:
        print(f"[Retention] Deleted {deleted} records older than {RETENTION_DAYS} days.")


# ---------------- DUMMY DATA ----------------
def insert_dummy_data():
    conn = sqlite3.connect(DB)
    c = conn.cursor()

    for i in range(20):
        c.execute("""
        INSERT INTO threats
        (pulse, indicator, type, classification, mitre, risk_score, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            f"Dummy Pulse {i+1}",
            f"malicious{i+1}.com",
            "domain",
            "Medium",
            "OTX",
            random.randint(60, 95),
            datetime.utcnow().isoformat()
        ))

    conn.commit()
    conn.close()


# ---------------- OTX FETCH ----------------
def fetch_otx_data():
    ensure_database()

    if not OTX_KEY:
        insert_dummy_data()
        apply_retention_policy()
        return

    headers = {"X-OTX-API-KEY": OTX_KEY}

    try:
        r = requests.get(OTX_URL, headers=headers, timeout=15)
        r.raise_for_status()
        pulses = r.json().get("results", [])
    except Exception:
        insert_dummy_data()
        apply_retention_policy()
        return

    conn = sqlite3.connect(DB)
    c = conn.cursor()

    for pulse in pulses[:10]:
        name = pulse.get("name", "OTX Pulse")
        indicators = pulse.get("indicators", [])

        for ind in indicators:
            val = ind.get("indicator")
            if not val:
                continue

            c.execute("""
            INSERT INTO threats
            (pulse, indicator, type, classification, mitre, risk_score, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                name,
                val,
                ind.get("type", "domain"),
                "Medium",
                "OTX",
                random.randint(60, 95),
                datetime.utcnow().isoformat()
            ))

    conn.commit()
    conn.close()

    apply_retention_policy()


# ---------------- SCHEDULER ----------------
def scheduler():
    while True:
        fetch_otx_data()
        apply_retention_policy()
        time.sleep(3600)


# ---------------- CHARTS ----------------
def generate_charts():
    ensure_database()
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    trend = c.execute("""
    SELECT substr(created_at,1,10) as date, COUNT(*) as cnt
    FROM threats GROUP BY date ORDER BY date
    """).fetchall()

    types = c.execute("""
    SELECT type, COUNT(*) as cnt
    FROM threats GROUP BY type
    """).fetchall()

    conn.close()

    trend_img = None
    type_img = None

    # -------- Trend Chart --------
    if trend:
        dates = [x["date"] for x in trend]
        counts = [x["cnt"] for x in trend]

        plt.figure(figsize=(6,3))
        ax = plt.gca()
        ax.set_facecolor("#0d1b2a")

        plt.plot(dates, counts, marker="o", color="#d90429")
        plt.title("Threat Trend", color="crimson", fontweight="bold")

        plt.xticks(rotation=45, color="white")
        plt.yticks(color="white")
        plt.tight_layout()

        buf = io.BytesIO()
        plt.savefig(buf, format="png", facecolor="#0d1b2a")
        plt.close()

        trend_img = base64.b64encode(buf.getvalue()).decode()

    # -------- Indicator Type Chart --------
    if types:
        labels = [x["type"] for x in types]
        values = [x["cnt"] for x in types]

        plt.figure(figsize=(6,4))
        ax = plt.gca()
        ax.set_facecolor("#0d1b2a")

        plt.bar(labels, values, color="#ff7f50")
        plt.title("Indicator Types", color="crimson", fontweight="bold")

        plt.xticks(rotation=30, color="white")
        plt.yticks(color="white")
        plt.tight_layout()

        buf = io.BytesIO()
        plt.savefig(buf, format="png", facecolor="#0d1b2a")
        plt.close()

        type_img = base64.b64encode(buf.getvalue()).decode()

    return trend_img, type_img


# ---------------- MALAYSIA HEATMAP ----------------
MALAYSIA_STATES = {
    "Johor": [1.4927,103.7414],
    "Kedah": [6.1164,100.3678],
    "Kelantan": [6.1254,102.2381],
    "Melaka": [2.1896,102.2501],
    "Negeri Sembilan": [2.7290,101.9383],
    "Pahang": [3.8167,103.3333],
    "Perak": [4.5929,101.0900],
    "Perlis": [6.4400,100.2000],
    "Penang": [5.4164,100.3327],
    "Sabah": [5.9804,116.0735],
    "Sarawak": [1.5533,110.3592],
    "Selangor": [3.1390,101.6869],
    "Terengganu": [5.3300,103.1400],
    "Kuala Lumpur": [3.1390,101.6869],
    "Putrajaya": [2.9264,101.6981],
    "Labuan": [5.2833,115.2333]
}


def generate_malaysia_heatmap():
    tz = timedelta(hours=8)
    timestamp = (datetime.utcnow() + tz).strftime("%Y-%m-%d %H:%M:%S GMT+8")

    m = folium.Map(location=[4.2105,101.9758], zoom_start=6,
                   tiles="CartoDB dark_matter")

    folium.Marker([5.4164,100.3327],
                  popup=f"Last update: {timestamp}").add_to(m)

    heat_data = []
    for coords in MALAYSIA_STATES.values():
        heat_data.append([coords[0], coords[1], random.randint(1,10)])

    HeatMap(heat_data, radius=25).add_to(m)

    return m._repr_html_(), timestamp


# ---------------- SECURE INDEX ----------------
def calculate_secure_index():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT AVG(risk_score) FROM threats")
    avg = c.fetchone()[0] or 0
    conn.close()
    return round(avg,1)


# ---------------- PDF FOOTER ----------------
def add_page_number(canvas, doc):
    canvas.saveState()
    canvas.setStrokeColor(colors.grey)
    canvas.line(doc.leftMargin, 30,
                letter[0] - doc.rightMargin, 30)

    canvas.setFont("Helvetica", 9)
    canvas.setFillColor(colors.grey)
    canvas.drawRightString(
        letter[0] - doc.rightMargin,
        20,
        f"RedShark Threat Intelligence Report | Page {doc.page}"
    )
    canvas.restoreState()


# ---------------- PDF REPORT ----------------
@app.route("/report/pdf")
def pdf_report():
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    buffer = io.BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=60,
        rightMargin=60,
        topMargin=70,
        bottomMargin=60
    )

    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph(
        "RedShark Threat Intelligence Report",
        styles["Title"]
    ))
    elements.append(Spacer(1,12))

    elements.append(Paragraph(
        f"SecureNation Index: {calculate_secure_index()}/100",
        styles["Normal"]
    ))

    elements.append(PageBreak())

    trend, type_chart = generate_charts()
    usable_width = letter[0] - doc.leftMargin - doc.rightMargin

    if trend:
        img = io.BytesIO(base64.b64decode(trend))
        elements.append(Image(img, width=usable_width, height=220))
        elements.append(Spacer(1,15))

    if type_chart:
        img2 = io.BytesIO(base64.b64decode(type_chart))
        elements.append(Image(img2, width=usable_width, height=250))
        elements.append(PageBreak())

    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    rows = c.execute("""
        SELECT * FROM threats
        ORDER BY risk_score DESC
        LIMIT 20
    """).fetchall()

    conn.close()

    small_style = styles["Normal"]
    table_data = [["ID","Pulse","Indicator","Type",
                   "Class","MITRE","Risk","Created"]]

    for r in rows:
        table_data.append([
            r["id"],
            Paragraph(str(r["pulse"]), small_style),
            Paragraph(str(r["indicator"]), small_style),
            r["type"],
            r["classification"],
            r["mitre"],
            r["risk_score"],
            r["created_at"]
        ])

    col_widths = [40,100,110,60,60,60,40,90]

    table = Table(table_data,
                  colWidths=col_widths,
                  repeatRows=1)

    table.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,0),colors.HexColor("#4B6C8A")),
        ('TEXTCOLOR',(0,0),(-1,0),colors.white),
        ('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'),
        ('FONTSIZE',(0,0),(-1,-1),8),
        ('GRID',(0,0),(-1,-1),0.25,colors.grey),
        ('VALIGN',(0,0),(-1,-1),'TOP'),
        ('LEFTPADDING',(0,0),(-1,-1),6),
        ('RIGHTPADDING',(0,0),(-1,-1),6),
    ]))

    elements.append(table)

    doc.build(elements,
              onFirstPage=add_page_number,
              onLaterPages=add_page_number)

    buffer.seek(0)

    return send_file(buffer,
                     as_attachment=True,
                     download_name=f"RedShark_report_{timestamp}.pdf",
                     mimetype="application/pdf")


# ---------------- START ----------------
ensure_database()
fetch_otx_data()

if not os.getenv("RUN_MAIN"):
    threading.Thread(target=scheduler, daemon=True).start()

if __name__ == "__main__":
    app.run(host="0.0.0.0",
            port=int(os.getenv("PORT",5000)))
