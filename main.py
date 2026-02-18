import os
import sqlite3
import random
from datetime import datetime, timedelta
from flask import Flask, jsonify, render_template_string, send_file
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import io, csv, base64
import folium
from folium.plugins import HeatMap
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import A4, landscape

app = Flask(__name__)

DB = "threats.db"
DISCLAIMER = "Information and analysis derived from publicly available sources by DarkGrid."

# ------------------ DATABASE ------------------
def init_db():
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
    conn.commit()
    conn.close()

def seed_data():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    if c.execute("SELECT COUNT(*) FROM threats").fetchone()[0] > 0:
        conn.close()
        return

    for i in range(80):
        classification = random.choice(["Low","Medium","High"])
        mitre = random.choice(["T1566 Phishing","T1071 C2","T1059 Execution"])
        risk = random.randint(40,95)
        c.execute("""
        INSERT INTO threats (pulse,indicator,type,classification,mitre,risk_score,created_at)
        VALUES (?,?,?,?,?,?,?)
        """,(
            f"Campaign {i%6}",
            f"malicious{i}.com",
            random.choice(["domain","IPv4","URL"]),
            classification,
            mitre,
            risk,
            datetime.utcnow().isoformat()
        ))
    conn.commit()
    conn.close()

def ensure_db():
    init_db()
    seed_data()

ensure_db()

# ------------------ RISK INDEX ------------------
def secure_nation_index():
    conn = sqlite3.connect(DB)
    scores = [x[0] for x in conn.execute("SELECT risk_score FROM threats").fetchall()]
    conn.close()
    return int(sum(scores)/len(scores)) if scores else 0

# ------------------ EXEC SUMMARY ------------------
def executive_summary():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    total = c.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
    high = c.execute("SELECT COUNT(*) FROM threats WHERE risk_score>=70").fetchone()[0]
    top_mitre = c.execute("""
        SELECT mitre, COUNT(*) FROM threats
        GROUP BY mitre ORDER BY COUNT(*) DESC LIMIT 1
    """).fetchone()
    conn.close()
    mitre_text = top_mitre[0] if top_mitre else "N/A"
    return (
        f"Redshark observed {total} active threat indicators this week. "
        f"{high} classified as High/Critical. "
        f"Dominant technique: {mitre_text}. "
        f"SecureNation Index: {secure_nation_index()}."
    )

# ------------------ HEAT MAP ------------------
def malaysia_heatmap():
    m = folium.Map(location=[4.2,101.97], zoom_start=6)
    heat_data = [
        [3.139,101.6869,5],
        [1.49,103.74,4],
        [5.41,100.33,3],
        [6.12,102.24,2],
        [2.19,102.25,3]
    ]
    HeatMap(heat_data).add_to(m)
    return m._repr_html_()

# ------------------ TREND CHART ------------------
def trend_chart():
    conn = sqlite3.connect(DB)
    data = conn.execute("""
        SELECT substr(created_at,1,10), COUNT(*)
        FROM threats GROUP BY substr(created_at,1,10)
    """).fetchall()
    conn.close()

    if not data:
        return ""

    dates = [d[0] for d in data]
    counts = [d[1] for d in data]

    plt.figure(figsize=(8,3))
    ax = plt.gca()
    ax.set_facecolor('black')

    if os.path.exists("boxing_ring.png"):
        bg = plt.imread("boxing_ring.png")
        ax.imshow(bg, extent=[0,len(dates)-1,0,max(counts)+5],
                  aspect='auto', alpha=0.15)

    plt.plot(dates, counts, color="crimson", marker="o")
    plt.xticks(rotation=45)
    plt.tight_layout()

    img = io.BytesIO()
    plt.savefig(img, format="png", transparent=True)
    plt.close()
    img.seek(0)
    return base64.b64encode(img.read()).decode()

# ------------------ DASHBOARD ------------------
@app.route("/")
def dashboard():
    conn = sqlite3.connect(DB)
    rows = conn.execute("""
        SELECT pulse,indicator,type,classification,mitre,risk_score,created_at
        FROM threats ORDER BY risk_score DESC
    """).fetchall()
    conn.close()

    return render_template_string(TEMPLATE,
        data=rows,
        total=len(rows),
        map_html=malaysia_heatmap(),
        trend=trend_chart(),
        disclaimer=DISCLAIMER,
        summary=executive_summary(),
        index=secure_nation_index()
    )

# ------------------ REPORTS ------------------
@app.route("/report/json")
def json_report():
    conn = sqlite3.connect(DB)
    rows = conn.execute("SELECT * FROM threats").fetchall()
    conn.close()
    return jsonify(rows)

@app.route("/report/csv")
def csv_report():
    conn = sqlite3.connect(DB)
    rows = conn.execute("SELECT * FROM threats").fetchall()
    conn.close()

    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(["ID","Pulse","Indicator","Type","Classification","MITRE","Risk","Created"])
    cw.writerows(rows)

    output = io.BytesIO()
    output.write(si.getvalue().encode())
    output.seek(0)
    return send_file(output, as_attachment=True, download_name="report.csv")

@app.route("/report/pdf")
def pdf_report():
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=landscape(A4))
    styles = getSampleStyleSheet()
    elements = [Paragraph("REDSHAK CYBER REPORT", styles["Title"]), Spacer(1,12)]

    conn = sqlite3.connect(DB)
    rows = conn.execute("SELECT * FROM threats").fetchall()
    conn.close()

    header = ["ID","Pulse","Indicator","Type","Classification","MITRE","Risk","Created"]
    table_data = [header] + [list(r) for r in rows[:20]]  # top 20
    table = Table(table_data)
    table.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,0),colors.black),
        ("TEXTCOLOR",(0,0),(-1,0),colors.white),
        ("GRID",(0,0),(-1,-1),0.5,colors.grey)
    ]))
    elements.append(table)
    doc.build(elements)
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name="report.pdf")

# ------------------ RUN ------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT",5000))
    app.run(host="0.0.0.0", port=port)

# ------------------ TEMPLATE ------------------
TEMPLATE = """
<html>
<body style='background:#0a1f44;color:white;font-family:Arial;margin:0 auto;max-width:1200px;'>

<h1 style='color:crimson;text-align:center;'>
REDSHAK CYBER THREATS INTELLIGENCE DASHBOARD
</h1>

<p style='text-align:center;font-size:18px;'>
SecureNation Index: <b>{{ index }}</b>
</p>

<p style='text-align:center;'>{{ summary }}</p>

<div style='text-align:center;'>{{ map_html|safe }}</div>

<div style='text-align:center;'>
<img src="data:image/png;base64,{{ trend }}">
</div>

<h3 style='text-align:center;'>Total Indicators: {{ total }}</h3>

<table border=1 width=100% style='border-collapse:collapse;text-align:center;'>
<tr style='background:#001f3f;color:white;'>
<th>Pulse</th>
<th>Indicator</th>
<th>Type</th>
<th>Classification</th>
<th>MITRE</th>
<th>Risk Score</th>
<th>Created</th>
</tr>
{% for r in data %}
<tr style='background:#1a2d5a;color:white;'>
<td>{{ r[0] }}</td>
<td>{{ r[1] }}</td>
<td>{{ r[2] }}</td>
<td>{{ r[3] }}</td>
<td>{{ r[4] }}</td>
<td>{{ r[5] }}</td>
<td>{{ r[6] }}</td>
</tr>
{% endfor %}
</table>

<p style='text-align:center;'>{{ disclaimer }}</p>

<p style='text-align:center;'>
<a href='/report/pdf'>PDF</a> |
<a href='/report/csv'>CSV</a> |
<a href='/report/json'>JSON</a>
</p>

</body>
</html>
"""
