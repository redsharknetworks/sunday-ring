import os, sqlite3, random, io, base64, csv, json
from datetime import datetime, timedelta
from flask import Flask, request, render_template_string, Response
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

app = Flask(__name__)
DB = "threats.db"
PAGE_SIZE = 50
DISCLAIMER = "Information and analysis developed from publicly available sources by DarkGrid (darkgrid@redshark.my)."

# ---------------- DB INIT ----------------
def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS threats(
        id INTEGER PRIMARY KEY,
        pulse TEXT,
        indicator TEXT,
        type TEXT,
        classification TEXT,
        mitre TEXT,
        risk_score INTEGER,
        created_at TEXT
    )""")

    c.execute("""
    CREATE TABLE IF NOT EXISTS hashes(
        id INTEGER PRIMARY KEY,
        pulse TEXT,
        hash TEXT,
        classification TEXT,
        mitre TEXT,
        risk_score INTEGER,
        created_at TEXT
    )""")

    conn.commit()
    conn.close()

# ---------------- SEED ----------------
def seed():
    conn = sqlite3.connect(DB)
    c = conn.cursor()

    if c.execute("SELECT COUNT(*) FROM threats").fetchone()[0] == 0:
        for i in range(120):
            t = random.choice(["IPv4","domain","URL"])
            c.execute("""
            INSERT INTO threats VALUES(NULL,?,?,?,?,?,?,?)
            """,(
                f"Pulse {i}",
                f"indicator{i}.com",
                t,
                "Malware",
                "T1059",
                random.randint(10,100),
                (datetime.now()-timedelta(days=random.randint(0,7))).isoformat()
            ))

    if c.execute("SELECT COUNT(*) FROM hashes").fetchone()[0] == 0:
        for i in range(40):
            c.execute("""
            INSERT INTO hashes VALUES(NULL,?,?,?,?,?,?)
            """,(
                f"Pulse H{i}",
                hex(random.getrandbits(128)),
                "File",
                "T1204",
                random.randint(10,100),
                datetime.now().isoformat()
            ))

    conn.commit()
    conn.close()

# ---------------- BOXING BG ----------------
def boxing_bg(ax, max_y, count):
    try:
        img = plt.imread("boxing_ring.png")
        ax.imshow(img, extent=[-1,count,0,max_y*1.2], alpha=0.25, aspect="auto")
    except:
        pass

# ---------------- TREND CHART ----------------
def trend_chart():
    conn = sqlite3.connect(DB)
    rows = conn.execute("""
        SELECT substr(created_at,1,10), COUNT(*)
        FROM threats GROUP BY 1
    """).fetchall()
    conn.close()

    dates=[r[0] for r in rows]
    counts=[r[1] for r in rows]

    fig, ax = plt.subplots(figsize=(8,3))
    ax.set_facecolor("#2b2b2b")
    fig.patch.set_facecolor("#2b2b2b")

    if counts:
        boxing_bg(ax, max(counts)+5, len(dates))
        ax.plot(dates, counts, color="crimson", marker="o", linewidth=2)
        ax.fill_between(dates, counts, color="crimson", alpha=0.15)

    ax.set_title("Total Indicators Trend", color="white")
    ax.tick_params(colors="white")

    img=io.BytesIO()
    plt.savefig(img, format="png", bbox_inches="tight")
    img.seek(0)
    plt.close()
    return base64.b64encode(img.read()).decode()

# ---------------- TYPE CHART (NO BOXING BG) ----------------
def type_chart():
    conn=sqlite3.connect(DB)
    rows=conn.execute("SELECT type, COUNT(*) FROM threats GROUP BY type").fetchall()
    conn.close()

    labels=[r[0] for r in rows]
    counts=[r[1] for r in rows]

    fig, ax = plt.subplots(figsize=(8,3))
    ax.set_facecolor("#2b2b2b")
    fig.patch.set_facecolor("#2b2b2b")

    if counts:
        ax.bar(labels, counts, color="orange", alpha=0.9)

    ax.set_title("Indicator Types", color="white")
    ax.tick_params(colors="white")

    img=io.BytesIO()
    plt.savefig(img, format="png", bbox_inches="tight")
    img.seek(0)
    plt.close()
    return base64.b64encode(img.read()).decode()

# ---------------- DASHBOARD ----------------
@app.route("/")
def dashboard():
    page=int(request.args.get("page",1))
    sort=request.args.get("sort","risk_score")
    offset=(page-1)*PAGE_SIZE

    conn=sqlite3.connect(DB)
    conn.row_factory=sqlite3.Row
    rows=conn.execute(f"""
        SELECT * FROM threats
        ORDER BY {sort} DESC
        LIMIT ? OFFSET ?
    """,(PAGE_SIZE,offset)).fetchall()
    conn.close()

    return render_template_string("""
    <body style="background:#0a1f44;color:white;font-family:Arial;">
    <h2 style="text-align:center;">RedShark Cyber Threat Intelligent Dashboard</h2>

    <div style="text-align:center;">
        <img src="data:image/png;base64,{{trend}}"/><br>
        <img src="data:image/png;base64,{{type}}"/>
    </div>

    <table border=1 align=center width="80%">
    <tr>
        <th>Pulse</th><th>Indicator</th><th>Type</th><th>Risk</th>
    </tr>
    {% for r in rows %}
    <tr>
        <td>{{r.pulse}}</td>
        <td>{{r.indicator}}</td>
        <td>{{r.type}}</td>
        <td>{{r.risk_score}}</td>
    </tr>
    {% endfor %}
    </table>

    <p style="text-align:center;margin-top:20px;">{{disc}}</p>
    </body>
    """, rows=rows, trend=trend_chart(), type=type_chart(), disc=DISCLAIMER)

# ---------------- CSV ----------------
@app.route("/report/csv")
def csv_report():
    conn=sqlite3.connect(DB)
    conn.row_factory=sqlite3.Row
    rows=conn.execute("SELECT * FROM threats").fetchall()
    conn.close()

    output=io.StringIO()
    writer=csv.writer(output)
    writer.writerow(rows[0].keys())
    for r in rows:
        writer.writerow(list(r))

    return Response(output.getvalue(),mimetype="text/csv",
        headers={"Content-Disposition":"attachment; filename=darkgridatredsharkdotmy.csv"})

# ---------------- JSON ----------------
@app.route("/report/json")
def json_report():
    conn=sqlite3.connect(DB)
    conn.row_factory=sqlite3.Row
    rows=conn.execute("SELECT * FROM threats").fetchall()
    conn.close()

    return Response(json.dumps([dict(r) for r in rows],indent=2),
        mimetype="application/json",
        headers={"Content-Disposition":"attachment; filename=darkgridatredsharkdotmy.json"})

# ---------------- PDF ----------------
@app.route("/report/pdf")
def pdf_report():
    buf=io.BytesIO()
    c=canvas.Canvas(buf,pagesize=letter)
    c.drawString(50,750,"Weekly Top 10 Threats")

    conn=sqlite3.connect(DB)
    rows=conn.execute("""
        SELECT indicator,risk_score FROM threats
        ORDER BY risk_score DESC LIMIT 10
    """).fetchall()
    conn.close()

    y=720
    for r in rows:
        c.drawString(50,y,f"{r[0]} - {r[1]}")
        y-=20

    c.drawString(50,50,DISCLAIMER)
    c.save()
    buf.seek(0)

    return Response(buf,mimetype="application/pdf",
        headers={"Content-Disposition":"attachment; filename=darkgridatredsharkdotmy.pdf"})

# ---------------- MAIN ----------------
if __name__ == "__main__":
    init_db()
    seed()
    app.run(host="0.0.0.0", port=5000)
