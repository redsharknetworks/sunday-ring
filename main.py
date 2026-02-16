import os
import sqlite3
import requests
import io
import csv
from datetime import datetime, timedelta
from flask import Flask, jsonify, request, render_template_string, send_file, abort

from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.pagesizes import landscape, A4

# =====================================================
# CONFIG
# =====================================================
app = Flask(__name__)

DB_FILE = "cti_platform.db"
OTX_API_KEY = os.environ.get("OTX_API_KEY")
ADMIN_KEY = os.environ.get("ADMIN_KEY", "change_this")

# =====================================================
# DATABASE
# =====================================================
def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()

    # Multi-tenant clients
    c.execute("""
    CREATE TABLE IF NOT EXISTS clients (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE,
        api_key TEXT UNIQUE
    )
    """)

    # Threat intel table
    c.execute("""
    CREATE TABLE IF NOT EXISTS threats (
        id TEXT PRIMARY KEY,
        client TEXT,
        pulse_name TEXT,
        threat_actor TEXT,
        indicator TEXT,
        indicator_type TEXT,
        latitude REAL,
        longitude REAL,
        mitre_tactic TEXT,
        classification TEXT,
        created TEXT
    )
    """)

    # SOC analyst notes
    c.execute("""
    CREATE TABLE IF NOT EXISTS notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        threat_id TEXT,
        analyst TEXT,
        note TEXT,
        created TEXT
    )
    """)

    conn.commit()
    conn.close()

init_db()

# =====================================================
# INTELLIGENCE LOGIC
# =====================================================
def mitre_tag(indicator_type):
    mapping = {
        "domain": "Command and Control",
        "IPv4": "Initial Access",
        "URL": "Execution",
        "FileHash-SHA256": "Defense Evasion"
    }
    return mapping.get(indicator_type, "Reconnaissance")

def classify_indicator(indicator):
    indicator = indicator.lower()
    if ".my" in indicator:
        return "TARGET_MY"
    if indicator.startswith(("103.","175.","60.")):
        return "SOURCE_MY"
    return "SOURCE_OTHER"

def get_geo(ip):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        if r.status_code == 200:
            data = r.json()
            return data.get("lat"), data.get("lon")
    except:
        pass
    return None, None

def calculate_risk(rows):
    weights = {"TARGET_MY":4,"SOURCE_MY":3,"SOURCE_OTHER":1}
    score = sum(weights.get(r["classification"],0) for r in rows)
    if score>100: level="CRITICAL"
    elif score>50: level="HIGH"
    elif score>20: level="MODERATE"
    else: level="LOW"
    return score, level

def cleanup_old():
    cutoff=(datetime.utcnow()-timedelta(days=30)).isoformat()
    conn=get_db()
    conn.execute("DELETE FROM threats WHERE created < ?",(cutoff,))
    conn.commit()
    conn.close()

# =====================================================
# ADMIN INGEST
# =====================================================
@app.route("/admin/update")
def ingest():
    if request.args.get("key")!=ADMIN_KEY:
        abort(403)

    headers={"X-OTX-API-KEY":OTX_API_KEY}
    r=requests.get("https://otx.alienvault.com/api/v1/pulses/subscribed",headers=headers,timeout=15)
    if r.status_code!=200:
        return jsonify({"error":"OTX fetch failed"}),500

    pulses=r.json().get("results",[])
    conn=get_db()
    c=conn.cursor()
    inserted=0

    for pulse in pulses:
        actor=pulse.get("author_name","Unknown")
        created=pulse.get("created")

        for ind in pulse.get("indicators",[]):
            indicator=ind.get("indicator")
            ind_type=ind.get("type")
            tactic=mitre_tag(ind_type)
            classification=classify_indicator(indicator)
            lat,lon=(None,None)
            if ind_type=="IPv4":
                lat,lon=get_geo(indicator)
            threat_id=pulse.get("id")+indicator
            c.execute("""
            INSERT OR IGNORE INTO threats
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
            """,(
                threat_id,"default",
                pulse.get("name"),actor,
                indicator,ind_type,
                lat,lon,tactic,
                classification,created
            ))
            inserted+=1

    conn.commit()
    conn.close()
    cleanup_old()

    return jsonify({"status":"updated","inserted":inserted})

# =====================================================
# CLIENT PORTAL
# =====================================================
@app.route("/portal")
def portal():
    api_key=request.args.get("api_key")
    conn=get_db()
    client=conn.execute("SELECT * FROM clients WHERE api_key=?",(api_key,)).fetchone()
    if not client:
        return "Unauthorized"

    rows=conn.execute("SELECT * FROM threats ORDER BY created DESC LIMIT 200").fetchall()
    rows=[dict(r) for r in rows]
    conn.close()

    score,level=calculate_risk(rows)

    return render_template_string(PORTAL_TEMPLATE,rows=rows,score=score,level=level)

# =====================================================
# EXPORT CSV
# =====================================================
@app.route("/export/csv")
def export_csv():
    conn=get_db()
    rows=conn.execute("SELECT * FROM threats ORDER BY created DESC").fetchall()
    conn.close()

    output=io.StringIO()
    writer=csv.writer(output)
    if rows:
        writer.writerow(rows[0].keys())
        for r in rows:
            writer.writerow(r)
    return send_file(
        io.BytesIO(output.getvalue().encode()),
        mimetype="text/csv",
        as_attachment=True,
        download_name="malaysia_threats.csv"
    )

# =====================================================
# EXPORT JSON
# =====================================================
@app.route("/export/json")
def export_json():
    conn=get_db()
    rows=[dict(r) for r in conn.execute("SELECT * FROM threats ORDER BY created DESC").fetchall()]
    conn.close()
    return jsonify(rows)

# =====================================================
# EXPORT PDF
# =====================================================
@app.route("/export/pdf")
def export_pdf():
    conn=get_db()
    rows=[dict(r) for r in conn.execute("SELECT * FROM threats ORDER BY created DESC").fetchall()]
    conn.close()

    score,level=calculate_risk(rows)

    buffer=io.BytesIO()
    doc=SimpleDocTemplate(buffer,pagesize=landscape(A4),
                          leftMargin=40,rightMargin=40)
    elements=[]
    styles=getSampleStyleSheet()
    wrap_style=ParagraphStyle("wrap",fontSize=8,leading=10)
    elements.append(Paragraph("<b>Malaysia Weekly Threat Intelligence Report</b>",styles["Title"]))
    elements.append(Spacer(1,10))
    elements.append(Paragraph(f"Risk Index: {score} ({level})",styles["Normal"]))
    elements.append(Spacer(1,10))

    data=[["Actor","Indicator","Type","MITRE","Class","Date"]]
    for r in rows:
        data.append([
            Paragraph(r["threat_actor"],wrap_style),
            Paragraph(r["indicator"],wrap_style),
            r["indicator_type"],
            r["mitre_tactic"],
            r["classification"],
            r["created"]
        ])

    table=Table(data,repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,0),colors.darkblue),
        ("TEXTCOLOR",(0,0),(-1,0),colors.white),
        ("GRID",(0,0),(-1,-1),0.5,colors.grey)
    ]))
    elements.append(table)
    elements.append(Spacer(1,10))
    elements.append(Paragraph("Disclaimer: Developed and analyzed from public sources by darkgrid@redshark.my",styles["Normal"]))

    doc.build(elements)
    buffer.seek(0)
    return send_file(buffer,mimetype="application/pdf",
                     as_attachment=True,
                     download_name="malaysia_threat_report.pdf")

# =====================================================
# NOTES SYSTEM
# =====================================================
@app.route("/notes/add",methods=["POST"])
def add_note():
    data=request.json
    conn=get_db()
    conn.execute("""
    INSERT INTO notes (threat_id,analyst,note,created)
    VALUES (?,?,?,?)
    """,(data["threat_id"],data["analyst"],data["note"],datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()
    return jsonify({"status":"note added"})

@app.route("/notes/<threat_id>")
def get_notes(threat_id):
    conn=get_db()
    rows=conn.execute("SELECT * FROM notes WHERE threat_id=? ORDER BY created DESC",(threat_id,)).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

# =====================================================
# PORTAL TEMPLATE
# =====================================================
PORTAL_TEMPLATE="""
<!DOCTYPE html>
<html>
<head>
<link rel="stylesheet" href="https://unpkg.com/leaflet/dist/leaflet.css"/>
<script src="https://unpkg.com/leaflet/dist/leaflet.js"></script>
<style>
body{background:#0b0f1a;color:#e0e0e0;font-family:Arial;}
h1{color:orange;}
table{width:100%;border-collapse:collapse;margin-top:10px;}
th{background:#001f4d;color:white;cursor:pointer;}
td,th{padding:6px;border:1px solid #333;}
tr:nth-child(even){background:#001a33;}
#map{height:400px;margin-bottom:20px;}
a{color:orange;margin-right:10px;}
</style>
</head>
<body>
<h1>Malaysia CTI Portal</h1>
<h2>Risk Index: {{score}} ({{level}})</h2>

<a href="/export/pdf">Download PDF</a>
<a href="/export/csv">CSV</a>
<a href="/export/json">JSON</a>

<div id="map"></div>
<script>
var map=L.map('map').setView([4.2105,101.9758],6);
L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png').addTo(map);
var threats={{rows|tojson}};
threats.forEach(function(t){
 if(t.latitude && t.longitude){
   L.marker([t.latitude,t.longitude]).addTo(map)
   .bindPopup(t.indicator + "<br>" + t.mitre_tactic);
 }
});
</script>

<table>
<tr><th>Actor</th><th>Indicator</th><th>Type</th><th>MITRE</th><th>Class</th></tr>
{% for r in rows %}
<tr>
<td>{{r.threat_actor}}</td>
<td>{{r.indicator}}</td>
<td>{{r.indicator_type}}</td>
<td>{{r.mitre_tactic}}</td>
<td>{{r.classification}}</td>
</tr>
{% endfor %}
</table>

<p>Total Showing: {{rows|length}}</p>
<p style="font-size:0.8em;color:#aaa;">Disclaimer: Developed and analyzed from public sources by darkgrid@redshark.my</p>

</body>
</html>
"""

# =====================================================
# START
# =====================================================
if __name__=="__main__":
    port=int(os.environ.get("PORT",10000))
    app.run(host="0.0.0.0",port=port)
