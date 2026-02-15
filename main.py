import os
import sqlite3
import requests
from flask import Flask, jsonify, request, render_template_string

# --------------------------
# Flask App
# --------------------------
app = Flask(__name__)

# --------------------------
# Environment / Config
# --------------------------
OTX_API_KEY = os.environ.get("OTX_API_KEY")
if not OTX_API_KEY:
    raise RuntimeError("OTX_API_KEY environment variable is required!")

ADMIN_KEY = os.environ.get("ADMIN_KEY", "M@ttdemon2026")
DATABASE_FILE = "threat_intel.db"

# --------------------------
# Malaysia Targeting Rules
# --------------------------
MALAYSIA_KEYWORDS = [
    "malaysia", "maybank", "cimb", "bank negara",
    "petronas", ".my", "gov.my", "edu.my"
]

THREAT_SCORES = {
    "keyword": 3,
    "my_domain": 4
}

# --------------------------
# Database Setup
# --------------------------
def init_db():
    conn = sqlite3.connect(DATABASE_FILE)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS malaysia_targeted_threats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator TEXT UNIQUE,
            indicator_type TEXT,
            pulse_name TEXT,
            pulse_description TEXT,
            pulse_author TEXT,
            pulse_created TEXT,
            threat_score INTEGER
        )
    """)
    conn.commit()
    conn.close()

init_db()

def get_db_connection():
    conn = sqlite3.connect(DATABASE_FILE)
    conn.row_factory = sqlite3.Row
    return conn

# --------------------------
# Fetch Pulses from OTX
# --------------------------
def fetch_otx_pulses(limit=100):
    headers = {"X-OTX-API-KEY": OTX_API_KEY, "Accept": "application/json"}
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
    params = {"limit": limit}

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()
        pulses = data.get("results", [])
        print(f"Fetched {len(pulses)} pulses from OTX")
        return pulses
    except requests.HTTPError as e:
        print(f"OTX Fetch Error: {e} | Status: {getattr(e.response, 'status_code', None)}")
        if hasattr(e.response, "text"):
            print("Response Text:", e.response.text[:200])
        return []
    except Exception as e:
        print("OTX Fetch Error:", e)
        return []

# --------------------------
# Compute Malaysia Score
# --------------------------
def compute_malaysia_score(pulse):
    score = 0
    text = (pulse.get("name", "") + " " + pulse.get("description", "")).lower()

    # Keyword matches
    for kw in MALAYSIA_KEYWORDS:
        if kw in text:
            score += THREAT_SCORES["keyword"]

    # Indicators ending with .my
    indicators = pulse.get("indicators") or []
    for ind in indicators:
        if ind.get("type") == "domain" and ind.get("indicator", "").endswith(".my"):
            score += THREAT_SCORES["my_domain"]

    return score

# --------------------------
# Save Threats to DB
# --------------------------
def save_threats(pulses):
    conn = get_db_connection()
    cursor = conn.cursor()

    for pulse in pulses:
        score = compute_malaysia_score(pulse)
        if score < 3:
            continue  # ignore low-score pulses

        indicators = pulse.get("indicators") or []
        for ind in indicators:
            cursor.execute("""
                INSERT OR IGNORE INTO malaysia_targeted_threats
                (indicator, indicator_type, pulse_name, pulse_description, pulse_author, pulse_created, threat_score)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                ind.get("indicator"),
                ind.get("type"),
                pulse.get("name"),
                pulse.get("description"),
                pulse.get("author"),
                pulse.get("created"),
                score
            ))

    conn.commit()
    conn.close()
    print("Threats saved to database.")

# --------------------------
# Update Endpoint
# --------------------------
@app.route("/update")
def update_threats():
    key = request.args.get("key")
    if key != ADMIN_KEY:
        return {"error": "Unauthorized"}, 403

    pulses = fetch_otx_pulses(limit=200)
    save_threats(pulses)
    return {"status": "updated", "total_pulses_fetched": len(pulses)}

# --------------------------
# Dashboard API
# --------------------------
@app.route("/api/dashboard")
def dashboard_api():
    conn = get_db_connection()
    rows = conn.execute("""
        SELECT * FROM malaysia_targeted_threats
        ORDER BY threat_score DESC, pulse_created DESC
        LIMIT 50
    """).fetchall()
    conn.close()
    return jsonify([dict(row) for row in rows])

# --------------------------
# Dashboard HTML
# --------------------------
@app.route("/")
def dashboard_html():
    conn = get_db_connection()
    rows = conn.execute("""
        SELECT * FROM malaysia_targeted_threats
        ORDER BY threat_score DESC, pulse_created DESC
        LIMIT 20
    """).fetchall()
    conn.close()

    html = """
    <html>
    <head>
        <title>Malaysia Threat Intel Dashboard</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #111; color: #eee; }
            table { border-collapse: collapse; width: 100%; margin-top: 20px; }
            th, td { border: 1px solid #555; padding: 8px; text-align: left; }
            th { background-color: #222; }
            tr:nth-child(even) { background-color: #1a1a1a; }
            .header { display: flex; align-items: center; gap: 15px; }
            img.logo { height: 60px; }
            .email { margin-top: 5px; font-size: 0.9em; color: #aaa; }
        </style>
    </head>
    <body>
        <div class="header">
            <img src="https://raw.githubusercontent.com/redsharknetworks/sunday-ring/main/redshark.png" class="logo" />
            <h1>Malaysia Threat Intel Dashboard</h1>
        </div>
        <div class="email">Contact: darkgrid@redshark.my</div>

        <table>
            <tr>
                <th>Indicator</th>
                <th>Type</th>
                <th>Pulse Name</th>
                <th>Threat Score</th>
            </tr>
            {% for row in rows %}
            <tr>
                <td>{{row['indicator']}}</td>
                <td>{{row['indicator_type']}}</td>
                <td>{{row['pulse_name']}}</td>
                <td>{{row['threat_score']}}</td>
            </tr>
            {% endfor %}
        </table>
        <p>Total Showing: {{rows|length}}</p>
    </body>
    </html>
    """
    return render_template_string(html, rows=rows)

# --------------------------
# Run App
# --------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
