import os
import sqlite3
import requests
from flask import Flask, render_template_string, request, jsonify
import geoip2.database

app = Flask(__name__)

# --- Environment Variables ---
OTX_API_KEY = os.environ.get("OTX_API_KEY")
DATABASE_FILE = "threat_intel.db"
GEOIP_DB = "GeoLite2-City.mmdb"

# --- Database Helper ---
def get_db_connection():
    conn = sqlite3.connect(DATABASE_FILE)
    conn.row_factory = sqlite3.Row
    return conn

# --- Initialize Database ---
def init_db():
    conn = get_db_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ip_indicators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT UNIQUE,
            city TEXT,
            country TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

# --- Fetch OTX Indicators ---
def fetch_otx_ips():
    if not OTX_API_KEY:
        return []

    headers = {
        "X-OTX-API-KEY": OTX_API_KEY,
        "Accept": "application/json"
    }

    url = "https://otx.alienvault.com/api/v1/pulses/indicators"
    params = {"limit": 100}

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()
        return [
            d["indicator"]
            for d in data.get("results", [])
            if d.get("type") == "IPv4"
        ]
    except Exception:
        return []

# --- Filter Malaysian IPs ---
def filter_malaysia(ips):
    if not os.path.exists(GEOIP_DB):
        return []

    reader = geoip2.database.Reader(GEOIP_DB)
    mal_ips = []

    for ip in ips:
        try:
            rec = reader.city(ip)
            if rec.country.iso_code == "MY":
                mal_ips.append(
                    (ip, rec.city.name or "-", rec.country.name)
                )
        except Exception:
            continue

    reader.close()
    return mal_ips

# --- Save to DB ---
def save_ips(ip_list):
    conn = get_db_connection()
    for ip, city, country in ip_list:
        conn.execute(
            "INSERT OR IGNORE INTO ip_indicators (ip, city, country) VALUES (?, ?, ?)",
            (ip, city, country)
        )
    conn.commit()
    conn.close()

# --- Dashboard ---
@app.route("/")
def dashboard():
    conn = get_db_connection()
    rows = conn.execute(
        "SELECT ip, city, country FROM ip_indicators ORDER BY id DESC LIMIT 10"
    ).fetchall()
    conn.close()

    html = """
    <h1>Malaysia Threat Intel Dashboard</h1>
    <table border="1" cellpadding="5">
      <tr><th>IP</th><th>City</th><th>Country</th></tr>
      {% for row in rows %}
      <tr>
        <td>{{row['ip']}}</td>
        <td>{{row['city']}}</td>
        <td>{{row['country']}}</td>
      </tr>
      {% endfor %}
    </table>
    <p>Total Showing: {{rows|length}}</p>
    """

    return render_template_string(html, rows=rows)

# --- /top/ip Route ---
@app.route("/top/ip")
def get_ip():
    ip = request.args.get("ip")

    if not ip:
        return jsonify({"error": "IP parameter required"}), 400

    conn = get_db_connection()
    row = conn.execute(
        "SELECT ip, city, country FROM ip_indicators WHERE ip = ?",
        (ip,)
    ).fetchone()
    conn.close()

    if not row:
        return jsonify({"message": "IP not found in database"})

    return jsonify(dict(row))

# --- Secure Update Endpoint ---
@app.route("/update")
def update_threat_intel():
    secret = request.args.get("key")

    if secret != os.environ.get("ADMIN_KEY"):
        return {"error": "Unauthorized"}, 403

    ips = fetch_otx_ips()
    mal_ips = filter_malaysia(ips)
    save_ips(mal_ips)

    return {
        "status": "updated",
        "malaysian_ips_found": len(mal_ips)
    }

# --- Run Local Only ---
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
