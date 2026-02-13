import os
import sqlite3
import requests
from flask import Flask, render_template_string
import geoip2.database

app = Flask(__name__)

# --- Environment Variables ---
OTX_API_KEY = os.environ.get("OTX_API_KEY")
GEOIP_DB = "GeoLite2-City.mmdb"            # GeoIP database file
DATABASE_FILE = "threat_intel.db"

# --- Initialize SQLite ---
conn = sqlite3.connect(DATABASE_FILE, check_same_thread=False)
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS ip_indicators (
    id INTEGER PRIMARY KEY,
    ip TEXT UNIQUE,
    city TEXT,
    country TEXT
)""")
conn.commit()

# --- Function to fetch OTX indicators ---
def fetch_otx_ips():
    headers = {
        "X-OTX-API-KEY": OTX_API_KEY,
        "Accept": "application/json"
    }
    url = "https://otx.alienvault.com/api/v1/pulses/indicators"
    params = {"limit": 100}
    response = requests.get(url, headers=headers, params=params)

    if response.status_code == 200:
        data = response.json()
        ips = [d["indicator"] for d in data.get("results", []) if d["type"] == "IPv4"]
        return ips
    return []

# --- Filter Malaysian IPs ---
def filter_malaysia(ips):
    reader = geoip2.database.Reader(GEOIP_DB)
    mal_ips = []
    for ip in ips:
        try:
            rec = reader.city(ip)
            if rec.country.iso_code == "MY":   # Country = Malaysia
                mal_ips.append((ip, rec.city.name, rec.country.name))
        except:
            continue
    reader.close()
    return mal_ips

# --- Save to DB ---
def save_ips(ip_list):
    for ip, city, country in ip_list:
        cursor.execute(
            "INSERT OR IGNORE INTO ip_indicators (ip, city, country) VALUES (?, ?, ?)",
            (ip, city or "-", country)
        )
    conn.commit()

# --- Build Dashboard ---
@app.route("/")
def dashboard():
    cursor.execute("SELECT ip, city, country FROM ip_indicators ORDER BY id DESC LIMIT 10")
    top_ips = cursor.fetchall()

    html = """
    <h1>Malaysia Threat Intel Dashboard</h1>
    <table border="1" cellpadding="5">
      <tr><th>IP</th><th>City</th><th>Country</th></tr>
      {% for ip, city, country in top_ips %}
      <tr><td>{{ip}}</td><td>{{city}}</td><td>{{country}}</td></tr>
      {% endfor %}
    </table>
    <p>Total IPs: {{count}}</p>
    """
    return render_template_string(html, top_ips=top_ips, count=len(top_ips))

# --- Update & Filter Indicators Endpoint ---
@app.route("/update")
def update_threat_intel():
    ips = fetch_otx_ips()
    mal_ips = filter_malaysia(ips)
    save_ips(mal_ips)
    return f"Updated! Found {len(mal_ips)} Malaysian IPs."

if __name__ == "__main__":
    # Render requires binding to host=0.0.0.0 and using PORT env variable
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
