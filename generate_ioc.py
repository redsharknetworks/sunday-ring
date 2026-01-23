#!/usr/bin/env python3
import requests
import geoip2.database
from datetime import date, datetime
import csv
import os
import json
from uuid import uuid4
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
import geoip2.errors
import sys
import time
import traceback

# ---------------- CONFIG ----------------
TALOS_IOC_URL = "https://raw.githubusercontent.com/Cisco-Talos/IOCs/main/2025/2025-01-IOC.json"
GEOIP_DB = "GeoLite2-Country.mmdb"
LOGO_FILE = "redshark.jpg"
MAX_IOCS = 10
GITHUB_REPO = "Cisco-Talos/IOCs"
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

# ---------------- FATAL HANDLER ----------------
def fatal(msg):
    print(f"\n❌ FATAL: {msg}", file=sys.stderr)
    traceback.print_exc()
    sys.exit(1)

# ---------------- HELPERS ----------------
def severity(score):
    if score <= 3:
        return "Low"
    if score <= 7:
        return "Medium"
    return "High"

def requests_get(url):
    headers = {}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"token {GITHUB_TOKEN}"
    return requests.get(url, headers=headers, timeout=30)

def fetch_with_retries(url, retries=3):
    last_exc = None
    for i in range(retries):
        try:
            r = requests_get(url)
            r.raise_for_status()
            return r
        except Exception as e:
            last_exc = e
            time.sleep(2 * (i + 1))
    raise last_exc

# ---------------- MAIN ----------------
try:
    today = date.today()
    today_str = today.strftime("%d %B %Y")
    archive_name = today.strftime("%Y-%m-%d")
    os.makedirs("archive", exist_ok=True)

    # Fetch IOC data
    r = fetch_with_retries(TALOS_IOC_URL)
    data = r.json()

    # GeoIP
    reader = None
    if os.path.exists(GEOIP_DB):
        reader = geoip2.database.Reader(GEOIP_DB)

    malaysia_ips = []

    for ioc in data.get("indicators", []):
        if ioc.get("type") != "ip":
            continue

        ip = ioc.get("indicator") or ioc.get("value")
        if not ip:
            continue

        if reader:
            try:
                rec = reader.country(ip)
                if rec.country.iso_code == "MY":
                    malaysia_ips.append(ip)
            except geoip2.errors.AddressNotFoundError:
                pass
        else:
            malaysia_ips.append(ip)

        if len(malaysia_ips) >= MAX_IOCS:
            break

    if reader:
        reader.close()

    # HARD FAIL if nothing found
    if not malaysia_ips:
        print("❌ ERROR: No Malaysia-related IPs found.")
        sys.exit(1)

    # ---------------- WRITE FILES ----------------
    with open("index.md", "w") as f:
        f.write(f"# Sunday Ring with Red Shark\n\nWeek: {today_str}\n\n")
        for i, ip in enumerate(malaysia_ips, 1):
            f.write(f"- {ip} ({severity(i)})\n")

    with open("weekly-ioc.csv", "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Date", "Indicator", "Country", "Severity"])
        for i, ip in enumerate(malaysia_ips, 1):
            writer.writerow([today_str, ip, "Malaysia", severity(i)])

    stix_objects = []
    for i, ip in enumerate(malaysia_ips, 1):
        stix_objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid4()}",
            "created": datetime.utcnow().isoformat() + "Z",
            "modified": datetime.utcnow().isoformat() + "Z",
            "name": f"Malicious IP {ip}",
            "pattern": f"[ipv4-addr:value = '{ip}']",
            "confidence": min(100, 50 + i * 5)
        })

    with open("weekly-ioc.json", "w") as jf:
        json.dump({"type": "bundle", "objects": stix_objects}, jf, indent=2)

    with open(f"archive/{archive_name}.md", "w") as a:
        with open("index.md") as idx:
            a.write(idx.read())

    # ---------------- PDF ----------------
    doc = SimpleDocTemplate("weekly-report.pdf", pagesize=A4)
    styles = getSampleStyleSheet()
    story = [
        Paragraph("Sunday Ring with Red Shark", styles["Title"]),
        Spacer(1, 12),
        Paragraph(f"Week: {today_str}", styles["Normal"]),
    ]

    table_data = [["#", "Indicator", "Severity"]]
    for i, ip in enumerate(malaysia_ips, 1):
        table_data.append([i, ip, severity(i)])

    table = Table(table_data)
    table.setStyle(TableStyle([
        ("GRID", (0,0), (-1,-1), 1, colors.black),
        ("BACKGROUND", (0,0), (-1,0), colors.grey)
    ]))
    story.append(table)
    doc.build(story)

    # ---------------- FINAL ASSERT ----------------
    required = ["index.md", "weekly-ioc.csv", "weekly-ioc.json", "weekly-report.pdf"]
    missing = [f for f in required if not os.path.exists(f)]
    if missing:
        print("❌ ERROR: Missing files:", missing)
        sys.exit(1)

    print("✅ IOC generation completed successfully")

except Exception:
    fatal("Unhandled exception in IOC pipeline")
