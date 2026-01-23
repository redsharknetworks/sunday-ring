#!/usr/bin/env python3
import os, sys, traceback, csv, json
from uuid import uuid4
from datetime import date, datetime
import requests
import geoip2.database
import geoip2.errors
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from dateutil.parser import parse

# ---------------- CONFIG ----------------
TALOS_IOC_URL = "https://raw.githubusercontent.com/Cisco-Talos/IOCs/main/2025/2025-01-IOC.json"
GEOIP_DB = "GeoLite2-Country.mmdb"
OUTPUT_DIR = "."   # Root for Pages
MAX_IOCS = 10

# ---------------- FATAL ----------------
def fatal(msg):
    print(f"\n❌ FATAL: {msg}", file=sys.stderr)
    traceback.print_exc()
    sys.exit(1)

# ---------------- VALIDATE GEOIP ----------------
if not os.path.exists(GEOIP_DB):
    fatal("GeoIP DB missing. Pipeline cannot continue.")

try:
    reader = geoip2.database.Reader(GEOIP_DB)
except Exception:
    fatal("Unable to open GeoIP DB")

# ---------------- HELPERS ----------------
def severity(rank):
    return "High" if rank <= 3 else "Medium" if rank <= 7 else "Low"

def fetch_json(url):
    r = requests.get(url, timeout=30)
    r.raise_for_status()
    return r.json()

# ---------------- MAIN ----------------
try:
    today = date.today()
    today_str = today.strftime("%d %B %Y")

    data = fetch_json(TALOS_IOC_URL)
    indicators = data.get("indicators", [])

    malaysia_candidates = []

    for ioc in indicators:
        if ioc.get("type") != "ip":
            continue
        ip = ioc.get("indicator") or ioc.get("value")
        if not ip:
            continue

        try:
            rec = reader.country(ip)
            if rec.country.iso_code != "MY":
                continue
        except geoip2.errors.AddressNotFoundError:
            continue

        malaysia_candidates.append({
            "ip": ip,
            "confidence": ioc.get("confidence", 50),
            "first_seen": ioc.get("first_seen", "1970-01-01")
        })

    reader.close()

    if not malaysia_candidates:
        fatal("No Malaysia-geolocated IPs found")

    # Sort by confidence & first_seen
    malaysia_candidates.sort(
        key=lambda x: (x["confidence"], parse(x["first_seen"])),
        reverse=True
    )

    top_ips = malaysia_candidates[:MAX_IOCS]

    # ---------------- HTML Output ----------------
    html_file = os.path.join(OUTPUT_DIR, "index.html")
    with open(html_file, "w") as f:
        f.write(f"""
        <!DOCTYPE html>
        <html>
        <head><title>Weekly IOC – Malaysia</title></head>
        <body>
        <h1>Weekly Threat Intel – Malaysia</h1>
        <p>Week: {today_str}</p>
        <ul>
        """)
        for i, item in enumerate(top_ips, 1):
            f.write(f"<li>{i}. {item['ip']} ({severity(i)})</li>\n")
        f.write("</ul></body></html>")

    # ---------------- CSV ----------------
    with open(os.path.join(OUTPUT_DIR, "weekly-ioc.csv"), "w", newline="") as c:
        w = csv.writer(c)
        w.writerow(["Date", "IP", "Country", "Severity", "Confidence"])
        for i, item in enumerate(top_ips, 1):
            w.writerow([today_str, item["ip"], "Malaysia", severity(i), item["confidence"]])

    # ---------------- JSON/STIX ----------------
    bundle = {"type": "bundle", "id": f"bundle--{uuid4()}", "objects": []}
    for item in top_ips:
        bundle["objects"].append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid4()}",
            "created": datetime.utcnow().isoformat() + "Z",
            "modified": datetime.utcnow().isoformat() + "Z",
            "name": f"Malicious IP {item['ip']}",
            "pattern": f"[ipv4-addr:value = '{item['ip']}']",
            "confidence": item["confidence"],
            "labels": ["geoip-my", "redshark"]
        })
    with open(os.path.join(OUTPUT_DIR, "weekly-ioc.json"), "w") as j:
        json.dump(bundle, j, indent=2)

    # ---------------- PDF ----------------
    doc = SimpleDocTemplate(os.path.join(OUTPUT_DIR, "weekly-report.pdf"), pagesize=A4)
    styles = getSampleStyleSheet()
    story = [
        Paragraph("Weekly Threat Intel – Malaysia", styles["Title"]),
        Spacer(1, 12),
        Paragraph(f"Week: {today_str}", styles["Normal"])
    ]
    table_data = [["#", "IP", "Severity"]]
    for i, item in enumerate(top_ips, 1):
        table_data.append([i, item["ip"], severity(i)])
    table = Table(table_data)
    table.setStyle(TableStyle([
        ("GRID", (0,0), (-1,-1), 1, colors.black),
        ("BACKGROUND", (0,0), (-1,0), colors.grey),
    ]))
    story.append(table)
    doc.build(story)

    # ---------------- FINAL ASSERT ----------------
    for f in ["index.html", "weekly-ioc.csv", "weekly-ioc.json", "weekly-report.pdf"]:
        path = os.path.join(OUTPUT_DIR, f)
        if not os.path.exists(path):
            fatal(f"Missing output file: {path}")

    print("✅ IOC pipeline completed successfully")

except Exception:
    fatal("Unhandled exception in pipeline")
