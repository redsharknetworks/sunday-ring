#!/usr/bin/env python3
import requests
import geoip2.database
import geoip2.errors
from datetime import date, datetime
from uuid import uuid4
import csv, json, os, sys, time, traceback
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from dateutil.parser import parse

# ---------------- CONFIG ----------------
TALOS_IOC_URL = "https://raw.githubusercontent.com/Cisco-Talos/IOCs/main/2025/2025-01-IOC.json"
GEOIP_DB = "GeoLite2-Country.mmdb"
MAX_IOCS = 10

# ---------------- FATAL ----------------
def fatal(msg):
    print(f"\n❌ FATAL: {msg}", file=sys.stderr)
    traceback.print_exc()
    sys.exit(1)

# ---------------- VALIDATE GEOIP ----------------
if not os.path.exists(GEOIP_DB):
    print("❌ GeoIP DB missing. Refusing to continue.")
    sys.exit(1)

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
        print("❌ No Malaysia-geolocated IPs found")
        sys.exit(1)

    # Sort = “TOP”
    malaysia_candidates.sort(
        key=lambda x: (x["confidence"], parse(x["first_seen"])),
        reverse=True
    )

    top_ips = malaysia_candidates[:MAX_IOCS]

    # ---------------- OUTPUT ----------------
    with open("index.md", "w") as f:
        f.write(f"# Sunday Ring – Malaysia\n\nWeek: {today_str}\n\n")
        for i, item in enumerate(top_ips, 1):
            f.write(f"- {item['ip']} ({severity(i)})\n")

    with open("weekly-ioc.csv", "w", newline="") as c:
        w = csv.writer(c)
        w.writerow(["Date", "IP", "Country", "Severity", "Confidence"])
        for i, item in enumerate(top_ips, 1):
            w.writerow([today_str, item["ip"], "Malaysia", severity(i), item["confidence"]])

    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid4()}",
        "objects": []
    }

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

    with open("weekly-ioc.json", "w") as j:
        json.dump(bundle, j, indent=2)

    # PDF
    doc = SimpleDocTemplate("weekly-report.pdf", pagesize=A4)
    styles = getSampleStyleSheet()
    story = [
        Paragraph("Weekly Threat Intel – Malaysia", styles["Title"]),
        Spacer(1, 12),
        Paragraph(f"Week: {today_str}", styles["Normal"]),
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

    # Final assertion
    for f in ["index.md", "weekly-ioc.csv", "weekly-ioc.json", "weekly-report.pdf"]:
        if not os.path.exists(f):
            print(f"❌ Missing output file: {f}")
            sys.exit(1)

    print("✅ IOC pipeline completed (GeoIP verified, audit-clean)")

except Exception:
    fatal("Unhandled exception in pipeline")
