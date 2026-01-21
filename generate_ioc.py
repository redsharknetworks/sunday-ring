import requests
import geoip2.database
from datetime import date, datetime
import csv, os, json, subprocess
from uuid import uuid4

from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors

# ---------------- CONFIG ----------------
TALOS_IOC_URL = "https://raw.githubusercontent.com/Cisco-Talos/IOCs/main/2025/2025-01-IOC.json"
GEOIP_DB = "GeoLite2-Country.mmdb"
MAX_IOCS = 10

# ---------------- DATE ----------------
today = date.today()
today_str = today.strftime("%d %B %Y")
archive_name = today.strftime("%Y-%m-%d")
os.makedirs("archive", exist_ok=True)

# ---------------- FETCH IOC ----------------
response = requests.get(TALOS_IOC_URL, timeout=30)
data = response.json()

reader = geoip2.database.Reader(GEOIP_DB)
malaysia_ips = []

for ioc in data.get("indicators", []):
    if ioc.get("type") != "ip":
        continue
    try:
        if reader.country(ioc["indicator"]).country.iso_code == "MY":
            malaysia_ips.append(ioc["indicator"])
    except:
        continue
    if len(malaysia_ips) >= MAX_IOCS:
        break

reader.close()

def severity(score):
    if score <= 3:
        return "Low"
    if score <= 7:
        return "Medium"
    return "High"

# ---------------- MARKDOWN ----------------
with open("index.md", "w") as f:
    f.write(f"""
# 🦈 Sunday Ring with Red Shark
**Weekly Threat Intelligence – Malaysia**

**Week:** {today_str}

---

## 🔥 Top 10 Malicious IPs

| # | Indicator | Severity | Action |
|---|----------|----------|--------|
""")
    for i, ip in enumerate(malaysia_ips, 1):
        f.write(f"| {i} | {ip} | {severity(i)} | Block / Monitor |\n")

    f.write("""
---

## 📥 Downloads
- 📄 [PDF Report](weekly-report.pdf)
- 📊 [CSV Export](weekly-ioc.csv)

---

## ⚠️ Disclaimer
Source: Cisco Talos (Public)
Analysis: Red Shark Networks
""")

# ---------------- CSV ----------------
with open("weekly-ioc.csv", "w", newline="") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["Date", "Indicator", "Country", "Severity", "Action"])
    for i, ip in enumerate(malaysia_ips, 1):
        writer.writerow([today_str, ip, "Malaysia", severity(i), "Block / Monitor"])

# ---------------- STIX LITE ----------------
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
        "confidence": 50 + i * 5,
        "labels": ["redshark", "malaysia"]
    })

with open("weekly-ioc.json", "w") as jf:
    json.dump({"type": "bundle", "objects": stix_objects}, jf, indent=2)

# ---------------- PDF ----------------
doc = SimpleDocTemplate("weekly-report.pdf", pagesize=A4)
styles = getSampleStyleSheet()
story = []

story.append(Paragraph("Sunday Ring with Red Shark", styles["Title"]))
story.append(Paragraph(f"Week: {today_str}", styles["Normal"]))
story.append(Spacer(1, 12))

table_data = [["#", "Indicator", "Severity", "Action"]]
for i, ip in enumerate(malaysia_ips, 1):
    table_data.append([str(i), ip, severity(i), "Block / Monitor"])

table = Table(table_data)
table.setStyle(TableStyle([
    ("GRID", (0,0), (-1,-1), 1, colors.black),
    ("BACKGROUND", (0,0), (-1,0), colors.lightgrey)
]))
story.append(table)
doc.build(story)

# ---------------- ARCHIVE ----------------
with open(f"archive/{archive_name}.md", "w") as a:
    a.write(open("index.md").read())

# ---------------- GIT COMMIT ----------------
subprocess.run("git config user.name 'github-actions'", shell=True)
subprocess.run("git config user.email 'actions@github.com'", shell=True)
subprocess.run("git add index.md weekly-ioc.csv weekly-ioc.json weekly-report.pdf archive/", shell=True)
subprocess.run(f"git commit -m 'Weekly IOC update {today_str}' || echo 'No changes'", shell=True)
subprocess.run("git push", shell=True)

print("✅ Phase 5 complete: content generated & published")