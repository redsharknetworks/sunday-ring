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
import subprocess

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

def severity(score):
    if score <= 3:
        return "Low"
    if score <= 7:
        return "Medium"
    return "High"

# ---------------- WRITE MARKDOWN ----------------
with open("index.md", "w") as f:
    f.write(f"""
<p align="center">
  <img src="redshark.jpg" width="180">
</p>

# 🦈 Sunday Ring with Red Shark
**Weekly Threat Intelligence Snapshot – Malaysia**

**Week:** {today_str}

---

## 🔥 Top 10 Threat Indicators

| # | Indicator | Severity | Action |
|---|----------|----------|--------|
""")
    for i, ip in enumerate(malaysia_ips, start=1):
        f.write(f"| {i} | {ip} | {severity(i)} | Block / Monitor |\n")

    f.write("""
---

## 📥 Downloads
- 📄 [PDF Report](weekly-report.pdf)
- 📊 [CSV Export](weekly-ioc.csv)

---

## 📞 Contact Red Shark Networks
- 📧 devnet@redshark.my
- 💬 https://wa.me/60195352325

---

## ⚠️ Disclaimer
Based on publicly available Cisco Talos intelligence.
Analysis independently developed by Red Shark Networks.
""")

# ---------------- WRITE CSV ----------------
with open("weekly-ioc.csv", "w", newline="") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["Date", "Indicator", "Type", "Country", "Severity", "Recommended Action"])
    for i, ip in enumerate(malaysia_ips, start=1):
        writer.writerow([today_str, ip, "IP Address", "Malaysia", severity(i), "Block / Monitor"])

# ---------------- WRITE STIX-LITE JSON ----------------
stix_objects = []
for i, ip in enumerate(malaysia_ips, start=1):
    stix_objects.append({
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{uuid4()}",
        "created": datetime.utcnow().isoformat() + "Z",
        "modified": datetime.utcnow().isoformat() + "Z",
        "name": f"Malicious IP {ip}",
        "indicator_types": ["malicious-activity"],
        "pattern": f"[ipv4-addr:value = '{ip}']",
        "confidence": 50 + (i * 5),
        "labels": ["redshark", "malaysia"],
        "description": "Publicly observed malicious infrastructure affecting Malaysia"
    })

stix_bundle = {"type": "bundle", "id": f"bundle--{uuid4()}", "objects": stix_objects}
with open("weekly-ioc.json", "w") as jf:
    json.dump(stix_bundle, jf, indent=2)

# ---------------- ARCHIVE ----------------
with open(f"archive/{archive_name}.md", "w") as a:
    a.write(open("index.md").read())

# ---------------- GENERATE PDF ----------------
pdf_file = "weekly-report.pdf"
doc = SimpleDocTemplate(pdf_file, pagesize=A4)
styles = getSampleStyleSheet()
story = []

# Add logo if exists
if os.path.exists("redshark.jpg"):
    story.append(Image("redshark.jpg", width=180, height=60))

story.append(Paragraph("<b>Sunday Ring with Red Shark</b>", styles["Title"]))
story.append(Paragraph("Weekly Threat Intelligence – Malaysia", styles["Heading2"]))
story.append(Spacer(1, 12))
story.append(Paragraph(f"Week: {today_str}", styles["Normal"]))
story.append(Spacer(1, 12))

table_data = [["#", "Indicator", "Severity", "Action"]]
for i, ip in enumerate(malaysia_ips, start=1):
    table_data.append([str(i), ip, severity(i), "Block / Monitor"])

table = Table(table_data)
table.setStyle(TableStyle([
    ("BACKGROUND", (0,0), (-1,0), colors.grey),
    ("TEXTCOLOR", (0,0), (-1,0), colors.whitesmoke),
    ("GRID", (0,0), (-1,-1), 1, colors.black),
    ("FONT", (0,0), (-1,0), "Helvetica-Bold")
]))
story.append(table)
doc.build(story)

print("Markdown, CSV, JSON, PDF & archive generated successfully!")

# ---------------- COMMIT & PUSH ----------------
def run_cmd(cmd):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Command failed: {cmd}\n{result.stderr}")
    return result

# Configure git
run_cmd("git config --global user.name 'GitHub Actions'")
run_cmd("git config --global user.email 'actions@github.com'")

# Add files
run_cmd("git add index.md weekly-report.pdf weekly-ioc.csv weekly-ioc.json archive/")

# Commit changes
run_cmd(f'git commit -m "Weekly IOC update {today_str}" || echo "No changes to commit"')

# Push to main
run_cmd("git push")
print("Changes committed and pushed to main branch successfully!")
