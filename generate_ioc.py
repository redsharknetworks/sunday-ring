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
import subprocess
import sys
import geoip2.errors
import time

# ---------------- CONFIG ----------------
TALOS_IOC_URL = "https://raw.githubusercontent.com/Cisco-Talos/IOCs/main/2025/2025-01-IOC.json"
GEOIP_DB = "GeoLite2-Country.mmdb"
LOGO_FILE = "redshark.jpg"
MAX_IOCS = 10
GITHUB_REPO = "Cisco-Talos/IOCs"  # owner/repo
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")  # optional, helps avoid rate limits

# ---------------- HELPERS ----------------
def severity(score):
    if score <= 3:
        return "Low"
    if score <= 7:
        return "Medium"
    return "High"

def run_cmd(cmd):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Command failed: {cmd}\n{result.stderr}")
    return result

def requests_get(url, **kwargs):
    headers = kwargs.pop("headers", {})
    if GITHUB_TOKEN:
        headers.update({"Authorization": f"token {GITHUB_TOKEN}"})
    return requests.get(url, headers=headers, timeout=30, **kwargs)

def fetch_with_retries(url, retries=3, backoff=1):
    last_exc = None
    for attempt in range(1, retries + 1):
        try:
            r = requests_get(url)
            r.raise_for_status()
            return r
        except requests.exceptions.HTTPError as e:
            # For 404 return the response so caller can inspect status_code
            if e.response is not None and e.response.status_code == 404:
                return e.response
            last_exc = e
        except requests.exceptions.RequestException as e:
            last_exc = e
        time.sleep(backoff * attempt)
    raise last_exc

# ---------------- CHECK FOR OPTIONAL FILES ----------------
geoip_available = os.path.exists(GEOIP_DB)
if not geoip_available:
    print(f"Warning: GeoIP DB not found at {GEOIP_DB}. Falling back to non-geolocated selection.")
logo_available = os.path.exists(LOGO_FILE)
if not logo_available:
    print(f"Note: Logo file not found at {LOGO_FILE}. PDF will be generated without logo.")

# ---------------- DATE ----------------
today = date.today()
today_str = today.strftime("%d %B %Y")
archive_name = today.strftime("%Y-%m-%d")
os.makedirs("archive", exist_ok=True)

# ---------------- FETCH IOC ----------------
def find_ioc_in_year(year_folder):
    api_url = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{year_folder}"
    try:
        r = fetch_with_retries(api_url)
        if r.status_code != 200:
            return None
        items = r.json()
        # pick first file that looks like YYYY-MM-IOC.json or contains 'ioc' and '.json'
        for it in items:
            name = it.get("name", "").lower()
            if name.endswith(".json") and ("ioc" in name or "-" in name or name.startswith(year_folder)):
                return it.get("download_url")
    except Exception:
        return None
    return None

data = None
try:
    # Try configured static URL first
    r = fetch_with_retries(TALOS_IOC_URL)
    if r.status_code == 200:
        try:
            data = r.json()
        except ValueError as e:
            print(f"Error parsing IOC JSON from configured URL: {e}")
            sys.exit(1)
    elif r.status_code == 404:
        # Try to auto-discover
        year = None
        try:
            # attempt to get year segment from configured URL (assumes .../<year>/...)
            parts = TALOS_IOC_URL.rstrip("/").split("/")
            if len(parts) >= 2:
                year = parts[-2] if parts[-2].isdigit() and len(parts[-2]) == 4 else None
        except Exception:
            year = None

        download_url = None
        if year:
            download_url = find_ioc_in_year(year)

        if not download_url:
            # list top-level contents and try year folders
            api_root = f"https://api.github.com/repos/{GITHUB_REPO}/contents"
            r_root = fetch_with_retries(api_root)
            if r_root.status_code == 200:
                items = r_root.json()
                year_folders = [it["name"] for it in items if it.get("type") == "dir" and it["name"].isdigit() and len(it["name"]) == 4]
                # prefer newest year first
                for yf in sorted(year_folders, reverse=True):
                    download_url = find_ioc_in_year(yf)
                    if download_url:
                        break

        if not download_url:
            print(f"Could not locate IOC JSON in {GITHUB_REPO} (checked configured URL and repo contents).")
            sys.exit(1)

        # fetch discovered file
        r2 = fetch_with_retries(download_url)
        if r2.status_code == 200:
            try:
                data = r2.json()
            except ValueError as e:
                print(f"Error parsing discovered IOC JSON: {e}")
                sys.exit(1)
        else:
            print(f"Failed to download discovered IOC JSON: HTTP {r2.status_code}")
            sys.exit(1)
    else:
        print(f"Unexpected HTTP status when fetching configured URL: {r.status_code}")
        sys.exit(1)
except requests.exceptions.RequestException as e:
    print(f"Error fetching IOC data (HTTP): {e}")
    sys.exit(1)

# ---------------- GEOIP READER ----------------
reader = None
if geoip_available:
    try:
        reader = geoip2.database.Reader(GEOIP_DB)
    except Exception as e:
        print(f"Could not open GeoIP DB ({GEOIP_DB}): {e}")
        reader = None

malaysia_ips = []

for ioc in (data.get("indicators", []) if isinstance(data, dict) else []):
    if ioc.get("type") != "ip":
        continue
    ip = ioc.get("indicator") or ioc.get("value") or None
    if not ip:
        continue

    if reader:
        try:
            rec = reader.country(ip)
            if rec and getattr(rec.country, "iso_code", None) == "MY":
                malaysia_ips.append(ip)
        except geoip2.errors.AddressNotFoundError:
            continue
        except Exception:
            continue
    else:
        malaysia_ips.append(ip)

    if len(malaysia_ips) >= MAX_IOCS:
        break

if reader:
    try:
        reader.close()
    except Exception:
        pass

if not malaysia_ips:
    print("No Malaysia-related IPs found. Exiting.")
    sys.exit(0)

# ---------------- WRITE MARKDOWN ----------------
with open("index.md", "w") as f:
    f.write(f"""<p align=\"center\">\n  <img src=\"{LOGO_FILE}\" width=180>\n</p>\n\n# 🦈 Sunday Ring with Red Shark\n**Weekly Threat Intelligence Snapshot – Malaysia**\n\n**Week:** {today_str}\n\n---\n\n## 🔥 Top {len(malaysia_ips)} Threat Indicators\n\n| # | Indicator | Severity | Action |\n|---|----------|----------|--------|\n""")
    for i, ip in enumerate(malaysia_ips, start=1):
        f.write(f"| {i} | {ip} | {severity(i)} | Block / Monitor |\n")

    f.write("""\n---\n\n## 📥 Downloads\n- 📄 [PDF Report](weekly-report.pdf)\n- 📊 [CSV Export](weekly-ioc.csv)\n\n---\n\n## 📞 Contact Red Shark Networks\n- 📧 devnet@redshark.my\n- 💬 https://wa.me/60132330646\n\n---\n\n## ⚠️ Disclaimer\nBased on publicly available Cisco Talos intelligence.\nAnalysis independently developed by Red Shark Networks.\n""")

# ---------------- WRITE CSV ----------------
with open("weekly-ioc.csv", "w", newline="") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["Date", "Indicator", "Type", "Country", "Severity", "Recommended Action"])
    for i, ip in enumerate(malaysia_ips, start=1):
        writer.writerow([today_str, ip, "IP Address", "Malaysia", severity(i), "Block / Monitor"])

# ---------------- WRITE STIX-LITE JSON ----------------
stix_objects = []
for i, ip in enumerate(malaysia_ips, start=1):
    confidence = min(100, 50 + (i * 5))
    stix_objects.append({
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{uuid4()}",
        "created": datetime.utcnow().isoformat() + "Z",
        "modified": datetime.utcnow().isoformat() + "Z",
        "name": f"Malicious IP {ip}",
        "indicator_types": ["malicious-activity"],
        "pattern": f"[ipv4-addr:value = '{ip}']",
        "confidence": confidence,
        "labels": ["redshark", "malaysia"],
        "description": "Publicly observed malicious infrastructure affecting Malaysia"
    })

stix_bundle = {"type": "bundle", "id": f"bundle--{uuid4()}", "objects": stix_objects}
with open("weekly-ioc.json", "w") as jf:
    json.dump(stix_bundle, jf, indent=2)

# ---------------- ARCHIVE ----------------
with open(f"archive/{archive_name}.md", "w") as a:
    with open("index.md", "r") as idx:
        a.write(idx.read())

# ---------------- GENERATE PDF ----------------
pdf_file = "weekly-report.pdf"
doc = SimpleDocTemplate(pdf_file, pagesize=A4)
styles = getSampleStyleSheet()
story = []

if logo_available:
    try:
        story.append(Image(LOGO_FILE, width=180, height=60))
    except Exception as e:
        print(f"Could not include logo in PDF: {e}")

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
    ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold")
]))
story.append(table)

try:
    doc.build(story)
except Exception as e:
    print(f"Error building PDF: {e}")

print("Markdown, CSV, JSON, PDF & archive generated successfully!")
