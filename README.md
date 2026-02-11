# Malaysia Threat Intel (OTX + MaxMind)

This project collects threat indicators from AlienVault OTX and filters
malicious IPs targeting Malaysia using MaxMind GeoIP.

## Features
- Pull IPs, Domains, File Hashes from OTX
- Filter Malaysian IPs
- Store indicators in SQLite
- Show Top 10 per category

## Setup
1. Clone repo
```bash
git clone https://github.com/yourusername/otx-malaysia-threat-intel.git
cd otx-malaysia-threat-intel
pip install -r requirements.txt
cp .env.example .env
