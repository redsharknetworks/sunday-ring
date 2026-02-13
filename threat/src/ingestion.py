from otx_client import fetch_indicators
from maxmind_geo import is_malaysia_ip
from database import insert_indicator

def ingest():
    ips = fetch_indicators("IPv4")
    domains = fetch_indicators("domain")
    hashes = fetch_indicators("FileHash-SHA256")

    # Malaysian IPs
    for ip in ips:
        if is_malaysia_ip(ip):
            insert_indicator("ip", ip, "MY")

    # Domains & hashes
    for domain in domains:
        insert_indicator("domain", domain, "")
    for h in hashes:
        insert_indicator("hash", h, "")
