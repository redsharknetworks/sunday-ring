from app.db.database import SessionLocal
from app.db.models import Indicator
from app.services.otx_client import fetch_indicators
from app.services.maxmind import is_malaysia

def ingest():
    db = SessionLocal()

    ips = fetch_indicators("IPv4")

    for ip in ips:
        if is_malaysia(ip):
            indicator = Indicator(type="ip", value=ip, country="MY")
            db.add(indicator)

    db.commit()
    db.close()
