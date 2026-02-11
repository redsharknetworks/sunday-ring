import geoip2.database
from app.core.config import MAXMIND_DB

reader = geoip2.database.Reader(MAXMIND_DB)

def is_malaysia(ip):
    try:
        response = reader.country(ip)
        return response.country.iso_code == "MY"
    except:
        return False
