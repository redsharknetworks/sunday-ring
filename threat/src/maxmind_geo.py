import geoip2.database
import os
from dotenv import load_dotenv

load_dotenv()
MAXMIND_DB = os.getenv("MAXMIND_DB")

reader = geoip2.database.Reader(MAXMIND_DB)

def is_malaysia_ip(ip):
    try:
        response = reader.country(ip)
        return response.country.iso_code == "MY"
    except:
        return False
