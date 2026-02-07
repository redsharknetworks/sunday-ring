import geoip2.database
from db import insert_ioc, init_db
import sqlite3

DB = 'data/iocs.db'
MMDB = 'GeoLite2-City.mmdb'

def enrich_and_update():
    reader = geoip2.database.Reader(MMDB)
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT id, indicator FROM iocs WHERE country IS NULL")
    rows = c.fetchall()
    for _id, ip in rows:
        try:
            r = reader.city(ip)
            country = r.country.iso_code
            asn = None  # use additional ASN DB or service
            isp = None
            c.execute("UPDATE iocs SET country=?, asn=?, isp=? WHERE id=?", (country, asn, isp, _id))
        except Exception:
            continue
    conn.commit()
    conn.close()
    reader.close()
