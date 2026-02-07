import sqlite3
from pathlib import Path

DB_PATH = Path('data/iocs.db')
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
    CREATE TABLE IF NOT EXISTS iocs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        indicator TEXT,
        type TEXT,
        seen_at TEXT,
        country TEXT,
        asn TEXT,
        isp TEXT,
        score INTEGER,
        sources TEXT,
        raw_json TEXT
    )''')
    conn.commit()
    conn.close()

def insert_ioc(ioc):
    conn = sqlite3.connect(DB_PATH)
    v = (ioc.get('indicator'), ioc.get('type'), ioc.get('seen_at'),
         ioc.get('country'), ioc.get('asn'), ioc.get('isp'),
         ioc.get('score'), ioc.get('sources'), json.dumps(ioc.get('raw',{})))
    c = conn.cursor()
    c.execute('''
      INSERT INTO iocs (indicator,type,seen_at,country,asn,isp,score,sources,raw_json)
      VALUES (?,?,?,?,?,?,?,?,?)
    ''', v)
    conn.commit()
    conn.close()
