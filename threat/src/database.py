import sqlite3

conn = sqlite3.connect("threatintel.db", check_same_thread=False)
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS indicators (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT,
    value TEXT,
    country TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)
""")
conn.commit()

def insert_indicator(ind_type, value, country):
    cursor.execute(
        "INSERT INTO indicators (type, value, country) VALUES (?, ?, ?)",
        (ind_type, value, country)
    )
    conn.commit()
