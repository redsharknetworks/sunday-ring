from fastapi import APIRouter
from database import cursor

router = APIRouter()

@router.get("/top/ip")
def top_ips():
    cursor.execute("""
        SELECT value, COUNT(*) as cnt
        FROM indicators
        WHERE type='ip'
        GROUP BY value
        ORDER BY cnt DESC
        LIMIT 10
    """)
    return cursor.fetchall()

@router.get("/top/domain")
def top_domains():
    cursor.execute("""
        SELECT value, COUNT(*) as cnt
        FROM indicators
        WHERE type='domain'
        GROUP BY value
        ORDER BY cnt DESC
        LIMIT 10
    """)
    return cursor.fetchall()

@router.get("/top/hash")
def top_hashes():
    cursor.execute("""
        SELECT value, COUNT(*) as cnt
        FROM indicators
        WHERE type='hash'
        GROUP BY value
        ORDER BY cnt DESC
        LIMIT 10
    """)
    return cursor.fetchall()
