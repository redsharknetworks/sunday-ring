import sqlite3, csv, json
from pathlib import Path
from datetime import datetime, timedelta
import pdfkit  # or weasyprint

OUT = Path('exports')
OUT.mkdir(parents=True, exist_ok=True)

def export_weekly():
    conn = sqlite3.connect('data/iocs.db')
    c = conn.cursor()
    week_ago = (datetime.utcnow() - timedelta(days=7)).isoformat()
    c.execute("SELECT indicator,type,seen_at,country,asn,isp,score,sources FROM iocs WHERE seen_at >= ?", (week_ago,))
    rows = c.fetchall()
    # CSV
    csv_path = OUT / 'csv' / f'iocs_{datetime.utcnow():%Y%m%d}.csv'
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with csv_path.open('w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['indicator','type','seen_at','country','asn','isp','score','sources'])
        writer.writerows(rows)
    # JSON
    json_path = OUT / 'json' / f'iocs_{datetime.utcnow():%Y%m%d}.json'
    json_path.parent.mkdir(parents=True, exist_ok=True)
    with json_path.open('w', encoding='utf-8') as f:
        json.dump([dict(zip(['indicator','type','seen_at','country','asn','isp','score','sources'], r)) for r in rows], f, indent=2)
    # PDF via HTML template (simple)
    html = "<h1>Weekly IOCs</h1>" + "<table>" + "".join(f"<tr>{''.join(f'<td>{c}</td>' for c in r)}</tr>" for r in rows) + "</table>"
    pdf_path = OUT / 'pdf' / f'iocs_{datetime.utcnow():%Y%m%d}.pdf'
    pdf_path.parent.mkdir(parents=True, exist_ok=True)
    pdfkit.from_string(html, str(pdf_path))
    conn.close()
