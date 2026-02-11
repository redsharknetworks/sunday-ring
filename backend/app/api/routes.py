from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.db.database import SessionLocal
from app.db.models import Indicator
from fastapi.responses import StreamingResponse
import csv
import io
from reportlab.platypus import SimpleDocTemplate, Paragraph
from reportlab.lib.styles import getSampleStyleSheet

router = APIRouter(prefix="/api")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@router.get("/top/ip")
def top_ips(db: Session = Depends(get_db)):
    result = (
        db.query(Indicator.value, func.count(Indicator.id).label("count"))
        .filter(Indicator.type == "ip")
        .group_by(Indicator.value)
        .order_by(func.count(Indicator.id).desc())
        .limit(10)
        .all()
    )
    return result

@router.get("/report/json")
def json_report(db: Session = Depends(get_db)):
    indicators = db.query(Indicator).all()
    return indicators

@router.get("/report/csv")
def csv_report(db: Session = Depends(get_db)):
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Type", "Value", "Country", "Date"])

    for i in db.query(Indicator).all():
        writer.writerow([i.type, i.value, i.country, i.created_at])

    output.seek(0)
    return StreamingResponse(output, media_type="text/csv")

@router.get("/report/pdf")
def pdf_report(db: Session = Depends(get_db)):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer)
    styles = getSampleStyleSheet()
    content = []

    content.append(Paragraph("Red Shark Weekly Threat Report", styles["Title"]))

    results = (
        db.query(Indicator.value, func.count(Indicator.id))
        .filter(Indicator.type == "ip")
        .group_by(Indicator.value)
        .order_by(func.count(Indicator.id).desc())
        .limit(10)
        .all()
    )

    for ip, count in results:
        content.append(Paragraph(f"{ip} - {count}", styles["Normal"]))

    doc.build(content)
    buffer.seek(0)

    return StreamingResponse(buffer, media_type="application/pdf")
