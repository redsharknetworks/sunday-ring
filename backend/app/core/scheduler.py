from apscheduler.schedulers.background import BackgroundScheduler
from app.services.ingestion import ingest

scheduler = BackgroundScheduler()
scheduler.add_job(ingest, "interval", minutes=15)
scheduler.start()
