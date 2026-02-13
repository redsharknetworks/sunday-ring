from fastapi import FastAPI
from apscheduler.schedulers.background import BackgroundScheduler
from ingestion import ingest
from api.routes import router

app = FastAPI(title="Malaysia Threat Intel Dashboard")
app.include_router(router)

# Scheduler for real-time ingestion
scheduler = BackgroundScheduler()
scheduler.add_job(ingest, "interval", minutes=15)
scheduler.start()

# Run once at startup
ingest()
