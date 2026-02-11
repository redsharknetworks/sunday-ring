from fastapi import FastAPI
from app.api.routes import router
from app.db.database import engine
from app.db.models import Base
from app.core.scheduler import scheduler

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Red Shark Threat Intelligence Platform")

app.include_router(router)
