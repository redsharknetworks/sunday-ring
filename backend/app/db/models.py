from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy.sql import func
from app.db.database import Base

class Indicator(Base):
    __tablename__ = "indicators"

    id = Column(Integer, primary_key=True, index=True)
    type = Column(String)
    value = Column(String, index=True)
    country = Column(String)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
