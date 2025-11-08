# app/models/workflow_job.py
from sqlalchemy import Column, Integer, String, DateTime, JSON
from sqlalchemy.orm import relationship
from app.db.base import Base # <--- Import từ base
import datetime

class WorkflowJob(Base):
    __tablename__ = "workflow_jobs"
    id = Column(Integer, primary_key=True, index=True)
    workflow_id = Column(String, unique=True, index=True)
    parent_workflow_id = Column(String, nullable=True, index=True)  # ID của workflow cha
    targets = Column(JSON)
    strategy = Column(String, default="wide")
    status = Column(String, default="pending")
    vpn_profile = Column(String, nullable=True)
    vpn_country = Column(String, nullable=True)
    vpn_assignment = Column(JSON, nullable=True)
    total_steps = Column(Integer, default=0)
    completed_steps = Column(Integer, default=0)
    failed_steps = Column(Integer, default=0)
    total_phase = Column(Integer, default=1)  # Tổng số phase (lần gọi API/workflow)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    sub_jobs = relationship("ScanJob", back_populates="workflow")