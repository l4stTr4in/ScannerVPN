# app/schemas/scan_job.py
from pydantic import BaseModel
from typing import List, Any, Dict, Optional
from datetime import datetime
from .common import PaginationInfo # <--- Import từ file common

class ScanJobRequest(BaseModel):
    tool: str
    targets: List[str]
    options: Dict[str, Any] = {}
    country: Optional[str] = None

class ScanJob(BaseModel):
    id: int
    job_id: str
    scanner_job_name: Optional[str] = None
    tool: str
    targets: List[str]
    options: Optional[Dict[str, Any]] = None
    status: str
    error_message: Optional[str] = None
    vpn_profile: Optional[str] = None  # Lưu VPN filename được assign
    vpn_country: Optional[str] = None
    vpn_hostname: Optional[str] = None
    vpn_assignment: Optional[Dict[str, Any]] = None
    workflow_id: Optional[str] = None
    step_order: Optional[int] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class PaginatedScanJobs(BaseModel):
    pagination: PaginationInfo
    results: List[ScanJob]