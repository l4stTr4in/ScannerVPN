# app/schemas/workflow.py
from pydantic import BaseModel
from typing import List, Any, Dict, Optional
from datetime import datetime

class WorkflowStep(BaseModel):
    tool_id: str
    params: Dict[str, Any] = {}

class WorkflowRequest(BaseModel):
    workflow_id: Optional[str] = None
    workflow_phase: Optional[int] = None
    parent_workflow_id: Optional[str] = None  # ID của workflow cha
    targets: List[str]
    strategy: str = "wide"
    steps: List[WorkflowStep]
    country: Optional[str] = None  # Chỉ giữ country preference

class WorkflowJob(BaseModel):
    id: int
    workflow_id: str
    parent_workflow_id: Optional[str] = None  # ID của workflow cha
    targets: List[str]
    strategy: str
    status: str
    vpn_profile: Optional[str] = None  # Lưu VPN filename được assign
    vpn_country: Optional[str] = None
    vpn_assignment: Optional[Dict[str, Any]] = None
    total_steps: int
    completed_steps: int
    failed_steps: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class WorkflowStepResult(BaseModel):
    step_order: int
    tool_id: str
    job_id: str
    status: str
    params: Dict[str, Any]

class WorkflowDetail(BaseModel):
    workflow: WorkflowJob
    sub_jobs: List[WorkflowStepResult]