# Test script để kiểm tra auto workflow chain limits
# File: test_auto_workflow_limits.py

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.models.workflow_job import WorkflowJob
from app.models.scan_job import ScanJob
from app.services.auto_workflow_service import AutoWorkflowService
from app.core.config import settings

# Tạo test database session
engine = create_engine("sqlite:///test_workflows.db")
WorkflowJob.metadata.create_all(bind=engine)
ScanJob.metadata.create_all(bind=engine)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def test_workflow_chain_counting():
    """Test đếm scanners trong workflow chain"""
    
    db = SessionLocal()
    auto_service = AutoWorkflowService(db)
    
    try:
        # Tạo mock data: workflow chain A -> B -> C
        # Workflow A (root): 5 scanners
        wf_a = WorkflowJob(
            workflow_id="workflow-a",
            parent_workflow_id=None,  # Root workflow
            targets=["192.168.1.1"],
            strategy="wide",
            status="running"
        )
        db.add(wf_a)
        
        # Tạo 5 scan jobs cho workflow A
        for i in range(5):
            job = ScanJob(
                job_id=f"job-a-{i}",
                workflow_id="workflow-a",
                tool="port-scan",
                targets=["192.168.1.1"],
                status="completed"
            )
            db.add(job)
        
        # Workflow B (child của A): 8 scanners
        wf_b = WorkflowJob(
            workflow_id="workflow-b",
            parent_workflow_id="workflow-a",  # Child của A
            targets=["192.168.1.1"],
            strategy="wide",
            status="running"
        )
        db.add(wf_b)
        
        # Tạo 8 scan jobs cho workflow B
        for i in range(8):
            job = ScanJob(
                job_id=f"job-b-{i}",
                workflow_id="workflow-b",
                tool="nuclei-scan",
                targets=["192.168.1.1"],
                status="completed"
            )
            db.add(job)
        
        # Workflow C (child của B): 12 scanners
        wf_c = WorkflowJob(
            workflow_id="workflow-c",
            parent_workflow_id="workflow-b",  # Child của B
            targets=["192.168.1.1"],
            strategy="wide",
            status="running"
        )
        db.add(wf_c)
        
        # Tạo 12 scan jobs cho workflow C
        for i in range(12):
            job = ScanJob(
                job_id=f"job-c-{i}",
                workflow_id="workflow-c",
                tool="dirsearch-scan",
                targets=["192.168.1.1"],
                status="completed"
            )
            db.add(job)
        
        db.commit()
        
        # Test tìm root workflow
        print("=== Test tìm root workflow ===")
        root_a = auto_service._find_root_workflow("workflow-a")
        root_b = auto_service._find_root_workflow("workflow-b") 
        root_c = auto_service._find_root_workflow("workflow-c")
        
        print(f"Root của workflow-a: {root_a}")  # Expect: workflow-a
        print(f"Root của workflow-b: {root_b}")  # Expect: workflow-a
        print(f"Root của workflow-c: {root_c}")  # Expect: workflow-a
        
        # Test đếm scanners trong chain
        print("\\n=== Test đếm scanners trong chain ===")
        total_scanners = auto_service._count_total_scanners_in_chain("workflow-a")
        print(f"Tổng scanners trong chain từ workflow-a: {total_scanners}")  # Expect: 5 + 8 + 12 = 25
        
        # Test kiểm tra limits
        print("\\n=== Test kiểm tra limits ===")
        print(f"Current limit: {settings.MAX_TOTAL_SCANNERS_PER_WORKFLOW_CHAIN}")
        
        can_continue_a = auto_service._should_continue_workflow_chain("workflow-a")
        can_continue_b = auto_service._should_continue_workflow_chain("workflow-b")
        can_continue_c = auto_service._should_continue_workflow_chain("workflow-c")
        
        print(f"Có thể tiếp tục từ workflow-a: {can_continue_a}")
        print(f"Có thể tiếp tục từ workflow-b: {can_continue_b}")
        print(f"Có thể tiếp tục từ workflow-c: {can_continue_c}")
        
        # Test với limit nhỏ hơn
        print("\\n=== Test với limit = 20 ===")
        original_limit = settings.MAX_TOTAL_SCANNERS_PER_WORKFLOW_CHAIN
        settings.MAX_TOTAL_SCANNERS_PER_WORKFLOW_CHAIN = 20
        
        can_continue_with_limit = auto_service._should_continue_workflow_chain("workflow-c")
        print(f"Có thể tiếp tục với limit 20: {can_continue_with_limit}")  # Expect: False (25 > 20)
        
        # Restore limit
        settings.MAX_TOTAL_SCANNERS_PER_WORKFLOW_CHAIN = original_limit
        
        print("\\n=== Test hoàn thành ===")
        
    finally:
        db.close()

if __name__ == "__main__":
    test_workflow_chain_counting()