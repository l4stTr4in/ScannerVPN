# app/services/scan_job_service.py
import logging
from uuid import uuid4
from sqlalchemy.orm import Session
from fastapi import HTTPException
import httpx
import asyncio

from app.crud import crud_scan_job
from app.schemas import scan_job as scan_job_schema
from app.models.scan_job import ScanJob
from app.core.config import settings
from app.services.vpn_service import VPNService
from app.services.scan_submission_service import ScanSubmissionService

logger = logging.getLogger(__name__)

class ScanJobService:
    def __init__(self, db: Session):
        self.db = db
        self.vpn_service = VPNService()
        self.submission_service = ScanSubmissionService()

    async def _assign_vpn_to_job(self, job_in: scan_job_schema.ScanJobRequest) -> dict | None:
        """Gán VPN cho một job quét đơn lẻ."""
        try:
            # ✅ Sử dụng available VPNs từ DB (idle/unreserved) thay vì fetch từ proxy
            all_vpns = self.vpn_service.get_available_vpn_profiles(self.db)
            if not all_vpns: return None
            
            # ✅ Auto-assign VPN dựa vào country preference (nếu có)
            if job_in.country:
                categorized = await self.vpn_service.categorize_vpns_by_country(all_vpns)
                vpns_in_country = categorized.get(job_in.country.upper())
                return self.vpn_service.get_random_vpn(vpns_in_country) if vpns_in_country else None

            # ✅ Fallback: random từ available VPNs
            return self.vpn_service.get_random_vpn(all_vpns)
        except Exception as e:
            logger.warning(f"Failed to assign VPN for single scan: {e}")
            # Fallback an toàn nếu có lỗi
            return None

    async def create_and_dispatch_scan(self, *, job_in: scan_job_schema.ScanJobRequest) -> ScanJob:
        """Tạo, gán VPN và gửi đi một job quét đơn lẻ."""
        job_id = f"scan-{job_in.tool}-{uuid4().hex[:6]}"

        db_job = ScanJob(
            job_id=job_id, tool=job_in.tool, targets=job_in.targets,
            options=job_in.options, status="submitted",
            vpn_country=job_in.country
        )

        vpn_assignment = await self._assign_vpn_to_job(job_in)
        db_job.vpn_assignment = vpn_assignment
        if vpn_assignment:
            db_job.vpn_profile = vpn_assignment.get('filename')  # Set VPN filename được assign
            db_job.vpn_hostname = vpn_assignment.get('hostname')
            if not db_job.vpn_country: db_job.vpn_country = vpn_assignment.get('country')

        crud_scan_job.create(db=self.db, job_obj=db_job)

        try:
            scanner_response, _ = self.submission_service.submit_job(db_job)
            crud_scan_job.update(self.db, db_obj=db_job, obj_in={
                "scanner_job_name": scanner_response.get("job_name"), "status": "running"
            })
        except Exception as e:
            crud_scan_job.update(self.db, db_obj=db_job, obj_in={"status": "failed", "error_message": str(e)})
            raise HTTPException(status_code=500, detail=f"Failed to submit scan to scanner node: {e}")

        return db_job

    def delete_scan_job(self, job_id: str) -> dict:
        """Xóa một scan job ở cả controller và scanner node."""
        job_db = crud_scan_job.get(db=self.db, job_id=job_id)
        if not job_db:
            raise HTTPException(status_code=404, detail="Scan job not found")

        scanner_job_name = job_db.scanner_job_name
        scanner_node_response = {}
        if scanner_job_name:
            try:
                resp = httpx.delete(f"{settings.SCANNER_NODE_URL}/api/scanner_jobs/{scanner_job_name}", timeout=10)
                scanner_node_response = {"status_code": resp.status_code, "body": resp.text}
            except Exception as e:
                scanner_node_response = {"error": str(e)}

        crud_scan_job.remove_and_related_results(db=self.db, db_obj=job_db)

        return {"status": "deleted", "job_id": job_id, "scanner_job_name": scanner_job_name, "scanner_node_response": scanner_node_response}
    
    def delete_scanner_job_only(self, job_id: str):
        """Xoá pod/job scanner node theo job_id (không xóa DB)."""
        from app.core.config import settings
        db = self.db
        job = self.crud.get_by_job_id(db, job_id=job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Scan job not found")
        scanner_job = getattr(job, "scanner_job_name", None)
        if not scanner_job:
            raise HTTPException(status_code=404, detail="No scanner_job_name found for this job")
        scanner_node_url = settings.SCANNER_NODE_URL
        try:
            resp = httpx.delete(f"{scanner_node_url}/api/scanner_jobs/{scanner_job}", timeout=10)
            if resp.status_code == 404:
                resp_json = {"status": "not found"}
            elif resp.status_code == 200:
                resp_json = resp.json()
            else:
                resp_json = {"error": resp.text}
        except Exception as e:
            resp_json = {"error": str(e)}
        logging.getLogger(__name__).info(f"Called scanner node to delete {scanner_job} for job {job_id}")
        return {"status": "scanner_job_deleted", "job_id": job_id, "scanner_job": scanner_job, "scanner_node_response": resp_json}