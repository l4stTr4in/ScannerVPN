# app/services/result_service.py
import json
import logging
logging.basicConfig(level=logging.INFO)
from fastapi import HTTPException
from sqlalchemy.orm import Session
from app.crud import crud_scan_result, crud_scan_job, crud_workflow, crud_vpn_profile
from app.schemas import scan_result as scan_result_schema
from app.models.scan_result import ScanResult

class ResultService:
    def __init__(self, db: Session):
        self.db = db

    def process_incoming_result(self, result_in: scan_result_schema.ScanResultCreate):
        """Xử lý kết quả do scanner node gửi về, giữ nguyên logic cũ (merge các trường đặc biệt vào scan_metadata, lưu DB, cập nhật job/workflow)."""
        scan_metadata = dict(result_in.scan_metadata) if result_in.scan_metadata else {}
        for k in ["httpx_results", "http_endpoints", "http_metadata"]:
            v = getattr(result_in, k, None)
            if v is not None:
                scan_metadata[k] = v

        db_obj = ScanResult(
            target=result_in.target,
            resolved_ips=result_in.resolved_ips,
            open_ports=result_in.open_ports,
            scan_metadata=scan_metadata,
            workflow_id=result_in.workflow_id
        )
        self.db.add(db_obj)

        job_id = scan_metadata.get('job_id')
        if job_id:
            from app.models.scan_job import ScanJob
            job = self.db.query(ScanJob).filter(ScanJob.job_id == job_id).first()
            if job:
                job.status = "completed"
                if job.workflow_id:
                    crud_workflow.update_workflow_progress(self.db, job.workflow_id, logger=logging.getLogger(__name__))

                    # Chỉ trigger AI/RAG khi tất cả các job trong cùng workflow_phase đã hoàn thành
                    current_phase = getattr(job, "workflow_phase", 1)
                    from app.models.scan_job import ScanJob as ScanJobModel
                    phase_jobs = self.db.query(ScanJobModel).filter(
                        ScanJobModel.workflow_id == job.workflow_id,
                        ScanJobModel.workflow_phase == current_phase
                    ).all()
                    if phase_jobs and all(j.status == "completed" for j in phase_jobs):
                        # Chọn representative job cho AI analysis (prefer parent job hoặc first job)
                        representative_job = None
                        
                        # Tìm parent job (job không có parent_job_id - là job gốc)
                        parent_jobs = [j for j in phase_jobs if not j.parent_job_id]
                        if parent_jobs:
                            # Nếu có parent jobs, chọn cái có step_order nhỏ nhất
                            representative_job = min(parent_jobs, key=lambda x: x.step_order or 0)
                        else:
                            # Nếu tất cả đều là sharded jobs, chọn job có step_order nhỏ nhất
                            jobs_with_step_order = [j for j in phase_jobs if j.step_order is not None]
                            if jobs_with_step_order:
                                representative_job = min(jobs_with_step_order, key=lambda x: x.step_order)
                            else:
                                representative_job = phase_jobs[0]
                        
                        logging.getLogger(__name__).info(
                            f"All {len(phase_jobs)} jobs in phase {current_phase} completed. "
                            f"Triggering AI analysis with representative job: {representative_job.job_id} "
                            f"(parent_job_id: {getattr(representative_job, 'parent_job_id', 'None')}, "
                            f"step_order: {getattr(representative_job, 'step_order', 'None')})"
                        )
                        
                        # Trigger với representative job (AI sẽ merge tất cả results)
                        self._trigger_ai_analysis(job.workflow_id, representative_job.job_id)

        self.db.commit()

    def _trigger_ai_analysis(self, workflow_id: str, job_id: str):
        """Trigger AI analysis cho job vừa hoàn thành"""
        try:
            from app.services.auto_workflow_service import AutoWorkflowService
            from app.core.config import settings
            
            # Chỉ trigger nếu auto workflow được enable
            if not getattr(settings, 'AUTO_WORKFLOW_ENABLED', True):
                return
            
            # Chạy AI analysis trong background
            import asyncio
            import threading
            
            def run_ai_analysis():
                loop = None
                thread_db = None
                try:
                    # Tạo event loop mới cho thread
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    
                    # Tạo session mới cho thread này
                    from app.db.session import SessionLocal
                    thread_db = SessionLocal()
                    
                    auto_service = AutoWorkflowService(thread_db)
                    loop.run_until_complete(
                        auto_service.analyze_and_suggest_next_steps(workflow_id, job_id)
                    )
                    
                except Exception as e:
                    logging.getLogger(__name__).error(f"AI analysis thread failed: {e}", exc_info=True)
                finally:
                    # ✅ Proper cleanup to prevent memory leaks
                    if thread_db:
                        thread_db.close()
                    if loop:
                        try:
                            loop.close()
                        except Exception as cleanup_error:
                            logging.getLogger(__name__).warning(f"Loop cleanup failed: {cleanup_error}")
            
          
            thread = threading.Thread(target=run_ai_analysis, daemon=True)
            thread.start()
            
            logging.getLogger(__name__).info(f"Started AI analysis thread for workflow {workflow_id}, job {job_id}")
            
        except Exception as e:
            logging.getLogger(__name__).error(f"Failed to trigger AI analysis: {e}", exc_info=True)

    # Đã chuyển logic update workflow progress sang crud_workflow.update_workflow_progress

    def get_paginated_results(self, page: int, page_size: int, workflow_id: str | None = None, job_id: str | None = None):
        """Lấy danh sách kết quả có phân trang."""
        return crud_scan_result.get_multi_paginated(
            db=self.db, page=page, page_size=page_size, workflow_id=workflow_id, job_id=job_id
        )

    def get_workflow_summary(self, workflow_id: str):
        """Tổng hợp kết quả của toàn bộ workflow."""
        workflow = crud_workflow.get_workflow_by_id(self.db, workflow_id=workflow_id)
        if not workflow:
            raise HTTPException(status_code=404, detail="Workflow not found")

        sub_jobs = crud_scan_job.get_by_workflow(self.db, workflow_id=workflow_id)
        job_ids = [job.job_id for job in sub_jobs]

        scan_results = self.db.query(ScanResult).filter(
            ScanResult.scan_metadata.op('->>')('job_id').in_(job_ids)
        ).all()

        summary_by_target = {}
        for r in scan_results:
            tgt = r.target
            if tgt not in summary_by_target:
                summary_by_target[tgt] = {
                    "target": tgt, 
                    "dns_records": [], 
                    "open_ports": [], 
                    "web_technologies": set(), 
                    "vulnerabilities": [], 
                    "dirsearch_results": []
                }
            if r.resolved_ips:
                summary_by_target[tgt]["dns_records"].extend(r.resolved_ips)
            if r.open_ports:
                for p in r.open_ports:
                    summary_by_target[tgt]["open_ports"].append({ "port": p.get("port"), "protocol": p.get("protocol"), "service": p.get("service") })

            meta = r.scan_metadata or {}
            if isinstance(meta, str):
                try: meta = json.loads(meta)
                except Exception: meta = {}

            if "httpx_results" in meta:
                    # Tạo object summary cho từng url
                    httpx_objs = []
                    for ep in meta["httpx_results"]:
                        obj = {
                            "url": ep.get("url"),
                            "host": ep.get("host"),
                            "port": int(ep.get("port")) if ep.get("port") else None,
                            "scheme": ep.get("protocol"),
                            "webserver": ep.get("webserver"),
                            "tech": ep.get("tech"),
                            "status_code": ep.get("statusCode"),
                            "title": ep.get("title"),
                            "content_length": ep.get("content_length")
                        }
                        httpx_objs.append(obj)
                        ws = ep.get("webserver")
                        if ws: summary_by_target[tgt]["web_technologies"].add(ws)
                    # Gán vào summary
                    summary_by_target[tgt]["httpx_summary"] = httpx_objs
            if "nuclei_results" in meta:
                for finding in meta["nuclei_results"]:
                    info = finding.get("info", {})
                    name = finding.get("name") or info.get("name")
                    sev = finding.get("severity") or info.get("severity")
                    if name and sev: summary_by_target[tgt]["vulnerabilities"].append({"name": name, "severity": sev})
            # Merge dirsearch_results
            if "dirsearch_results" in meta:
                summary_by_target[tgt]["dirsearch_results"].extend(meta["dirsearch_results"])

        for tgt in summary_by_target:
            summary_by_target[tgt]["web_technologies"] = list(summary_by_target[tgt]["web_technologies"])

        return {"summary": list(summary_by_target.values())}
    
    def get_sub_job_results(self, sub_job_id: str, page: int, page_size: int, db: Session):
        """Lấy kết quả của sub-job, nếu là port-scan chia nhỏ thì merge kết quả các sub-job cùng nhóm."""
        from app.models.scan_job import ScanJob
        from app.models.scan_result import ScanResult
        job = db.query(ScanJob).filter(ScanJob.job_id == sub_job_id).first()
        if not job:
            raise HTTPException(status_code=404, detail="Scan job not found")

        logging.getLogger(__name__).debug(f"Job tool: {job.tool}, workflow_id: {job.workflow_id}")
        
        # Nếu là port-scan và thuộc workflow, thực hiện merge kết quả các sub-job cùng nhóm
        if job.tool == "port-scan" and job.workflow_id:
            sub_jobs = db.query(ScanJob).filter(
                ScanJob.workflow_id == job.workflow_id,
                ScanJob.tool == "port-scan",
                ScanJob.targets == job.targets
            ).all()
            job_ids = [j.job_id for j in sub_jobs]
            scan_results = db.query(ScanResult).filter(
                ScanResult.scan_metadata.op('->>')('job_id').in_(job_ids)
            ).all()
            # Merge open_ports
            merged_ports = []
            seen = set()
            for r in scan_results:
                for p in (r.open_ports or []):
                    key = (p.get("ip"), p.get("port"), p.get("protocol", "tcp"))
                    if key not in seen:
                        seen.add(key)
                        merged_ports.append(p)
            total = len(merged_ports)
            start = (page - 1) * page_size
            end = start + page_size
            return {
                "pagination": {
                    "total_items": total,
                    "total_pages": (total + page_size - 1) // page_size,
                    "current_page": page,
                    "page_size": page_size,
                    "has_next": end < total,
                    "has_previous": page > 1
                },
                "results": merged_ports[start:end]
            }
            
        # Nếu là dirsearch-scan và thuộc workflow, thực hiện merge dirsearch_results của tất cả sub-job dirsearch-scan cùng workflow
        if job.tool == "dirsearch-scan" and job.workflow_id:
            logging.getLogger(__name__).debug(f"Merging dirsearch results for workflow {job.workflow_id}")
            sub_jobs = db.query(ScanJob).filter(
                ScanJob.workflow_id == job.workflow_id,
                ScanJob.tool == "dirsearch-scan"
            ).all()
            logging.getLogger(__name__).debug(f"Found {len(sub_jobs)} dirsearch sub-jobs in workflow")
            job_ids = [j.job_id for j in sub_jobs]
            scan_results = db.query(ScanResult).filter(
                ScanResult.scan_metadata.op('->>')('job_id').in_(job_ids)
            ).all()
            logging.getLogger(__name__).debug(f"Found {len(scan_results)} scan results to merge")
            # Merge dirsearch_results
            all_findings = []
            for r in scan_results:
                meta = r.scan_metadata or {}
                if isinstance(meta, str):
                    import json
                    try:
                        meta = json.loads(meta)
                    except Exception:
                        meta = {}
                dirsearch_results = meta.get("dirsearch_results") or []
                all_findings.extend(dirsearch_results)
            total = len(all_findings)
            start = (page - 1) * page_size
            end = start + page_size
            merged_result = {
                "target": job.targets[0] if hasattr(job, "targets") and job.targets else None,
                "resolved_ips": getattr(job, "resolved_ips", []),
                "open_ports": getattr(job, "open_ports", []),
                "scan_metadata": {
                    "tool": "dirsearch-scan",
                    "job_id": sub_job_id,
                    "vpn_used": job.vpn_profile is not None,
                    "scan_ip": getattr(job, "scan_ip", "Unknown"),
                    "vpn_local_ip": getattr(job, "vpn_local_ip", None),
                    "tun_interface": getattr(job, "tun_interface", False),
                    "dirsearch_results": all_findings[start:end],
                    "total_findings": total
                }
            }
            return {
                "pagination": {
                    "total_items": total,
                    "total_pages": (total + page_size - 1) // page_size,
                    "current_page": page,
                    "page_size": page_size,
                    "has_next": end < total,
                    "has_previous": page > 1
                },
                "results": [merged_result]
            }
        # Nếu là nuclei-scan và thuộc workflow, thực hiện merge nuclei_results của tất cả sub-job nuclei-scan cùng workflow
        if job.tool == "nuclei-scan" and job.workflow_id:
            sub_jobs = db.query(ScanJob).filter(
                ScanJob.workflow_id == job.workflow_id,
                ScanJob.tool == "nuclei-scan"
            ).all()
            job_ids = [j.job_id for j in sub_jobs]
            scan_results = db.query(ScanResult).filter(
                ScanResult.scan_metadata.op('->>')('job_id').in_(job_ids)
            ).all()
            # Merge nuclei_results
            all_findings = []
            for r in scan_results:
                nuclei_results = []
                meta = r.scan_metadata or {}
                if isinstance(meta, str):
                    import json
                    try:
                        meta = json.loads(meta)
                    except Exception:
                        meta = {}
                nuclei_results = meta.get("nuclei_results") or []
                all_findings.extend(nuclei_results)
            total = len(all_findings)
            start = (page - 1) * page_size
            end = start + page_size
            merged_result = {
                "target": job.targets[0] if hasattr(job, "targets") and job.targets else None,
                "resolved_ips": getattr(job, "resolved_ips", []),
                "open_ports": getattr(job, "open_ports", []),
                "scan_metadata": {
                    "tool": "nuclei-scan",
                    "job_id": sub_job_id,
                    "vpn_used": job.vpn_profile is not None,
                    "scan_ip": getattr(job, "scan_ip", "Unknown"),
                    "vpn_local_ip": getattr(job, "vpn_local_ip", None),
                    "tun_interface": getattr(job, "tun_interface", False),
                    "nuclei_results": all_findings[start:end]
                }
            }
            return {
                "pagination": {
                    "total_items": total,
                    "total_pages": (total + page_size - 1) // page_size,
                    "current_page": page,
                    "page_size": page_size,
                    "has_next": end < total,
                    "has_previous": page > 1
                },
                "results": [merged_result]
            }
        # Nếu không phải port-scan chia nhỏ, trả về như cũ (lấy kết quả sub-job này, phân trang)
        scan_results = db.query(ScanResult).filter(
            ScanResult.scan_metadata.op('->>')('job_id') == sub_job_id
        ).all()
        total = len(scan_results)
        start = (page - 1) * page_size
        end = start + page_size
        results = []
        for r in scan_results[start:end]:
            result = {
                "target": r.target,
                "resolved_ips": r.resolved_ips,
                "open_ports": r.open_ports,
                "scan_metadata": r.scan_metadata
            }
            results.append(result)
        return {
            "pagination": {
                "total_items": total,
                "total_pages": (total + page_size - 1) // page_size,
                "current_page": page,
                "page_size": page_size,
                "has_next": end < total,
                "has_previous": page > 1
            },
            "results": results
        }
