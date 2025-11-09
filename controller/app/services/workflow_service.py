# app/services/workflow_service.py
import logging
from uuid import uuid4
import asyncio
from sqlalchemy.orm import Session
from fastapi import HTTPException
import httpx

from app.crud import crud_workflow, crud_scan_job, crud_vpn_profile
from app.schemas import workflow as workflow_schema, scan_job as scan_job_schema
from app.models.workflow_job import WorkflowJob
from app.models.scan_job import ScanJob
from app.core.config import settings
from app.services.vpn_service import VPNService
from app.services.scan_submission_service import ScanSubmissionService

logger = logging.getLogger(__name__)

class WorkflowService:
    def get_workflow_status(self, workflow_id: str):
        db: Session = self.db
        workflow = db.query(WorkflowJob).filter(WorkflowJob.workflow_id == workflow_id).first()
        if not workflow:
            raise HTTPException(status_code=404, detail="Workflow not found")

        # Get sub-jobs
        sub_jobs = db.query(ScanJob).filter(
            ScanJob.workflow_id == workflow_id
        ).order_by(ScanJob.created_at).all()

        # Lấy tổng số phase từ DB
        total_phase = workflow.total_phase or 1

        # Sắp xếp step_order lại cho đúng thứ tự tạo (theo created_at)
        for idx, job in enumerate(sub_jobs, 1):
            job.step_order = idx

        sub_job_list = []
        for job in sub_jobs:
            job_dict = {
                "job_id": job.job_id,
                "tool": job.tool,
                "status": job.status,
                "step_order": job.step_order,
                "workflow_phase": job.workflow_phase
            }
            if getattr(job, "error_message", None):
                job_dict["error_message"] = job.error_message
            sub_job_list.append(job_dict)

        # Progress calculation
        completed = sum(1 for job in sub_jobs if job.status == "completed")
        failed = sum(1 for job in sub_jobs if job.status == "failed")
        total = getattr(workflow, "total_steps", None) or len(sub_jobs)
        percentage = ((completed + failed) / total * 100) if total > 0 else 0

        # Nếu tất cả sub-job đã completed thì cập nhật status workflow
        if completed == total and total > 0:
            workflow.status = "completed"
            db.commit()

        # Compose workflow info
        workflow_info = {
            "workflow_id": workflow.workflow_id,
            "status": workflow.status,
            "updated_at": getattr(workflow, "updated_at", None) or getattr(workflow, "timestamp", None),
            "created_at": getattr(workflow, "created_at", None) or getattr(workflow, "timestamp", None),
            "targets": getattr(workflow, "targets", []),
            "vpn": getattr(workflow, "vpn_country", None),
            "total_phase": total_phase
        }

        return {
            "workflow": workflow_info,
            "sub_jobs": sub_job_list,
            "progress": {
                "completed": completed,
                "total": total,
                "failed": failed,
                "percentage": percentage
            }
        }

    def get_workflow_detail(self, workflow_id: str) -> dict:
        """Lấy chi tiết workflow, sub-jobs, tổng hợp kết quả từng tool (giống code cũ)."""
        db = self.db
        import json
        workflow = db.query(WorkflowJob).filter(WorkflowJob.workflow_id == workflow_id).first()
        if not workflow:
            raise HTTPException(status_code=404, detail="Workflow not found")

        # Tính lại completed_steps, failed_steps, status cho workflow này
        completed = db.query(ScanJob).filter(
            ScanJob.workflow_id == workflow.workflow_id,
            ScanJob.status == "completed"
        ).count()
        failed = db.query(ScanJob).filter(
            ScanJob.workflow_id == workflow.workflow_id,
            ScanJob.status == "failed"
        ).count()
        workflow.completed_steps = completed
        workflow.failed_steps = failed
        if completed + failed >= (workflow.total_steps or 0):
            if failed == 0:
                workflow.status = "completed"
            else:
                workflow.status = "partially_failed"
        elif completed + failed == 0:
            workflow.status = "pending"
        else:
            workflow.status = "running"
        db.commit()

        # Get sub-jobs
        sub_jobs = db.query(ScanJob).filter(
            ScanJob.workflow_id == workflow_id
        ).order_by(ScanJob.step_order).all()

        # Lấy kết quả từng sub-job (ScanResult)
        job_ids = [job.job_id for job in sub_jobs]
        results_by_job = {}
        if job_ids:
            from app.models.scan_result import ScanResult
            scan_results = db.query(ScanResult).filter(
                ScanResult.scan_metadata.op('->>')('job_id').in_(job_ids)
            ).all()
            for r in scan_results:
                meta = r.scan_metadata or {}
                if isinstance(meta, str):
                    try:
                        meta = json.loads(meta)
                    except Exception:
                        meta = {}
                job_id = meta.get('job_id')
                if job_id not in results_by_job:
                    results_by_job[job_id] = []
                # Gắn lại scan_metadata đã parse cho flatten
                r.scan_metadata = meta
                results_by_job[job_id].append(r)

        def nuclei_flatten(find):
            info = find.get('info', {}) or {}
            out = {
                "template": find.get("template"),
                "template-id": find.get("template-id"),
                "template-url": find.get("template-url"),
                "name": info.get("name"),
                "severity": info.get("severity"),
                "tags": info.get("tags"),
                "matched_at": find.get("matched-at"),
                "type": find.get("type"),
                "host": find.get("host"),
                "ip": find.get("ip"),
                "port": find.get("port"),
                "timestamp": find.get("timestamp"),
            }
            extra = {}
            for k, v in find.items():
                if k not in ("template", "template-id", "template-url", "type", "host", "ip", "port", "timestamp", "matched-at", "matcher-status", "info"):
                    extra[k] = v
            for k, v in info.items():
                if k not in ("name", "severity", "tags"):
                    extra[k] = v
            if extra:
                out["extra_fields"] = extra
            return out

        def portscan_flatten(r):
            return [
                {"ip": r.target, "port": p.get("port"), "service": p.get("service"), "protocol": p.get("protocol"), "version": p.get("version", "")}
                for p in (r.open_ports or [])
            ]

        def dns_flatten(r):
            return {"target": r.target, "resolved_ips": r.resolved_ips}

        def httpx_flatten(r):
            meta = r.scan_metadata or {}
            if "httpx_results" in meta:
                return meta["httpx_results"]
            if "http_endpoints" in meta:
                return meta["http_endpoints"]
            if "http_metadata" in meta and isinstance(meta["http_metadata"], dict):
                return [meta["http_metadata"]]
            return []

        def dirsearch_flatten(r):
            meta = r.scan_metadata or {}
            return meta.get("dirsearch_results") or []

        def wpscan_flatten(r):
            meta = r.scan_metadata or {}
            return meta.get("wpscan_results") or []

        def sqlmap_flatten(r):
            meta = r.scan_metadata or {}
            # Kết quả từ sqlmap_scan.py được lưu trong 'sqlmap_results'
            return meta.get("sqlmap_results") or []
        
        def bruteforce_flatten(r):
            meta = r.scan_metadata or {}
            # Kết quả từ bf_runner.py được lưu trong key 'findings'
            return meta.get("findings") or []

        def ffuf_flatten(r):
            meta = r.scan_metadata or {}
            # Kết quả từ ffuf_entry.py
            if meta.get("fuzz_mode") == "param":
                return meta.get("results") or meta.get("candidates") or []
            else:
                return meta.get("results") or meta.get("targets") or []

        tool_result_map = {
            "nuclei-scan": lambda r: [nuclei_flatten(f) for f in (r.scan_metadata.get("nuclei_results") or [])],
            "port-scan": portscan_flatten,
            "dns-lookup": lambda r: [dns_flatten(r)],
            "httpx-scan": httpx_flatten,
            "dirsearch-scan": dirsearch_flatten,
            "wpscan-scan": wpscan_flatten,
            "sqlmap-scan": sqlmap_flatten,
            "bruteforce": bruteforce_flatten,
            "ffuf-entry": ffuf_flatten
        }

        sub_job_details = []
        for job in sub_jobs:
            job_id = job.job_id
            tool = job.tool
            job_results = results_by_job.get(job_id, [])
            results = []
            if tool in tool_result_map:
                for r in job_results:
                    results.extend(tool_result_map[tool](r))
            else:
                for r in job_results:
                    results.append(r.scan_metadata)

            job_detail = {
                "job_id": job_id,
                "tool": tool,
                "status": job.status,
                "step_order": job.step_order,
                "error_message": job.error_message,
                "results": results,
            }
            sub_job_details.append(job_detail)

        total = workflow.total_steps or 0
        percentage = (completed / total * 100) if total > 0 else 0
        return {
            "workflow": workflow,
            "sub_jobs": sub_job_details,
            "progress": {
                "completed": completed,
                "total": total,
                "failed": failed,
                "percentage": percentage
            }
        }
    def __init__(self, db: Session):
        self.db = db
        self.vpn_service = VPNService()
        self.submission_service = ScanSubmissionService()

    async def _assign_vpn_to_workflow(self, workflow_req: workflow_schema.WorkflowRequest) -> dict | None:
        """Gán VPN cho toàn bộ workflow."""
        try:
            # Prefer controller DB state when selecting VPNs so we don't pick
            # profiles that are already marked used/reserved in the controller.
            all_vpns = self.vpn_service.get_available_vpn_profiles(self.db)
            if not all_vpns: return None

            # ✅ Auto-assign VPN dựa vào country preference (nếu có)
            if workflow_req.country:
                categorized = await self.vpn_service.categorize_vpns_by_country(all_vpns)
                vpns_in_country = categorized.get(workflow_req.country.upper())
                return self.vpn_service.get_random_vpn(vpns_in_country) if vpns_in_country else None

            # ✅ Fallback: auto-assign random idle VPN
            return self.vpn_service.get_random_vpn(all_vpns)
        except Exception as e:
            logger.warning(f"Failed to assign VPN for workflow: {e}")
            return None

    async def create_and_dispatch_workflow(self, *, workflow_in: workflow_schema.WorkflowRequest, workflow_id: str = None, workflow_phase: int = None) -> dict:
        """Tạo và thực thi một workflow quét mới hoặc thêm sub-job vào workflow cũ."""

        # Nếu không có targets trong request, lấy từ IP pool
        targets = getattr(workflow_in, "targets", None)
        if not targets or not isinstance(targets, list) or not targets:
            from app.services.ip_pool_service import get_ip_pool_targets
            targets = get_ip_pool_targets(self.db)
            workflow_in.targets = targets
        logger.info(f"Creating/Updating workflow for targets: {workflow_in.targets}")

        # Nếu có workflow_id thì lấy từ DB, không tạo mới
        if workflow_id:
            workflow_db = self.db.query(WorkflowJob).filter(WorkflowJob.workflow_id == workflow_id).first()
            if not workflow_db:
                raise HTTPException(status_code=404, detail="Workflow not found")
            # Nếu workflow đã completed, chuyển về running
            if workflow_db.status in ["completed", "partially_failed"]:
                crud_workflow.update(self.db, db_obj=workflow_db, obj_in={"status": "running"})
            # Tăng total_steps
            old_total = workflow_db.total_steps or 0
            # Tăng total_phase lên mỗi lần có phase mới
            workflow_db.total_phase = (workflow_db.total_phase or 1) + 1
            self.db.commit()
            # Truyền workflow_phase mới nhất vào sub-job
            current_phase = workflow_db.total_phase
        else:
            workflow_id = f"workflow-{uuid4().hex[:8]}"
            workflow_db = crud_workflow.create_workflow(db=self.db, workflow_in=workflow_in, workflow_id=workflow_id)
            old_total = 0
            workflow_db.total_phase = 1
            self.db.commit()
            # Truyền workflow_phase=1 vào sub-job
            current_phase = 1

        # ❌ Bỏ VPN reservation ở workflow level - chỉ reserve ở sub-job level
        vpn_assignment = await self._assign_vpn_to_workflow(workflow_in)

        # Chỉ update workflow metadata mà không reserve VPN
        if vpn_assignment:
            crud_workflow.update(self.db, db_obj=workflow_db, obj_in={
                "vpn_assignment": vpn_assignment, 
                "vpn_profile": vpn_assignment.get('filename'),
                "vpn_country": vpn_assignment.get('country')
            })
            logger.info(f"Assigned VPN {vpn_assignment.get('hostname')} to workflow {workflow_id} (metadata only)")
        else:
            # Fallback: if no idle/unreserved VPN available, assign any VPN (metadata only)
            try:
                all_profiles = crud_vpn_profile.get_all(self.db)
                if all_profiles:
                    # pick the first available in DB (could be improved to random/round-robin)
                    chosen = all_profiles[0]
                    vpn_assignment = {
                        'filename': getattr(chosen, 'filename', None),
                        'hostname': getattr(chosen, 'hostname', None),
                        'country': getattr(chosen, 'country', None)
                    }
                    # ❌ Bỏ force reserve VPN - chỉ update metadata
                    crud_workflow.update(self.db, db_obj=workflow_db, obj_in={
                        "vpn_assignment": vpn_assignment, 
                        "vpn_profile": vpn_assignment.get('filename'),
                        "vpn_country": vpn_assignment.get('country')
                    })
                    logger.info(f"Fallback-assigned VPN {vpn_assignment.get('hostname')} to workflow {workflow_id} (metadata only)")
            except Exception:
                logger.exception("Error during fallback vpn assignment")

        # Truyền workflow_phase khi tạo sub-job
        sub_jobs = self._create_sub_jobs_in_db(workflow_db, workflow_in.steps, vpn_assignment, workflow_phase=current_phase)
        crud_workflow.update(self.db, db_obj=workflow_db, obj_in={"total_steps": old_total + len(sub_jobs)})

        # Track detailed job submission results
        successful_submissions, failed_submissions = [], []
        sub_jobs_details = []
        errors = []
        for job in sub_jobs:
            try:
                scanner_response, _ = self.submission_service.submit_job(job)
                crud_scan_job.update(self.db, db_obj=job, obj_in={"scanner_job_name": scanner_response.get("job_name"), "status": "running"})
                successful_submissions.append(job)
                sub_jobs_details.append({
                    "job_id": job.job_id,
                    "tool": job.tool,
                    "targets": job.targets,
                    "scanner_job": scanner_response.get("job_name"),
                    "workflow_phase": getattr(job, "workflow_phase", None)
                })
            except Exception as e:
                error_message = str(e)
                crud_scan_job.update(self.db, db_obj=job, obj_in={"status": "failed", "error_message": error_message})
                failed_submissions.append(job)
                errors.append({
                    "job_id": job.job_id,
                    "tool": job.tool,
                    "targets": job.targets,
                    "error": error_message,
                    "workflow_phase": getattr(job, "workflow_phase", None)
                })

        status = "running" if successful_submissions else "failed"
        crud_workflow.update(self.db, db_obj=workflow_db, obj_in={"status": status})

        # Format vpn_assignment for response (country, hostname only)
        vpn_assignment_resp = None
        if vpn_assignment:
            vpn_assignment_resp = {
                "country": vpn_assignment.get("country"),
                "hostname": vpn_assignment.get("hostname")
            }

        return {
            "workflow_id": workflow_id,
            "status": status,
            "strategy": getattr(workflow_in, "strategy", None),
            "total_steps": old_total + len(sub_jobs),
            "total_targets": len(getattr(workflow_in, "targets", []) or []),
            "total_tools": len(getattr(workflow_in, "steps", []) or []),
            "successful_submissions": len(successful_submissions),
            "failed_submissions": len(failed_submissions),
            "sub_jobs": sub_jobs_details,
            "errors": errors,
            "vpn_assignment": vpn_assignment_resp
        }

    def _create_sub_jobs_in_db(self, workflow_db: WorkflowJob, steps: list[workflow_schema.WorkflowStep], vpn_assignment: dict | None, workflow_phase: int = None) -> list[ScanJob]:
        """Tạo các bản ghi sub-job trong DB, distribute idle VPNs cho từng sub-job."""
        import os
        from app.utils.port_utils import parse_nmap_top_ports, parse_ports_all, parse_ports_custom, split_ports
        sub_jobs_to_create = []
        step_counter = 0

        # ✅ Lấy pool available VPNs để distribute cho sub-jobs
        available_vpns = self.vpn_service.get_available_vpn_profiles(self.db)
        
        # ✅ Nếu không có VPN idle, lấy VPNs không bị reserved (bao gồm đang in_use)
        if not available_vpns:
            logger.warning("No idle VPNs available, using non-reserved VPNs including busy ones")
            all_vpn_objs = crud_vpn_profile.get_all(self.db)
            available_vpns = []
            
            from datetime import datetime
            now = datetime.utcnow()
            
            for v in all_vpn_objs:
                # ✅ Skip VPNs bị reserved và còn hiệu lực
                reserved_until = getattr(v, 'reserved_until', None)
                if reserved_until:
                    try:
                        if isinstance(reserved_until, str):
                            reserved_dt = datetime.fromisoformat(reserved_until)
                        else:
                            reserved_dt = reserved_until
                    except Exception:
                        reserved_dt = None
                    if reserved_dt and reserved_dt > now:
                        # still reserved -> skip
                        continue
                
                # ✅ Include VPNs không bị reserved (kể cả đang in_use hoặc busy)
                available_vpns.append({
                    'filename': getattr(v, 'filename', None),
                    'hostname': getattr(v, 'hostname', None),
                    'ip': getattr(v, 'ip', None),
                    'country': getattr(v, 'country', None),
                    'status': getattr(v, 'status', 'unknown'),
                    'in_use_by': getattr(v, 'in_use_by', None)
                })
            logger.info(f"Using {len(available_vpns)} non-reserved VPNs (including busy) for sub-job distribution")
        else:
            logger.info(f"Using {len(available_vpns)} idle VPNs for sub-job distribution")
            
        vpn_index = 0  # Index để rotate through available VPNs

        def get_next_vpn(job_id=None):
            """Get next available VPN for sub-job distribution"""
            nonlocal vpn_index
            if not available_vpns:
                logger.warning("No VPNs available for distribution")
                return None
            vpn = available_vpns[vpn_index % len(available_vpns)]
            vpn_index += 1
            
            # ✅ Reserve VPN cho specific sub-job với đúng job_id
            if vpn and vpn.get('filename') and job_id:
                try:
                    reserved = self.vpn_service.reserve_vpn_profile(
                        vpn.get('filename'), 
                        job_id,  # ✅ Chỉ dùng job_id, bỏ prefix "job:"
                        settings.VPN_RESERVATION_TTL, 
                        self.db
                    )
                    if reserved:
                        logger.info(f"Reserved VPN {vpn.get('filename')} for job {job_id}")
                    else:
                        logger.warning(f"Failed to reserve VPN {vpn.get('filename')} for job {job_id}")
                except Exception as e:
                    logger.error(f"Error reserving VPN {vpn.get('filename')} for job {job_id}: {e}")
            
            return vpn

        try:
            for i, step in enumerate(steps):
                # --- Custom logic for port-scan sharding ---
                if step.tool_id == "port-scan":
                    params = step.params.copy() if step.params else {}
                    scanner_count = params.get("scanner_count")
                    port_option = params.get("ports")
                    if scanner_count and int(scanner_count) > 1:
                        base_dir = os.path.dirname(os.path.abspath(__file__))
                        if port_option == "top-1000":
                            port_list = parse_nmap_top_ports(os.path.join(base_dir, "../../data/nmap-ports-top1000.txt"))
                        elif port_option == "all":
                            port_list = list(range(1, 65536))
                        else:
                            port_list = parse_ports_custom(port_option)
                        port_chunks = split_ports(port_list, int(scanner_count))
                        def chunk_to_range(chunk):
                            if not chunk:
                                return ""
                            if chunk == list(range(chunk[0], chunk[-1]+1)):
                                return f"{chunk[0]}-{chunk[-1]}"
                            else:
                                return ",".join(str(p) for p in chunk)
                        # Tạo parent job ID cho sharded jobs
                        parent_job_id = f"scan-port-scan-{uuid4().hex[:6]}-parent"
                        
                        for idx, chunk in enumerate(port_chunks):
                            if not chunk:
                                continue
                            step_counter += 1
                            job_id = f"scan-port-scan-{uuid4().hex[:6]}"
                            chunk_params = params.copy()
                            chunk_params["ports"] = chunk_to_range(chunk)
                            
                            # ✅ Assign VPN riêng cho từng sub-job với đúng job_id
                            job_vpn = get_next_vpn(job_id)
                            job_obj = ScanJob(
                                job_id=job_id,
                                tool=step.tool_id,
                                targets=workflow_db.targets,
                                options=chunk_params,
                                workflow_id=workflow_db.workflow_id,
                                parent_job_id=parent_job_id,  # ✅ Assign parent job ID
                                step_order=step_counter,
                                vpn_profile=job_vpn.get('filename') if job_vpn else None,
                                vpn_country=job_vpn.get('country') if job_vpn else getattr(workflow_db, "vpn_country", None),
                                vpn_assignment=job_vpn,
                                workflow_phase=workflow_phase
                            )
                            job = crud_scan_job.create(self.db, job_obj=job_obj)
                            sub_jobs_to_create.append(job)
                            logger.info(f"Created port-scan sub-job {job_id} chunk {idx+1}/{scanner_count} with VPN {job_vpn.get('filename') if job_vpn else 'None'} ports {chunk_params['ports']}" )
                        continue
                if step.tool_id == "nuclei-scan":
                    params = step.params.copy() if step.params else {}
                    distributed = params.get("distributed-scanning", False)
                    if str(distributed).lower() == "true":
                        templates = params.get("templates", [])
                        severity = params.get("severity", [])
                        if not templates or not severity:
                            pass
                        else:
                            # Tạo parent job ID cho sharded nuclei jobs  
                            parent_job_id = f"scan-nuclei-scan-{uuid4().hex[:6]}-parent"
                            
                            for t in templates:
                                for s in severity:
                                    step_counter += 1
                                    job_id = f"scan-nuclei-scan-{uuid4().hex[:6]}"
                                    job_params = {k: v for k, v in params.items() if k not in ["templates", "severity", "distributed-scanning"]}
                                    job_params["templates"] = [t]
                                    job_params["severity"] = [s]
                                    job_params["distributed-scanning"] = True
                                    
                                    # ✅ Assign VPN riêng cho từng sub-job với đúng job_id
                                    job_vpn = get_next_vpn(job_id)
                                    import json
                                    job_obj = ScanJob(
                                        job_id=job_id,
                                        tool=step.tool_id,
                                        targets=workflow_db.targets,
                                        options=job_params,
                                        workflow_id=workflow_db.workflow_id,
                                        parent_job_id=parent_job_id,  # ✅ Assign parent job ID
                                        step_order=step_counter,
                                        vpn_profile=job_vpn.get('filename') if job_vpn else None,
                                        vpn_country=job_vpn.get('country') if job_vpn else getattr(workflow_db, "vpn_country", None),
                                        vpn_assignment=job_vpn,
                                        workflow_phase=workflow_phase
                                    )
                                    job = crud_scan_job.create(self.db, job_obj=job_obj)
                                    sub_jobs_to_create.append(job)
                                    logger.info(f"Created nuclei-scan sub-job {job_id} template {t} severity {s} with VPN {job_vpn.get('filename') if job_vpn else 'None'}")
                            continue
                step_counter += 1
                job_id = f"scan-{step.tool_id}-{uuid4().hex[:6]}"
                step_params = step.params.copy() if step.params else {}
                if step.tool_id == "dirsearch-scan" and isinstance(step_params, dict):
                    if "threads" in step_params:
                        try:
                            step_params["threads"] = int(step_params["threads"])
                        except Exception:
                            step_params["threads"] = 10
                    if "recursive" in step_params:
                        if step.tool_id == "dirsearch-scan":
                            params = step.params.copy() if step.params else {}
                            scanner_count = params.get("scanner_count")
                            try:
                                scanner_count_int = int(scanner_count) if scanner_count is not None else None
                            except Exception:
                                scanner_count_int = None
                            if scanner_count_int is None or scanner_count_int < 1:
                                raise ValueError("Invalid or missing 'scanner_count' in dirsearch-scan step params. Must be a positive integer.")
                            if scanner_count_int > 1:
                                WORDLIST_LINE_COUNT = 9677
                                lines_per_scanner = WORDLIST_LINE_COUNT // scanner_count_int
                                remainder = WORDLIST_LINE_COUNT % scanner_count_int
                                start_line = 0
                                from app.services.vpn_service import VPNService
                                vpn_service = VPNService()
                                # Pass DB session so we only get idle / not-in-use profiles
                                available_vpns = vpn_service.get_available_vpn_profiles(self.db)
                                
                                # Tạo parent job ID cho sharded dirsearch jobs
                                parent_job_id = f"scan-dirsearch-scan-{uuid4().hex[:6]}-parent"
                                
                                for idx in range(scanner_count_int):
                                    end_line = start_line + lines_per_scanner - 1
                                    if idx < remainder:
                                        end_line += 1
                                    step_counter += 1
                                    job_id = f"scan-dirsearch-scan-{uuid4().hex[:6]}"
                                    chunk_params = params.copy()
                                    chunk_params["wordlist_start"] = start_line
                                    chunk_params["wordlist_end"] = end_line
                                    
                                    # ✅ Assign VPN riêng cho từng sub-job với đúng job_id
                                    job_vpn = get_next_vpn(job_id)
                                    import json
                                    job_obj = ScanJob(
                                        job_id=job_id,
                                        tool=step.tool_id,
                                        targets=workflow_db.targets,
                                        options=chunk_params,
                                        workflow_id=workflow_db.workflow_id,
                                        parent_job_id=parent_job_id,  # ✅ Assign parent job ID
                                        step_order=step_counter,
                                        vpn_profile=job_vpn.get('filename') if job_vpn else None,
                                        vpn_country=job_vpn.get('country') if job_vpn else getattr(workflow_db, "vpn_country", None),
                                        vpn_assignment=job_vpn,
                                        workflow_phase=workflow_phase
                                    )
                                    job = crud_scan_job.create(self.db, job_obj=job_obj)
                                    sub_jobs_to_create.append(job)
                                    logger.info(f"Created dirsearch-scan sub-job {job_id} chunk {idx+1}/{scanner_count_int} with VPN {job_vpn.get('filename') if job_vpn else 'None'} lines {start_line}-{end_line}")
                                    start_line = end_line + 1
                                continue
                        # Single dirsearch job (no sharding)
                        step_counter += 1
                        job_id = f"scan-dirsearch-scan-{uuid4().hex[:6]}"
                        
                        # ✅ Assign VPN riêng cho sub-job với đúng job_id
                        job_vpn = get_next_vpn(job_id)
                        job_obj = ScanJob(
                            job_id=job_id,
                            tool=step.tool_id,
                            targets=workflow_db.targets,
                            options=step.params or {},
                            workflow_id=workflow_db.workflow_id,
                            step_order=step_counter,
                            vpn_profile=job_vpn.get('filename') if job_vpn else None,
                            vpn_country=job_vpn.get('country') if job_vpn else getattr(workflow_db, "vpn_country", None),
                            vpn_assignment=job_vpn,
                            workflow_phase=workflow_phase
                        )
                        job = crud_scan_job.create(self.db, job_obj=job_obj)
                        sub_jobs_to_create.append(job)
                        logger.info(f"Created dirsearch-scan single job {job_id} with auto-assigned VPN")
                        continue
                step_counter += 1
                job_id = f"scan-{step.tool_id}-{uuid4().hex[:6]}"
                step_params = step.params.copy() if step.params else {}
                
                # ✅ Assign VPN riêng cho generic job với đúng job_id
                job_vpn = get_next_vpn(job_id)
                import json
                job_obj = ScanJob(
                    job_id=job_id,
                    tool=step.tool_id,
                    targets=workflow_db.targets,
                    options=step_params,
                    workflow_id=workflow_db.workflow_id,
                    step_order=step_counter,
                    vpn_profile=job_vpn.get('filename') if job_vpn else None,
                    vpn_country=job_vpn.get('country') if job_vpn else getattr(workflow_db, "vpn_country", None),
                    vpn_assignment=job_vpn,
                    workflow_phase=workflow_phase
                )
                job = crud_scan_job.create(self.db, job_obj=job_obj)
                sub_jobs_to_create.append(job)
                logger.info(f"Created generic sub-job {job_id} for tool {step.tool_id} with VPN {job_vpn.get('filename') if job_vpn else 'None'}")
            return sub_jobs_to_create
        except Exception as e:
            logger.error(f"Exception in _create_sub_jobs_in_db: {e}")
            return []
    def _submit_sub_jobs(self, sub_jobs: list[ScanJob]) -> tuple[list, list]:
        """Gửi các sub-job tới scanner node."""
        successful_submissions, failed_submissions = [], []
        for job in sub_jobs:
            try:
                scanner_response, _ = self.submission_service.submit_job(job)
                crud_scan_job.update(self.db, db_obj=job, obj_in={"scanner_job_name": scanner_response.get("job_name"), "status": "running"})
                successful_submissions.append(job.job_id)
            except Exception as e:
                error_message = str(e)
                crud_scan_job.update(self.db, db_obj=job, obj_in={"status": "failed", "error_message": error_message})
                failed_submissions.append({"job_id": job.job_id, "error": error_message})
        return successful_submissions, failed_submissions

    def get_status(self, workflow_id: str) -> dict:
        """Lấy trạng thái chi tiết của một workflow."""
        workflow = crud_workflow.get_workflow_by_id(self.db, workflow_id=workflow_id)
        if not workflow:
            raise HTTPException(status_code=404, detail="Workflow not found")

        sub_jobs = crud_scan_job.get_by_workflow(self.db, workflow_id=workflow_id)

        completed = sum(1 for job in sub_jobs if job.status == "completed")
        failed = sum(1 for job in sub_jobs if job.status == "failed")
        total = workflow.total_steps or len(sub_jobs)
        percentage = ((completed + failed) / total * 100) if total > 0 else 0

        sub_job_list = [
            {"job_id": job.job_id, "tool": job.tool, "status": job.status, "step_order": job.step_order, "error_message": job.error_message}
            for job in sub_jobs
        ]

        workflow_info = {
            "workflow_id": workflow.workflow_id, "status": workflow.status, "updated_at": workflow.updated_at,
            "created_at": workflow.created_at, "targets": workflow.targets,
            "vpn": workflow.vpn_country
        }

        return {
            "workflow": workflow_info,
            "sub_jobs": sub_job_list,
            "progress": {"completed": completed, "total": total, "failed": failed, "percentage": percentage}
        }

    def delete_workflow(self, workflow_id: str) -> dict:
        """Xóa workflow và tất cả các tài nguyên liên quan."""
        workflow = crud_workflow.get_workflow_by_id(self.db, workflow_id=workflow_id)
        if not workflow:
            raise HTTPException(status_code=404, detail="Workflow not found")

        sub_jobs = crud_scan_job.get_by_workflow(self.db, workflow_id=workflow_id)
        deleted_scanner_jobs = []

        for job in sub_jobs:
            if job.scanner_job_name:
                try:
                    resp = httpx.delete(f"{settings.SCANNER_NODE_URL}/api/scanner_jobs/{job.scanner_job_name}", timeout=10)
                    deleted_scanner_jobs.append({"job_id": job.job_id, "scanner_job": job.scanner_job_name, "status_code": resp.status_code})
                except Exception as e:
                    deleted_scanner_jobs.append({"job_id": job.job_id, "scanner_job": job.scanner_job_name, "error": str(e)})

            crud_scan_job.remove_and_related_results(self.db, db_obj=job)

        crud_workflow.remove(self.db, db_obj=workflow)

        logger.info(f"Deleted workflow {workflow_id} and all related resources.")
        return {"status": "deleted", "workflow_id": workflow_id, "deleted_scanner_jobs": deleted_scanner_jobs}
    
    def list_workflows(self, page: int = 1, page_size: int = 10) -> dict:
        """Lấy danh sách workflow, tính lại progress, trả về đúng format dashboard."""
        db = self.db
        from app import schemas as app_schemas
        query = db.query(WorkflowJob).order_by(WorkflowJob.id.desc())
        total = query.count()
        workflows = query.offset((page - 1) * page_size).limit(page_size).all()

        for wf in workflows:
            completed = db.query(ScanJob).filter(
                ScanJob.workflow_id == wf.workflow_id,
                ScanJob.status == "completed"
            ).count()
            failed = db.query(ScanJob).filter(
                ScanJob.workflow_id == wf.workflow_id,
                ScanJob.status == "failed"
            ).count()
            wf.completed_steps = completed
            wf.failed_steps = failed
            if (completed + failed) >= (wf.total_steps or 0):
                if failed == 0:
                    wf.status = "completed"
                else:
                    wf.status = "partially_failed"
            elif (completed + failed) == 0:
                wf.status = "pending"
            else:
                wf.status = "running"
        db.commit()

        def serialize_workflow(wf):
            try:
                return app_schemas.workflow.WorkflowJob.from_orm(wf).dict()
            except Exception:
                return {k: v for k, v in wf.__dict__.items() if not k.startswith('_')}

        return {
            "pagination": {
                "total_items": total,
                "total_pages": (total + page_size - 1) // page_size,
                "current_page": page,
                "page_size": page_size,
                "has_next": (page * page_size) < total,
                "has_previous": page > 1
            },
            "results": [serialize_workflow(wf) for wf in workflows]
        }