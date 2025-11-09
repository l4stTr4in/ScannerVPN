# app/services/scan_submission_service.py
import httpx
import logging
import json
from typing import Dict, Any, Tuple
from app.core.config import settings
from app.models.scan_job import ScanJob

logger = logging.getLogger(__name__)

class ScanSubmissionService:
    def prepare_tool_scan_options(self, tool_id: str, raw_options: Dict[str, Any]) -> Dict[str, Any]:
        """
        Chuẩn bị scan options sạch cho từng tool, xử lý conditional logic
        """
        if tool_id == "bruteforce":
            return self._prepare_bruteforce_options(raw_options)
        elif tool_id == "ffuf-entry":
            return self._prepare_ffuf_options(raw_options)
        else:
            # Các tool khác pass through bình thường
            return raw_options
    
    def _prepare_bruteforce_options(self, options: Dict[str, Any]) -> Dict[str, Any]:
        """
        Xử lý conditional logic cho bruteforce tool
        """
        input_mode = options.get("input_mode", "manual")
        
        if input_mode == "job_json":
            # Chỉ truyền job_json_content, loại bỏ tất cả manual fields
            job_json_content = options.get("job_json_content", "")
            if not job_json_content.strip():
                logger.warning("Bruteforce job_json mode but job_json_content is empty, falling back to manual")
                return self._extract_manual_fields(options)
            
            clean_options = {
                "job_json_content": job_json_content
            }
            logger.info("Bruteforce: Using job JSON mode, manual fields filtered out")
            return clean_options
            
        else:  # manual mode
            # Loại bỏ job_json_content, chỉ giữ manual fields
            clean_options = self._extract_manual_fields(options)
            logger.info("Bruteforce: Using manual mode, job_json_content filtered out")
            return clean_options
    
    def _extract_manual_fields(self, options: Dict[str, Any]) -> Dict[str, Any]:
        """
        Trích xuất manual fields cho bruteforce, loại bỏ job_json_content
        """
        manual_fields = [
            "input_mode", "strategy", "protocol", "login_url", "username_field", 
            "password_field", "csrf_token_selector", "success_indicator", "success_text",
            "concurrency", "rate_per_min", "timeout_sec", "jitter_ms", "stop_on_success",
            "wordlist_source", "users_wordlist", "passwords_wordlist", "pairs_wordlist",
            "users_list", "passwords_list", "pairs_list"
        ]
        
        clean_options = {}
        for field in manual_fields:
            if field in options and options[field] is not None:
                clean_options[field] = options[field]
        
        return clean_options
    
    def _prepare_ffuf_options(self, options: Dict[str, Any]) -> Dict[str, Any]:
        """
        Xử lý conditional logic cho ffuf-entry tool
        Chỉ gửi emit_job parameters nếu emit_job = true
        """
        emit_job = options.get("emit_job", False)
        
        # Danh sách các fields chỉ cần khi emit_job = true
        emit_job_fields = [
            "users_wordlist", "passwords_wordlist", "pairs_wordlist",
            "bf_strategy", "bf_concurrency", "bf_rate_per_min", 
            "bf_jitter", "bf_timeout_sec", "bf_stop_on_success"
        ]
        
        if emit_job:
            # Gửi tất cả parameters (bao gồm emit_job fields)
            logger.info("FFUF: emit_job=true, sending all parameters including bruteforce config")
            return options
        else:
            # Chỉ gửi FFUF scan parameters, loại bỏ emit_job fields
            clean_options = {
                k: v for k, v in options.items() 
                if k not in emit_job_fields
            }
            logger.info(f"FFUF: emit_job=false, filtered out {len(emit_job_fields)} bruteforce parameters")
            return clean_options

    def submit_job(self, job: ScanJob) -> Tuple[Dict[str, Any], Dict[str, Any] | None]:
        """
        Gửi một sub-job tới Scanner Node API và trả về phản hồi.
        """
        # VPN assignment được lấy từ bản ghi job trong DB
        vpn_assignment = job.vpn_assignment
        # Đảm bảo vpn_assignment là Dict, không phải str
        if isinstance(vpn_assignment, str):
            try:
                vpn_assignment = json.loads(vpn_assignment)
            except Exception:
                vpn_assignment = None
        if not vpn_assignment and job.vpn_profile: # Fallback nếu chưa gán vpn
            vpn_assignment = {"filename": job.vpn_profile, "country": job.vpn_country}

        # Đảm bảo job.options là Dict, không phải str
        raw_options = job.options
        if isinstance(raw_options, str):
            try:
                raw_options = json.loads(raw_options)
            except Exception:
                raw_options = {}
        
        # XỬ LÝ MỚI: Clean options theo tool-specific logic
        options = self.prepare_tool_scan_options(job.tool, raw_options)
        payload = {
            "tool": job.tool,
            "targets": job.targets,
            "options": options,
            "job_id": job.job_id,
            "controller_callback_url": settings.CONTROLLER_CALLBACK_URL,
            "vpn_assignment": vpn_assignment,
            "workflow_id": job.workflow_id
        }

        logger.info(f"Submitting job {job.job_id} to scanner node at {settings.SCANNER_NODE_URL}")
        logging.getLogger(__name__).debug("Payload gửi sang scanner-node-api:")
        print(payload)

        try:
            response = httpx.post(
                f"{settings.SCANNER_NODE_URL}/api/scan/execute",
                json=payload,
                timeout=30
            )
            response.raise_for_status()
            logger.info(f"Successfully submitted job {job.job_id}. Response: {response.json()}")
            return response.json(), vpn_assignment
        except httpx.RequestError as e:
            logger.error(f"HTTP error submitting job {job.job_id}: {e}")
            raise Exception(f"Failed to connect to scanner node: {e}")
        except Exception as e:
            logger.error(f"An unexpected error occurred while submitting job {job.job_id}: {e}")
            raise