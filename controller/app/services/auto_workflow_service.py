# app/services/auto_workflow_service.py
import logging
import asyncio
import os
from typing import Dict, List, Optional
from sqlalchemy.orm import Session
from app.services.workflow_service import WorkflowService
from app.services.ai_advisor_service import AIAdvisorService
from app.schemas import workflow as workflow_schema
from app.models.scan_result import ScanResult
from app.models.scan_job import ScanJob
from app.core.config import settings

logger = logging.getLogger(__name__)

class AutoWorkflowService:
    def __init__(self, db: Session):
        self.db = db
        self.workflow_service = WorkflowService(db)
        self.ai_advisor = AIAdvisorService()
    
    async def analyze_and_suggest_next_steps(self, workflow_id: str, completed_job_id: str):
        """Phân tích kết quả và tự động tạo bước tiếp theo"""
        
        # Kiểm tra xem auto workflow có enabled không
        if not getattr(settings, 'AUTO_WORKFLOW_ENABLED', True):
            logger.info("Auto workflow is disabled")
            return
        
        # ✅ Kiểm tra để tránh tạo quá nhiều scanners trong workflow chain
        if not self._should_continue_workflow_chain(workflow_id):
            logger.warning(f"Auto workflow stopped for {workflow_id} - reached scanner limits")
            return
        
        try:
            # Lấy thông tin job vừa hoàn thành
            completed_job = self.db.query(ScanJob).filter(
                ScanJob.job_id == completed_job_id
            ).first()
            
            if not completed_job:
                logger.error(f"Job {completed_job_id} not found")
                return
            
            logger.info(f"Analyzing completed job: {completed_job.tool} for targets: {completed_job.targets}")
            
            # Lấy merged results từ tất cả shards (nếu có) thay vì chỉ 1 shard
            from app.services.result_service import ResultService
            result_service = ResultService(self.db)
            
            # Kiểm tra xem tool có hỗ trợ sharding không
            sharded_tools = ["port-scan", "nuclei-scan", "dirsearch-scan"]
            
            if completed_job.tool in sharded_tools:
                logger.info(f"Getting merged results for sharded tool: {completed_job.tool}")
                try:
                    # Lấy merged results với page_size lớn để lấy tất cả
                    merged_data = result_service.get_sub_job_results(
                        sub_job_id=completed_job_id,
                        page=1, 
                        page_size=10000,  # Large enough để lấy all results
                        db=self.db
                    )
                    
                    # Convert merged results sang format AI expect
                    results_data = merged_data.get("results", [])
                    logger.info(f"Got {len(results_data)} merged results from shards for AI analysis")
                    
                except Exception as merge_error:
                    logger.warning(f"Failed to get merged results, fallback to single job: {merge_error}")
                    # Fallback to original logic nếu merge fails
                    scan_results = self.db.query(ScanResult).filter(
                        ScanResult.scan_metadata.op('->>')('job_id') == completed_job_id
                    ).all()
                    results_data = []
                    for result in scan_results:
                        results_data.append({
                            "target": result.target,
                            "open_ports": result.open_ports or [],
                            "scan_metadata": result.scan_metadata or {}
                        })
            else:
                # Non-sharded tools: use original logic
                logger.info(f"Getting single job results for non-sharded tool: {completed_job.tool}")
                scan_results = self.db.query(ScanResult).filter(
                    ScanResult.scan_metadata.op('->>')('job_id') == completed_job_id
                ).all()
                results_data = []
                for result in scan_results:
                    results_data.append({
                        "target": result.target,
                        "open_ports": result.open_ports or [],
                        "scan_metadata": result.scan_metadata or {}
                    })
            
            if not results_data:
                logger.warning(f"No results found for job {completed_job_id}")
                return
            
            # Phân tích cho từng target
            for target in completed_job.targets:
                target_results = [r for r in results_data if r["target"] == target]
                if not target_results:
                    continue
                
                logger.info(f"Analyzing {len(target_results)} results for target {target} from tool {completed_job.tool}")
                
                # Gọi AI để phân tích (với merged data từ tất cả shards)
                ai_analysis = self.ai_advisor.analyze_scan_results(
                    target_results, completed_job.tool, target
                )
                
                if "error" in ai_analysis:
                    logger.error(f"AI analysis failed for {target}: {ai_analysis['error']}")
                    continue
                
                logger.info(f"AI analysis for {target}: {ai_analysis.get('summary', '')}")
                
                # Parse suggestions và tạo workflow steps mới
                suggested_actions = ai_analysis.get("suggested_actions", [])
                
                if suggested_actions:
                    await self._create_follow_up_workflow(
                        workflow_id, 
                        suggested_actions, 
                        [target],  # Chỉ target này
                        ai_analysis,
                        completed_job
                    )
                else:
                    logger.info(f"No actionable suggestions from AI for {target}")
                    
        except Exception as e:
            logger.error(f"Error in auto workflow analysis: {e}", exc_info=True)
    
    async def _create_follow_up_workflow(
        self, 
        original_workflow_id: str, 
        suggestions: List[Dict], 
        targets: List[str],
        ai_analysis: Dict,
        parent_job: ScanJob
    ):
        """Tạo workflow mới dựa trên AI suggestions"""
        
        try:
            steps = []
            for suggestion in suggestions:
                if suggestion["type"] == "run_tool" and suggestion["confidence"] >= 0.5:
                    tool = suggestion["tool"]
                    
                    # Tạo params phù hợp cho từng tool
                    params = self._get_smart_params_for_tool(tool, ai_analysis, parent_job)
                    
                    steps.append(workflow_schema.WorkflowStep(
                        tool_id=tool,
                        params=params
                    ))
            
            if not steps:
                logger.info("No high-confidence suggestions to execute")
                return
            
            # Tạo workflow request (VPN sẽ được tự động gán)
            workflow_request = workflow_schema.WorkflowRequest(
                targets=targets,
                steps=steps,
                parent_workflow_id=original_workflow_id,  # Set workflow cha
                description=f"AI auto-generated follow-up for {parent_job.tool} scan"
            )
            
            # Tạo và dispatch workflow
            result = await self.workflow_service.create_and_dispatch_workflow(
                workflow_in=workflow_request
            )
            
            logger.info(f"Created auto follow-up workflow {result['workflow_id']} with {len(steps)} steps for targets: {targets}")
            
            # Log AI analysis summary
            logger.info(f"AI Analysis Summary: {ai_analysis.get('summary', 'N/A')}")
            
        except Exception as e:
            logger.error(f"Error creating follow-up workflow: {e}", exc_info=True)
    
    def _get_smart_params_for_tool(self, tool: str, ai_analysis: Dict, parent_job: ScanJob) -> Dict:
        """Trả về params thông minh cho từng tool dựa trên AI analysis và parent job"""
        
        base_params = self._get_default_params_for_tool(tool)
        
        # Customize params dựa trên AI analysis và parent job
        ai_response = ai_analysis.get("ai_analysis", "").lower()
        parent_tool = parent_job.tool
        
        if tool == "nuclei-scan":
            # Smart targeting dựa trên parent job và AI analysis
            if parent_tool == "httpx-scan":
                if any(tech in ai_response for tech in ["wordpress", "wp"]):
                    base_params["templates"] = ["cves", "vulnerabilities"]  # Focus on WP vulns
                elif any(tech in ai_response for tech in ["apache", "nginx", "iis"]):
                    base_params["templates"] = ["cves", "default-logins", "exposed-panels"]
                else:
                    base_params["templates"] = ["cves", "vulnerabilities", "exposed-panels"]
            elif parent_tool == "port-scan":
                # Port scan results - focus on service vulns
                base_params["templates"] = ["cves", "default-logins", "vulnerabilities"]
            
            # Severity tuning dựa trên AI assessment
            if "critical" in ai_response or "high" in ai_response:
                base_params["severity"] = ["critical", "high"]
            else:
                base_params["severity"] = ["medium", "high", "critical"]
        
        elif tool == "sqlmap-scan":
            # Smart SQLMap params dựa trên parent
            if parent_tool == "httpx-scan":
                # HTTP endpoints detected - comprehensive testing
                base_params.update({
                    "level": 2,
                    "risk": 2,
                    "batch": True,
                    "random_agent": True,
                    "threads": 1  # Conservative để tránh block
                })
            elif parent_tool == "dirsearch-scan":
                # Directory scan found endpoints - focus testing
                base_params.update({
                    "level": 3,  # Deeper testing
                    "risk": 2,
                    "batch": True,
                    "timeout": 20,
                    "threads": 1
                })
            
            # Technology-specific tuning
            if "php" in ai_response:
                base_params["tamper"] = "between,randomcase"
            elif "mysql" in ai_response:
                base_params["dbms"] = "MySQL"
        
        elif tool == "dirsearch-scan":
            # Smart extension targeting
            if parent_tool == "httpx-scan":
                # HTTPx detected tech stack
                if "php" in ai_response:
                    base_params["extensions"] = ["php", "phps", "php3", "php4", "php5", "phtml", "inc"]
                elif "asp" in ai_response or "iis" in ai_response:
                    base_params["extensions"] = ["asp", "aspx", "ashx", "asmx", "config"]
                elif "java" in ai_response or "jsp" in ai_response:
                    base_params["extensions"] = ["jsp", "jspx", "do", "action", "properties"]
                else:
                    base_params["extensions"] = ["php", "asp", "aspx", "jsp", "html", "js", "txt", "bak", "config"]
            else:
                # Default comprehensive scan
                base_params["extensions"] = ["php", "html", "js", "aspx", "jsp", "txt", "bak"]
            
            # Performance tuning
            base_params.update({
                "threads": 25,  # Balanced performance
                "recursive": False,  # Avoid deep rabbit holes
                "random_agent": True
            })
        
        elif tool == "wpscan-scan":
            # WordPress-specific optimizations
            if parent_tool == "httpx-scan" and "wordpress" in ai_response:
                # Confirmed WP site - aggressive scan
                base_params.update({
                    "enumerate": ["p", "t", "u"],  # plugins, themes, users
                    "plugins-detection": "aggressive",
                    "themes-detection": "aggressive",
                    "max-threads": 8,  # More aggressive
                    "request-timeout": 45   # Shorter timeout for speed
                })
            elif parent_tool == "nuclei-scan":
                # Nuclei found WP vulns - focus enumeration
                base_params.update({
                    "enumerate": ["p", "t"],  # Focus on components
                    "plugins-detection": "passive",
                    "max-threads": 5,  # Balanced
                    "request-timeout": 60
                })
            else:
                # Conservative default
                base_params.update({
                    "enumerate": ["p", "t"],
                    "plugins-detection": "passive",
                    "themes-detection": "passive",
                    "max-threads": 3,  # Conservative
                    "request-timeout": 90,  # Longer timeout for reliability
                    "connect-timeout": 45
                })
            
            # ✅ Auto-inject API token từ config nếu có
            if settings.WPSCAN_API_TOKEN:
                base_params["api_token"] = settings.WPSCAN_API_TOKEN
                logger.info("Auto-injected WPScan API token for AI-generated workflow")
            else:
                logger.warning("No WPScan API token configured - scan will be limited. Set WPSCAN_API_TOKEN environment variable.")
        
        elif tool == "httpx-scan":
            # Smart HTTPx configuration
            if parent_tool == "port-scan":
                # Many ports found - comprehensive HTTP analysis
                base_params.update({
                    "follow_redirects": True,
                    "status_code": True,
                    "tech_detect": True,
                    "title": True,
                    "ip": True,
                    "web_server": True,
                    "content_length": True,
                    "threads": 15  # Balanced performance
                })
            else:
                # Standard HTTP profiling
                base_params.update({
                    "follow_redirects": True,
                    "status_code": True,
                    "tech_detect": True,
                    "title": True,
                    "threads": 10
                })
        
        elif tool == "port-scan":
            # Smart port scanning strategy
            if "web" in ai_response or "http" in ai_response:
                # Focus on web ports
                base_params["ports"] = "80,443,8080,8443,8000,8888"
            elif "database" in ai_response or "db" in ai_response:
                # Focus on database ports  
                base_params["ports"] = "3306,5432,1433,27017,6379,5984"
            else:
                # Comprehensive but efficient
                base_params["ports"] = "top-1000"
            
            base_params.update({
                "scan_type": "-sS",  # Fast SYN scan
                "scanner_count": 5   # Parallel scanning
            })
        
        elif tool == "bruteforce":
            # Smart params cho bruteforce dựa trên parent job
            if parent_tool == "ffuf-entry":
                # FFuf đã tìm thấy login endpoints, focus vào credential testing
                base_params.update({
                    "input_mode": "manual",
                    "strategy": "dictionary", 
                    "protocol": "http_form",
                    "wordlist_source": "builtin",
                    "users_wordlist": "users.txt",
                    "passwords_wordlist": "passwords.txt",
                    "concurrency": 2,
                    "rate_per_min": 15
                })
            elif parent_tool == "port-scan" and any(service in ai_response for service in ["ssh", "ftp"]):
                # Port scan phát hiện service login, set protocol tương ứng
                if "ssh" in ai_response:
                    base_params["protocol"] = "ssh"
                elif "ftp" in ai_response:
                    base_params["protocol"] = "ftp"
                else:
                    base_params["protocol"] = "http_form"
                    
                base_params.update({
                    "input_mode": "manual",
                    "strategy": "dictionary",
                    "wordlist_source": "builtin",
                    "users_wordlist": "users.txt", 
                    "passwords_wordlist": "passwords.txt",
                    "concurrency": 2,
                    "rate_per_min": 8  # Conservative cho network services
                })
            else:
                # Default web-based brute force
                base_params.update({
                    "input_mode": "manual",
                    "strategy": "dictionary",
                    "protocol": "http_form",
                    "wordlist_source": "builtin",
                    "users_wordlist": "users.txt",
                    "passwords_wordlist": "passwords.txt",
                    "concurrency": 2,
                    "rate_per_min": 10
                })
        
        elif tool == "ffuf-entry":
            # Smart params cho ffuf-entry dựa trên parent job
            if parent_tool == "dirsearch-scan" or parent_tool == "httpx-scan":
                # Directory/HTTP scan đã có, focus vào login discovery
                base_params.update({
                    "wordlist": "custom",
                    "custom_wordlist": "admin-panels.txt",
                    "threads": 50,
                    "emit_job": True,  # Tạo job cho bruteforce
                    "bf_strategy": "dictionary",
                    "bf_concurrency": 2,
                    "users_wordlist": "users.txt",
                    "passwords_wordlist": "passwords.txt"
                })
                
                # Nếu AI mention specific technology, customize wordlist
                if "wordpress" in ai_response or "wp" in ai_response:
                    base_params["custom_wordlist"] = "admin-panels.txt"  # Best available for WP
                elif "admin" in ai_response:
                    base_params["custom_wordlist"] = "admin-panels.txt"
            else:
                # Default login discovery
                base_params.update({
                    "wordlist": "default",  # Sử dụng wordlist mặc định
                    "threads": 30,
                    "emit_job": True,
                    "bf_strategy": "dictionary",
                    "bf_concurrency": 2,
                    "users_wordlist": "users.txt",
                    "passwords_wordlist": "passwords.txt"
                })
        
        return base_params
    
    def _get_default_params_for_tool(self, tool: str) -> Dict:
        """Trả về params mặc định tối ưu cho từng tool"""
        defaults = {
            "port-scan": {
                "ports": "top-1000",
                "scan_type": "-sS", 
                "scanner_count": 3  # Balanced parallelism
            },
            "httpx-scan": {
                "method": "GET",
                "timeout": 10,
                "retries": 2,
                "threads": 10,
                "follow_redirects": True,
                "tech_detect": True,
                "title": True,
                "status_code": True,
                "ip": False,
                "web_server": True,
                "content_length": True
            },
            "nuclei-scan": {
                "severity": ["medium", "high", "critical"], 
                "templates": ["cves", "vulnerabilities"],
                "distributed_scanning": False
            },
            "dirsearch-scan": {
                "wordlist": "/app/dicc.txt",
                "extensions": ["php", "html", "js", "aspx", "jsp", "txt", "bak"], 
                "threads": 20,
                "include_status": ["200", "204", "301", "302", "307", "401", "403"],
                "recursive": False,
                "no_extensions": False,
                "scanner_count": 3,
                "random_agent": True
            },
            "sqlmap-scan": {
                "batch": True, 
                "level": 1, 
                "risk": 1,
                "threads": 1,
                "timeout": 20,
                "retries": 2,
                "random_agent": True,
                "identify_waf": False
            },
            "wpscan-scan": {
                "enumerate": ["p", "t"],  # plugins, themes (conservative)
                "plugins-detection": "passive",
                "themes-detection": "passive", 
                "disable-tls-checks": False,
                "force": False,
                "max-threads": 5,
                "request-timeout": 60,
                "connect-timeout": 30
                # Note: api_token sẽ được inject tự động trong _get_smart_params_for_tool
            },
            "bruteforce": {
                "input_mode": "manual",
                "strategy": "dictionary",
                "protocol": "http_form",
                "wordlist_source": "builtin",
                "users_wordlist": "users.txt",
                "passwords_wordlist": "passwords.txt",
                "concurrency": 2,
                "rate_per_min": 10,
                "timeout_sec": 15,
                "stop_on_success": True
            },
            "ffuf-entry": {
                "wordlist": "default",
                "threads": 30,
                "emit_job": True,
                "users_wordlist": "users.txt",
                "passwords_wordlist": "passwords.txt",
                "bf_strategy": "dictionary",
                "bf_concurrency": 2,
                "bf_rate_per_min": 10
            }
        }
        return defaults.get(tool, {})
    
    def _should_continue_workflow_chain(self, workflow_id: str) -> bool:
        """Kiểm tra xem có nên tiếp tục auto workflow không - đếm tổng scanners trong chain"""
        
        # Tìm root workflow (workflow gốc) của chain
        root_workflow_id = self._find_root_workflow(workflow_id)
        
        # Đếm tổng số scanners trong toàn bộ workflow chain 
        total_scanners = self._count_total_scanners_in_chain(root_workflow_id)
        
        # Lấy limit từ config
        max_scanners = getattr(settings, 'MAX_TOTAL_SCANNERS_PER_WORKFLOW_CHAIN', 50)
        
        if total_scanners >= max_scanners:
            logger.warning(f"Workflow chain starting from {root_workflow_id} reached max scanners limit ({total_scanners}/{max_scanners})")
            return False
        
        logger.info(f"Workflow chain can continue: {total_scanners}/{max_scanners} scanners used")
        return True
    
    def _find_root_workflow(self, workflow_id: str) -> str:
        """Tìm workflow gốc (root) của một workflow chain bằng đệ quy"""
        
        from app.models.workflow_job import WorkflowJob
        
        current_workflow_id = workflow_id
        visited = set()  # Tránh infinite loop
        
        while current_workflow_id and current_workflow_id not in visited:
            visited.add(current_workflow_id)
            
            # Lấy workflow hiện tại
            workflow = self.db.query(WorkflowJob).filter(
                WorkflowJob.workflow_id == current_workflow_id
            ).first()
            
            if not workflow or not workflow.parent_workflow_id:
                # Đây là root workflow (không có parent)
                return current_workflow_id
                
            # Di chuyển lên parent workflow
            current_workflow_id = workflow.parent_workflow_id
            
            # Safety limit
            if len(visited) > 20:
                logger.warning("Deep workflow chain detected, stopping search")
                break
        
        return workflow_id  # Fallback
    
    def _count_total_scanners_in_chain(self, root_workflow_id: str) -> int:
        """Đếm tổng số scanners trong toàn bộ workflow chain (bao gồm tất cả child workflows)"""
        
        from app.models.workflow_job import WorkflowJob
        
        # Lấy tất cả workflows trong chain bằng đệ quy
        all_workflow_ids = self._get_all_workflows_in_chain(root_workflow_id)
        
        # Đếm tổng số scan jobs trong tất cả workflows
        total_scanners = 0
        for wf_id in all_workflow_ids:
            scanner_count = self.db.query(ScanJob).filter(
                ScanJob.workflow_id == wf_id
            ).count()
            total_scanners += scanner_count
            logger.debug(f"Workflow {wf_id}: {scanner_count} scanners")
        
        logger.info(f"Total scanners in workflow chain starting from {root_workflow_id}: {total_scanners}")
        return total_scanners
    
    def _get_all_workflows_in_chain(self, root_workflow_id: str) -> List[str]:
        """Lấy tất cả workflow IDs trong chain bằng đệ quy (DFS)"""
        
        from app.models.workflow_job import WorkflowJob
        
        all_workflows = []
        visited = set()
        
        def _collect_workflows(workflow_id: str):
            if workflow_id in visited:
                return
            
            visited.add(workflow_id)
            all_workflows.append(workflow_id)
            
            # Tìm tất cả child workflows
            child_workflows = self.db.query(WorkflowJob).filter(
                WorkflowJob.parent_workflow_id == workflow_id
            ).all()
            
            for child in child_workflows:
                _collect_workflows(child.workflow_id)
        
        _collect_workflows(root_workflow_id)
        return all_workflows