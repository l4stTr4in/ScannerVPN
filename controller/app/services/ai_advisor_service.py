# app/services/ai_advisor_service.py
import requests
import logging
from typing import Dict, List, Any, Optional
from app.core.config import settings

logger = logging.getLogger(__name__)

class AIAdvisorService:
    def __init__(self):
        self.rag_url = getattr(settings, 'RAG_SERVER_URL', 'http://10.102.199.221:8080')
    
    def analyze_scan_results(self, scan_results: List[Dict], current_tool: str, target: str) -> Dict[str, Any]:
        """Phân tích kết quả scan và đề xuất bước tiếp theo"""
        
        # Tạo summary từ kết quả scan
        summary = self._create_results_summary(scan_results, current_tool, target)
        
        # Tạo câu hỏi cho RAG dựa trên tool hiện tại
        query = self._create_analysis_query(summary, current_tool, target)
        
        try:
            response = requests.post(
                f"{self.rag_url}/rag_query",
                json={"query": query}
                # Không set timeout - để RAG chạy bao lâu cũng được
            )
            response.raise_for_status()
            result = response.json()
            
            ai_answer = result.get("answer", "")
            
            return {
                "ai_analysis": ai_answer,
                "context": result.get("context", ""),
                "suggested_actions": self._parse_suggested_actions(ai_answer, current_tool),
                "summary": summary,
                "confidence": self._calculate_confidence(ai_answer, scan_results)
            }
        except Exception as e:
            logger.error(f"Error calling RAG service: {e}")
            return {"error": str(e), "summary": summary}
    
    def _create_analysis_query(self, summary: str, tool: str, target: str) -> str:
        """Tạo câu hỏi phù hợp cho RAG dựa trên tool và kết quả"""
        
        base_query = f"""
        Tôi đang thực hiện pentest cho target {target} mục tiêu là tìm lỗ hổng và vừa hoàn thành quét bằng {tool}.
        
        Kết quả: {summary}
        
        Dựa trên OWASP Web Security Testing Guide (WSTG), hãy phân tích và đề xuất:
        """
        
        if tool == "port-scan":
            query = base_query + """
            1. Những service nào có thể có lỗ hổng bảo mật
            2. Tool nào nên chạy tiếp theo để test cụ thể (nuclei-scan, httpx-scan, sqlmap-scan, wpscan-scan, dirsearch-scan)
            3. Những WSTG test case nào áp dụng được
            4. Các port/service nào cần ưu tiên test trước
            """
        elif tool == "httpx-scan":
            query = base_query + """
            1. Phân tích các endpoint HTTP đã phát hiện
            2. Technology stack nào đang được sử dụng
            3. Tool nào nên chạy tiếp: nuclei-scan cho vulnerability scan, dirsearch-scan cho directory enumeration, sqlmap-scan cho SQL injection test, wpscan-scan nếu phát hiện WordPress
            4. WSTG test cases nào phù hợp với technology đã phát hiện
            """
        elif tool == "nuclei-scan":
            query = base_query + """
            1. Đánh giá độ nghiêm trọng của các lỗ hổng đã phát hiện
            2. Cần chạy tool gì để khai thác sâu hơn: sqlmap-scan cho SQL injection, dirsearch-scan cho file exposure, wpscan-scan cho WordPress vulnerabilities
            3. Những WSTG test case nào cần verify manual
            4. Lỗ hổng nào cần ưu tiên patch trước
            """
        elif tool == "dirsearch-scan":
            query = base_query + """
            1. Phân tích các file/directory đã phát hiện
            2. File nào có thể chứa thông tin nhạy cảm
            3. Có cần chạy nuclei-scan để test lỗ hổng trên các endpoint mới không
            4. Có file backup, config exposure cần test manual không
            """
        elif tool in ["sqlmap-scan", "wpscan-scan"]:
            query = base_query + """
            1. Đánh giá kết quả test chuyên sâu
            2. Cần verify manual những gì
            3. Có cần chạy thêm tool nào để test vector khác không
            4. Recommendation để fix các issues đã phát hiện
            """
        elif tool == "bruteforce":
            query = base_query + """
            1. Đánh giá kết quả credential testing và brute force attack
            2. Phân tích các credential đã tìm thấy và tác động bảo mật
            3. Cần test manual gì với credentials đã tìm thấy: privilege escalation, lateral movement
            4. Tool nào nên chạy tiếp để khai thác credentials: nuclei-scan để test authenticated vulnerabilities, dirsearch-scan để enumerate với authenticated session
            5. WSTG test cases về authentication bypass, session management cần verify
            6. Các biện pháp defense recommend: account lockout, rate limiting, MFA
            """
        elif tool == "ffuf-entry":
            query = base_query + """
            1. Phân tích các login endpoint và form đã phát hiện
            2. Đánh giá attack surface từ các login interface tìm thấy
            3. Tool nào nên chạy tiếp theo: bruteforce cho credential testing, nuclei-scan để test authentication vulnerabilities, sqlmap-scan nếu phát hiện injection points
            4. WSTG test cases về authentication testing, session management cần thực hiện
            5. Có cần test manual: CSRF, account enumeration, password policy bypass
            6. Priority assessment cho từng login endpoint dựa trên technology stack
            """
        else:
            query = base_query + """
            1. Phân tích tổng quan kết quả
            2. Tool gì nên chạy tiếp theo
            3. WSTG test cases nào còn thiếu
            """
        
        return query
    
    def _create_results_summary(self, scan_results: List[Dict], tool: str, target: str) -> str:
        """Tạo summary ngắn gọn từ kết quả scan"""
        if not scan_results:
            return f"Không có kết quả từ {tool} scan cho {target}"
        
        if tool == "port-scan":
            unique_ports = {}  # Dedupe by (ip, port, protocol)
            total_ports = 0
            
            for result in scan_results:
                ports = result.get('open_ports', [])
                for port in ports:
                    total_ports += 1
                    ip = port.get('ip', '')
                    port_num = port.get('port', '')
                    protocol = port.get('protocol', 'tcp')
                    service = port.get('service', 'unknown')
                    version = port.get('version', '')
                    
                    # Create unique key để avoid duplicates từ shards
                    port_key = f"{ip}:{port_num}/{protocol}"
                    if port_key not in unique_ports:
                        port_info = f"Port {port_num}/{protocol}"
                        if ip and ip != target:
                            port_info = f"{ip}:{port_num}/{protocol}"
                        port_info += f" - {service}"
                        if version:
                            port_info += f" ({version})"
                        unique_ports[port_key] = port_info
            
            port_summaries = list(unique_ports.values())[:15]
            dedup_info = f" (deduplicated từ {total_ports} raw findings)" if total_ports != len(unique_ports) else ""
            return f"Phát hiện {len(unique_ports)} unique ports{dedup_info}: {', '.join(port_summaries)}" + ("..." if len(unique_ports) > 15 else "")
        
        elif tool == "httpx-scan":
            endpoints = []
            technologies = set()
            for result in scan_results:
                httpx_results = result.get('scan_metadata', {}).get('httpx_results', [])
                for ep in httpx_results:
                    url = ep.get('url', '')
                    status = ep.get('status_code', '')
                    tech = ep.get('tech', [])
                    if tech:
                        technologies.update(tech)
                    endpoints.append(f"{url} ({status})")
            
            summary = f"Phát hiện {len(endpoints)} HTTP endpoint: {', '.join(endpoints[:10])}" + ("..." if len(endpoints) > 10 else "")
            if technologies:
                summary += f". Technologies: {', '.join(list(technologies)[:5])}"
            return summary
        
        elif tool == "nuclei-scan":
            unique_vulns = {}  # Dedupe by template-id + target
            severities = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            total_findings = 0
            
            for result in scan_results:
                nuclei_results = result.get('scan_metadata', {}).get('nuclei_results', [])
                target_url = result.get('target', '')
                
                for vuln in nuclei_results:
                    total_findings += 1
                    template_id = vuln.get('template-id', '')
                    severity = vuln.get('info', {}).get('severity', 'info').lower()
                    
                    # Create unique key để avoid duplicates từ shards
                    vuln_key = f"{template_id}:{target_url}"
                    if vuln_key not in unique_vulns:
                        unique_vulns[vuln_key] = {
                            "template_id": template_id,
                            "severity": severity,
                            "target": target_url
                        }
                        severities[severity] = severities.get(severity, 0) + 1
            
            severity_summary = ", ".join([f"{sev}: {count}" for sev, count in severities.items() if count > 0])
            vuln_list = [f"{v['template_id']} ({v['severity']})" for v in list(unique_vulns.values())[:8]]
            
            dedup_info = f" (deduplicated từ {total_findings} raw findings)" if total_findings != len(unique_vulns) else ""
            return f"Nuclei phát hiện {len(unique_vulns)} unique vulnerabilities{dedup_info} - {severity_summary}. Chi tiết: {', '.join(vuln_list)}" + ("..." if len(unique_vulns) > 8 else "")
        
        elif tool == "dirsearch-scan":
            unique_findings = {}  # Dedupe by URL
            status_counts = {}
            total_findings = 0
            
            for result in scan_results:
                dirsearch_results = result.get('scan_metadata', {}).get('dirsearch_results', [])
                for finding in dirsearch_results:
                    total_findings += 1
                    url = finding.get('url', '')
                    status = finding.get('status', '')
                    
                    # Dedupe by URL (same URL from different shards)
                    if url not in unique_findings:
                        unique_findings[url] = status
                        status_counts[status] = status_counts.get(status, 0) + 1
            
            finding_summaries = [f"{url} ({status})" for url, status in list(unique_findings.items())[:10]]
            status_summary = ", ".join([f"{status}: {count}" for status, count in sorted(status_counts.items())])
            
            dedup_info = f" (deduplicated từ {total_findings} raw findings)" if total_findings != len(unique_findings) else ""
            return f"Dirsearch phát hiện {len(unique_findings)} unique paths{dedup_info} ({status_summary}): {', '.join(finding_summaries)}" + ("..." if len(unique_findings) > 10 else "")
        
        elif tool == "sqlmap-scan":
            vulns = []
            for result in scan_results:
                # SQLMap gửi vulnerabilities trong sqlmap_results
                sqlmap_results = result.get('scan_metadata', {}).get('sqlmap_results', [])
                for vuln in sqlmap_results:
                    parameter = vuln.get('parameter', '')
                    vuln_type = vuln.get('type', '')
                    title = vuln.get('title', '')
                    vulns.append(f"{parameter} - {vuln_type} ({title})")
            return f"SQLMap phát hiện {len(vulns)} SQL injection: {', '.join(vulns[:5])}" + ("..." if len(vulns) > 5 else "")
        
        elif tool == "wpscan-scan":
            findings = []
            for result in scan_results:
                wpscan_results = result.get('scan_metadata', {}).get('wpscan_results', [])
                findings.extend([f"{f.get('type', '')}: {f.get('title', '')}" for f in wpscan_results])
            return f"WPScan phát hiện {len(findings)} issues: {', '.join(findings[:5])}" + ("..." if len(findings) > 5 else "")
        
        elif tool == "bruteforce":
            credentials = []
            total_attempts = 0
            for result in scan_results:
                # Bruteforce tool gửi kết quả dưới dạng bruteforce_results.findings
                bf_results = result.get('scan_metadata', {}).get('bruteforce_results', {})
                findings = bf_results.get('findings', [])
                summary = bf_results.get('summary', {})
                
                # Lấy credentials thành công từ findings
                credentials.extend(findings)
                total_attempts += summary.get('tested', 0)
            
            if credentials:
                credential_strs = [f"{c.get('username', '')}:{c.get('password', '')}" for c in credentials]
                return f"Bruteforce thành công {len(credentials)} credential từ {total_attempts} attempts: {', '.join(credential_strs[:3])}" + ("..." if len(credentials) > 3 else "")
            else:
                return f"Bruteforce không tìm thấy credential nào từ {total_attempts} attempts"
        
        elif tool == "ffuf-entry":
            login_endpoints = []
            login_forms = []
            total_candidates = 0
            total_targets = 0
            
            for result in scan_results:
                # FFuf-entry tool gửi kết quả dưới scan_metadata.candidates và targets
                metadata = result.get('scan_metadata', {})
                candidates = metadata.get('candidates', [])
                targets = metadata.get('targets', [])
                
                total_candidates += metadata.get('total_candidates', len(candidates))
                total_targets += metadata.get('total_targets', len(targets))
                
                # Lấy danh sách login endpoints từ candidates (raw URLs)
                for candidate in candidates[:3]:  # Limit to first 3
                    login_endpoints.append(candidate)
                
                # Lấy thông tin login forms từ targets (parsed form data)
                for target in targets[:2]:  # Limit to first 2
                    if isinstance(target, dict) and 'http' in target:
                        url = target['http'].get('url', '')
                        method = target['http'].get('method', 'POST')
                        login_forms.append(f"{method} {url}")
            
            summary_parts = []
            if login_endpoints:
                summary_parts.append(f"{total_candidates} login endpoints: {', '.join(login_endpoints)}")
            if login_forms:
                summary_parts.append(f"{total_targets} login forms: {', '.join(login_forms)}")
            
            if summary_parts:
                return f"FFuf phát hiện {', '.join(summary_parts)}" + ("..." if (len(login_endpoints) > 3 or len(login_forms) > 2) else "")
            else:
                return f"FFuf không phát hiện login endpoint hoặc form nào"
        
        return f"Hoàn thành {tool} scan với {len(scan_results)} kết quả"
    
    def _parse_suggested_actions(self, ai_response: str, current_tool: str) -> List[Dict]:
        """Parse AI response để extract suggested actions"""
        suggestions = []
        response_lower = ai_response.lower()
        
        # Mapping tools với confidence dựa trên context
        tool_keywords = {
            "nuclei-scan": ["nuclei", "vulnerability", "lỗ hổng", "vuln scan", "automated scan"],
            "sqlmap-scan": ["sqlmap", "sql injection", "sqli", "database", "injection"],
            "wpscan-scan": ["wpscan", "wordpress", "wp", "cms"],
            "dirsearch-scan": ["dirsearch", "directory", "thư mục", "file", "enumeration", "brute force"],
            "httpx-scan": ["httpx", "http", "web", "endpoint", "service discovery"],
            "bruteforce": ["bruteforce", "brute force", "credential", "username", "password", "authentication", "login"],
            "ffuf-entry": ["ffuf", "login", "entry", "form", "authentication", "login page", "admin panel"]
        }
        
        # Tránh suggest lại tool vừa chạy
        available_tools = {k: v for k, v in tool_keywords.items() if k != current_tool}
        
        for tool, keywords in available_tools.items():
            confidence = 0.0
            matches = 0
            
            for keyword in keywords:
                if keyword in response_lower:
                    matches += 1
                    confidence += 0.2
            
            # Bonus confidence dựa trên logic workflow
            if current_tool == "port-scan":
                if tool == "httpx-scan" and any(port in response_lower for port in ["80", "443", "8080", "http"]):
                    confidence += 0.3
                elif tool == "nuclei-scan":
                    confidence += 0.2
            elif current_tool == "httpx-scan":
                if tool == "nuclei-scan":
                    confidence += 0.3
                elif tool == "dirsearch-scan":
                    confidence += 0.2
                elif tool == "wpscan-scan" and "wordpress" in response_lower:
                    confidence += 0.4
            elif current_tool == "nuclei-scan":
                if tool == "sqlmap-scan" and ("sql" in response_lower or "injection" in response_lower):
                    confidence += 0.4
                elif tool == "dirsearch-scan" and ("directory" in response_lower or "file" in response_lower):
                    confidence += 0.3
            elif current_tool == "ffuf-entry":
                if tool == "bruteforce" and ("credential" in response_lower or "username" in response_lower or "password" in response_lower):
                    confidence += 0.4
                elif tool == "nuclei-scan" and ("vulnerability" in response_lower or "authentication" in response_lower):
                    confidence += 0.3
                elif tool == "sqlmap-scan" and ("injection" in response_lower or "sql" in response_lower):
                    confidence += 0.3
            elif current_tool == "bruteforce":
                if tool == "nuclei-scan" and ("authenticated" in response_lower or "privilege" in response_lower):
                    confidence += 0.4
                elif tool == "dirsearch-scan" and ("authenticated" in response_lower or "session" in response_lower):
                    confidence += 0.3
            
            # Chỉ suggest nếu confidence > threshold
            if confidence >= 0.3:
                suggestions.append({
                    "type": "run_tool",
                    "tool": tool,
                    "confidence": min(confidence, 1.0),
                    "reason": f"AI detected {matches} relevant keywords for {tool}"
                })
        
        # Sort by confidence
        suggestions.sort(key=lambda x: x["confidence"], reverse=True)
        
        # Limit to top 3 suggestions
        return suggestions[:3]
    
    def _calculate_confidence(self, ai_response: str, scan_results: List[Dict]) -> float:
        """Tính confidence score cho analysis"""
        if not ai_response or not scan_results:
            return 0.0
        
        confidence = 0.5  # Base confidence
        
        # Increase confidence if AI mentions specific tools/technologies
        technical_terms = ["wstg", "owasp", "vulnerability", "security", "test", "scan"]
        for term in technical_terms:
            if term.lower() in ai_response.lower():
                confidence += 0.1
        
        # Increase confidence based on result count
        total_results = sum(len(result.get('open_ports', [])) + 
                          len(result.get('scan_metadata', {}).get('httpx_results', [])) +
                          len(result.get('scan_metadata', {}).get('nuclei_results', [])) 
                          for result in scan_results)
        
        if total_results > 0:
            confidence += min(0.2, total_results * 0.02)
        
        return min(confidence, 1.0)
