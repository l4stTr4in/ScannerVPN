#!/usr/bin/env python3
import json
import subprocess
import sys
import os
import requests
import logging
from vpn_manager import VPNManager

# Configure concise logger (match dns_lookup style)
logger = logging.getLogger("wpscan")
if not logger.handlers:
    h = logging.StreamHandler(stream=sys.stdout)
    h.setFormatter(logging.Formatter("[WPSCAN] %(levelname)s: %(message)s"))
    logger.addHandler(h)
    logger.setLevel(logging.INFO)

def scan_wpscan(url, api_token=None, options=None):
    """
    Execute WPScan với options tùy chỉnh.
    """
    try:
        cmd = ["wpscan", "--url", url, "--format", "json", "--random-user-agent"]
        
        # Thêm API token nếu có
        if api_token:
            cmd += ["--api-token", api_token]
        elif os.getenv("WPSCAN_API_TOKEN"):
            cmd += ["--api-token", os.getenv("WPSCAN_API_TOKEN")]
        
        # Thêm các options khác
        if options:
            # Enumerate option (list -> comma-separated string)
            if options.get("enumerate"):
                enum_val = options["enumerate"]
                if isinstance(enum_val, list):
                    enum_val = ",".join(enum_val)
                cmd += ["--enumerate", enum_val]
            
            # Detection modes
            if options.get("plugins-detection"):
                cmd += ["--plugins-detection", options["plugins-detection"]]
            if options.get("themes-detection"):
                cmd += ["--themes-detection", options["themes-detection"]]
            
            # Boolean flags - check for True value explicitly
            if options.get("disable-tls-checks") is True:
                cmd += ["--disable-tls-checks"]
            if options.get("force") is True:
                cmd += ["--force"]
            
            # Additional options
            if options.get("max-threads"):
                cmd += ["--max-threads", str(options["max-threads"])]
            if options.get("request-timeout"):
                cmd += ["--request-timeout", str(options["request-timeout"])]
            if options.get("connect-timeout"):
                cmd += ["--connect-timeout", str(options["connect-timeout"])]
            if options.get("user-agent"):
                cmd += ["--user-agent", options["user-agent"]]
        
        logger.info("Running WPScan command: %s... (API token hidden)", ' '.join(cmd[:6]))
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        
        # WPScan returns 0 for success, 5 for vulnerabilities found
        if proc.returncode not in (0, 5):
            logger.error("WPScan exited with code %s", proc.returncode)
            logger.error("Stderr: %s", proc.stderr)
            return {}
        
        # Parse JSON result
        if proc.stdout.strip():
            try:
                result = json.loads(proc.stdout)
                logger.info("WPScan completed for %s", url)
                return result
            except json.JSONDecodeError as e:
                logger.error("Failed to parse WPScan JSON output: %s", e)
                logger.debug("WPScan raw output: %s", proc.stdout[:500])
                return {}
        
        return {}
        
    except subprocess.TimeoutExpired:
        logger.warning("WPScan timeout for %s", url)
        return {}
    except Exception as e:
        logger.error("Error running WPScan: %s", e)
        return {}

if __name__ == "__main__":
    logger.info("Starting WPScan with VPN...")
    
    # Setup VPN trước khi scan
    vpn_manager = VPNManager()
    vpn_connected = False
    network_info = {}
    
    # Lấy VPN assignment từ Controller (nếu có)
    assigned_vpn = None
    controller_url = os.getenv("CONTROLLER_CALLBACK_URL")
    vpn_assignment = os.getenv("VPN_ASSIGNMENT")  # VPN được assign từ Controller
    
    if vpn_assignment:
        try:
            assigned_vpn = json.loads(vpn_assignment)
            logger.info("Received VPN assignment from Controller: %s", assigned_vpn.get('hostname', 'Unknown'))
        except json.JSONDecodeError as e:
            logger.warning("Failed to parse VPN assignment: %s", e)
    
    # Thử setup VPN (optional - có thể skip nếu proxy server không available)
    vpn_profile_info = None
    try:
        logger.info("Checking initial network status...")
        initial_info = vpn_manager.get_network_info()
        logger.info("Initial IP: %s", initial_info.get('public_ip'))

        # Sử dụng assigned VPN nếu có, nếu không thì dùng random
        if assigned_vpn:
            meta = vpn_manager.setup_specific_vpn(assigned_vpn)
            if meta:
                logger.info("Connected to assigned VPN: %s", meta.get('hostname', assigned_vpn.get('hostname', 'Unknown')))
                vpn_manager.print_vpn_status()
                network_info = vpn_manager.get_network_info()
                vpn_connected = True
                vpn_profile_info = meta
            else:
                logger.warning("Failed to connect to assigned VPN, trying random...")
        if not vpn_connected:
            logger.info("No VPN assignment from Controller or failed, using random VPN...")
            meta = vpn_manager.setup_random_vpn()
            if meta:
                logger.info("VPN setup completed!")
                vpn_manager.print_vpn_status()
                network_info = vpn_manager.get_network_info()
                vpn_connected = True
                vpn_profile_info = meta
            else:
                logger.warning("VPN connection failed, continuing without VPN...")

        # Gửi thông báo connect VPN về controller nếu kết nối thành công
        if vpn_connected and controller_url and vpn_profile_info:
            try:
                job_id = os.getenv("JOB_ID")
                payload = {
                    "filename": vpn_profile_info.get("filename"),
                    "action": "connect",
                    "scanner_id": job_id
                }
                logger.info("Notify controller: connect %s", payload)
                resp = requests.post(f"{controller_url}/api/vpn_profiles/update", json=payload, timeout=10)
                logger.info("Controller connect response: %s", resp.status_code)
            except Exception as notify_err:
                logger.warning("Failed to notify controller connect: %s", notify_err)
    except Exception as e:
        logger.warning("VPN setup error: %s, continuing without VPN...", e)
    
    try:
        # Đọc targets và options từ environment variables
        targets = os.getenv("TARGETS", "").split(",") if os.getenv("TARGETS") else sys.argv[1:]
        controller_url = os.getenv("CONTROLLER_CALLBACK_URL")
        job_id = os.getenv("JOB_ID")
        workflow_id = os.getenv("WORKFLOW_ID")
        
        # Parse scan options từ environment
        options_str = os.getenv("SCAN_OPTIONS", "{}")
        try:
            options = json.loads(options_str)
        except json.JSONDecodeError:
            options = {}
        
        api_token = options.get("api_token")
        
        logger.info("WPScan starting for targets: %s", targets)
        logger.info("Options: %s", options)
        
        # Scan từng target
        all_results = []
        for target in targets:
            if target.strip():
                logger.info("Scanning %s...", target.strip())
                wp_result = scan_wpscan(target.strip(), api_token, options)
                
                # Extract key information từ WPScan result
                vulnerabilities = []
                if wp_result.get("vulnerabilities"):
                    for vuln_category, vulns in wp_result["vulnerabilities"].items():
                        if isinstance(vulns, list):
                            vulnerabilities.extend(vulns)
                        elif isinstance(vulns, dict):
                            vulnerabilities.append(vulns)
                
                # Format results for Controller
                result = {
                    "target": target.strip(),
                    "wp_scan_result": wp_result,
                    "vulnerabilities": vulnerabilities,
                    "vulnerability_count": len(vulnerabilities),
                    "wordpress_version": wp_result.get("version", {}).get("number") if wp_result.get("version") else None,
                    "theme": wp_result.get("main_theme", {}).get("style_name") if wp_result.get("main_theme") else None
                }
                all_results.append(result)
                logger.info("Found %s vulnerabilities for %s", len(vulnerabilities), target.strip())
        
        # Gửi kết quả về Controller nếu có callback URL
        if controller_url and all_results:
            try:
                for result in all_results:
                    has_findings = bool(result["vulnerabilities"])
                    payload = {
                        "target": result["target"],
                        "workflow_id": workflow_id,
                        "wp_scan_result": result["wp_scan_result"],
                        "vulnerabilities": result["vulnerabilities"],
                        "vulnerability_count": result["vulnerability_count"],
                        "wordpress_version": result["wordpress_version"],
                        "theme": result["theme"],
                        "has_findings": has_findings,
                        "scan_metadata": {
                            "tool": "wpscan-scan",
                            "job_id": job_id,
                            "vpn_used": vpn_connected,
                            "scan_ip": network_info.get("public_ip", "Unknown"),
                            "vpn_local_ip": network_info.get("local_ip"),
                            "tun_interface": network_info.get("tun_interface", False),
                            "scan_options": options,
                            "wpscan_results": result["vulnerabilities"],  # ✅ For AI advisor compatibility
                            "wp_scan_result": result["wp_scan_result"]   # ✅ Keep original for full data
                        }
                    }
                    logger.info("Sending result to Controller: %s", json.dumps(payload))
                    response = requests.post(f"{controller_url}/api/scan_results", json=payload)
                    logger.info("Controller response: %s", response.status_code)
            except Exception as e:
                logger.error("Error sending results to Controller: %s", e)
        
        logger.info("WPScan completed")
        
    finally:
        # Gửi thông báo disconnect VPN về controller nếu đã connect VPN
        if vpn_connected and controller_url and vpn_profile_info:
            try:
                job_id = os.getenv("JOB_ID")
                payload = {
                    "filename": vpn_profile_info.get("filename"),
                    "action": "disconnect",
                    "scanner_id": job_id
                }
                logger.info("Notify controller: disconnect %s", payload)
                resp = requests.post(f"{controller_url}/api/vpn_profiles/update", json=payload, timeout=10)
                logger.info("Controller disconnect response: %s", resp.status_code)
            except Exception as notify_err:
                logger.warning("Failed to notify controller disconnect: %s", notify_err)
        # Cleanup VPN
        if vpn_connected:
            logger.info("Disconnecting VPN...")
            vpn_manager.disconnect_vpn()
