# modules/httpx_scan.py
import subprocess
import json
import os
import sys
import requests
import logging
from vpn_manager import VPNManager

# Configure concise logger (match dns_lookup/dirsearch style)
logger = logging.getLogger("httpx")
if not logger.handlers:
    h = logging.StreamHandler(stream=sys.stdout)
    h.setFormatter(logging.Formatter("[HTTPX] %(levelname)s: %(message)s"))
    logger.addHandler(h)
    logger.setLevel(logging.INFO)

def scan(target, options=None):
    """
    Dùng httpx để quét HTTP:
      - ip, port, service, status-code, headers, protocol
    """
    # httpx đầu ra JSON, mỗi dòng là 1 object
    cmd = [
        'httpx',
        '-silent',
        '-json',
        '-u', target
    ]
    
    # Add options if provided
    if options:
        if options.get("follow_redirects"):
            cmd.append('-fr')
        if options.get("include_response"):
            cmd.append('-include-response')
        if options.get("timeout"):
            cmd.extend(['-timeout', str(options["timeout"])])
        if options.get("retries"):
            cmd.extend(['-retries', str(options["retries"])])
        if options.get("ports"):
            cmd.extend(['-ports', options["ports"]])
        if options.get("status_code"):
            cmd.append('-status-code')
        if options.get("title"):
            cmd.append('-title')
        if options.get("ip"):
            cmd.append('-ip')
        if options.get("web_server") or options.get("server"):
            cmd.append('-web-server')
        if options.get("content_length"):
            cmd.append('-content-length')
        if options.get("tech_detect"):
            cmd.append('-tech-detect')
        if options.get("location"):
            cmd.append('-location')
        if options.get("cname"):
            cmd.append('-cname')
        if options.get("cdn"):
            cmd.append('-cdn')
        if options.get("threads"):
            cmd.extend(['-threads', str(options["threads"])])
        if options.get("method"):
            cmd.extend(['-method', options["method"]])
        if options.get("response_time"):
            cmd.append('-response-time')
        if options.get("content_type"):
            cmd.append('-content-type')
        if options.get("response_size"):
            cmd.append('-response-size')
    
    try:
        logger.info("Running httpx command: %s... %s", ' '.join(cmd[:4]), target)
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        lines = [l for l in proc.stdout.splitlines() if l.strip()]
        
        if not lines:
            logger.warning("No response from httpx for %s", target)
            return {}

        # Parse multiple results if available
        results = []
        for line in lines:
            try:
                data = json.loads(line)
                results.append({
                    'ip': data.get('ip'),
                    'port': data.get('port'),
                    'service': data.get('service'),
                    'responseHeaders': data.get('headers', {}),
                    'statusCode': data.get('status-code') or data.get('status_code'),
                    'protocol': data.get('http-protocol') or data.get('scheme'),
                    'url': data.get('url'),
                    'title': data.get('title'),
                    'content_length': data.get('content-length') or data.get('content_length'),
                    'webserver': data.get('webserver') or data.get('web-server'),
                    'location': data.get('location'),
                    'cname': data.get('cname'),
                    'cdn': data.get('cdn'),
                    'tech': data.get('tech', []),  # tech-detect results
                    'method': data.get('method'),
                    'host': data.get('host'),
                    'path': data.get('path'),
                    'response_time': data.get('response-time') or data.get('response_time'),
                    'content_type': data.get('content-type') or data.get('content_type'),
                    'response_size': data.get('response-size') or data.get('response_size'),
                    'raw': data  # Keep raw data for debugging/completeness
                })
            except json.JSONDecodeError as e:
                logger.error("Failed to parse line: %s, error: %s", line, e)
        
        logger.info("HTTPx scan found %s endpoints for %s", len(results), target)
        return {
            'metadata': results[0] if results else {},
            'all_endpoints': results
        }
        
    except subprocess.TimeoutExpired:
        logger.warning("HTTPx scan timeout for %s", target)
        return {}
    except Exception as e:
        logger.error("Error running httpx scan: %s", e)
        return {}

if __name__ == "__main__":
    logger.info("Starting HTTPx scan with VPN...")
    
    # Setup VPN trước khi scan
    vpn_manager = VPNManager()
    vpn_connected = False
    network_info = {}
    assigned_vpn = None
    controller_url = os.getenv("CONTROLLER_CALLBACK_URL")
    vpn_assignment = os.getenv("VPN_ASSIGNMENT")
    vpn_profile_info = None
    if vpn_assignment:
        try:
            assigned_vpn = json.loads(vpn_assignment)
            logger.info("Received VPN assignment from Controller: %s", assigned_vpn.get('hostname', 'Unknown'))
        except json.JSONDecodeError as e:
            logger.error("Failed to parse VPN assignment: %s", e)
    
    # Thử setup VPN (optional - có thể skip nếu proxy server không available)
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
                # Notify controller: connect
                if controller_url and vpn_profile_info:
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
                        logger.error("Failed to notify controller connect: %s", notify_err)
            else:
                logger.warning("Failed to connect to assigned VPN, trying random...")
                meta = vpn_manager.setup_random_vpn()
                if meta:
                    logger.info("Connected to random VPN as fallback!")
                    vpn_manager.print_vpn_status()
                    network_info = vpn_manager.get_network_info()
                    vpn_connected = True
                    vpn_profile_info = meta
                    if controller_url and vpn_profile_info:
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
                            logger.error("Failed to notify controller connect: %s", notify_err)
        else:
            # Fallback to random VPN nếu không có assignment
            logger.info("No VPN assignment from Controller, using random VPN...")
            meta = vpn_manager.setup_random_vpn()
            if meta:
                logger.info("VPN setup completed!")
                vpn_manager.print_vpn_status()
                network_info = vpn_manager.get_network_info()
                vpn_connected = True
                vpn_profile_info = meta
                if controller_url and vpn_profile_info:
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
                        logger.error("Failed to notify controller connect: %s", notify_err)
    except Exception as e:
        logger.error("VPN setup error: %s, continuing without VPN...", e)
    
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
        
        logger.info("HTTPx scan starting for targets: %s", targets)
        logger.info("Options: %s", options)

        # Scan từng target
        all_results = []
        for target in targets:
            if target.strip():
                logger.info("Scanning %s...", target.strip())
                result = scan(target.strip(), options)
                logger.info("Result for %s: %s endpoints found", target.strip(), len(result.get('all_endpoints', [])))
                all_results.append({
                    "target": target.strip(),
                    "metadata": result.get("metadata", {}),
                    "all_endpoints": result.get("all_endpoints", [])
                })

        # Gửi kết quả về Controller nếu có callback URL
        if controller_url and all_results:
            try:
                for result in all_results:
                    has_findings = bool(result["all_endpoints"])
                    payload = {
                        "target": result["target"],
                        "resolved_ips": [],
                        "open_ports": [],
                        "workflow_id": workflow_id,
                        "http_metadata": result["metadata"],
                        "httpx_results": result["all_endpoints"],  # Keep for backward compatibility
                        "has_findings": has_findings,
                        "scan_metadata": {
                            "tool": "httpx-scan",
                            "job_id": job_id,
                            "vpn_used": vpn_connected,
                            "scan_ip": network_info.get("public_ip", "Unknown"),
                            "vpn_local_ip": network_info.get("local_ip"),
                            "tun_interface": network_info.get("tun_interface", False),
                            "scan_options": options
                        }
                    }
                    logger.info("Sending result to Controller: %s", json.dumps(payload))
                    response = requests.post(f"{controller_url}/api/scan_results", json=payload)
                    logger.info("Controller response: %s", response.status_code)
            except Exception as e:
                logger.error("Error sending results to Controller: %s", e)
        
        logger.info("HTTPx scan completed")

    finally:
        # Notify controller: disconnect
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
                logger.error("Failed to notify controller disconnect: %s", notify_err)
        # Cleanup VPN
        if vpn_connected:
            logger.info("Disconnecting VPN...")
            vpn_manager.disconnect_vpn()
