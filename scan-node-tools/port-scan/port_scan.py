# modules/port_scan.py
import subprocess, tempfile, os, xml.etree.ElementTree as ET
import sys
import json
import requests
import logging
from vpn_manager import VPNManager

# Configure concise logger (match dns_lookup style)
logger = logging.getLogger("portscan")
if not logger.handlers:
    h = logging.StreamHandler(stream=sys.stdout)
    h.setFormatter(logging.Formatter("[PORT] %(levelname)s: %(message)s"))
    logger.addHandler(h)
    logger.setLevel(logging.INFO)

def scan(target, options=None):
    """
    Dùng nmap SYN scan top 1000 ports.
    Trả về {'open_ports': [port,…]}
    """
    # Parse options for port scanning
    ports = "1000"  # default
    scan_type = "-sS"  # default SYN scan
    # Default timeouts
    default_timeout = 300
    full_scan_timeout = 900
    # Allow override via options or env
    if options:
        # Nếu có 'ports' thì ưu tiên, kể cả khi all_ports=true
        if options.get("ports"):
            ports = options["ports"]
        if options.get("scan_type"):
            scan_type = options["scan_type"]
        # Nếu all_ports=true nhưng không có 'ports', mới quét all
        if options.get("all_ports") and not options.get("ports"):
            ports = "-"  # scan all ports
        if options.get("timeout"):
            try:
                default_timeout = int(options["timeout"])
                full_scan_timeout = int(options["timeout"])
            except Exception:
                pass
    # Allow override via env
    env_timeout = os.getenv("PORTSCAN_TIMEOUT")
    if env_timeout:
        try:
            default_timeout = int(env_timeout)
            full_scan_timeout = int(env_timeout)
        except Exception:
            pass
    # Thử SYN scan trước, nếu fail thì fallback sang TCP connect scan
    temp_fd, temp_path = tempfile.mkstemp(suffix='.xml')
    os.close(temp_fd)
    # Choose timeout
    timeout = full_scan_timeout if ports == "-" else default_timeout
    try:
        # Thử scan type được chỉ định (cần root cho SYN scan)
        # Nếu ports là dạng range (vd: '1-5000'), hoặc list, hoặc chuỗi số, đều truyền đúng cho nmap
        if ports == "-":
            cmd = ['nmap', scan_type, '-p-', '-oX', temp_path, target]
        elif ports.isdigit() and str(ports).startswith('top-'):
            # Chỉ dùng --top-ports nếu có prefix 'top-'
            top_count = ports.replace('top-', '')
            cmd = ['nmap', scan_type, '--top-ports', top_count, '-oX', temp_path, target]
        elif ports.isdigit():
            # Single port number - use -p instead of --top-ports
            cmd = ['nmap', scan_type, '-p', str(ports), '-oX', temp_path, target]
        elif '-' in str(ports) and all(x.isdigit() for x in str(ports).replace('-',',').split(',')):
            # Nếu là range, truyền nguyên cho nmap
            cmd = ['nmap', scan_type, '-p', str(ports), '-oX', temp_path, target]
        else:
            cmd = ['nmap', scan_type, '-p', str(ports), '-oX', temp_path, target]
        logger.info("Running nmap command: %s (timeout=%ss)", ' '.join(cmd), timeout)
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout)
    except subprocess.TimeoutExpired:
        logger.warning("Nmap command timed out after %s s: %s", timeout, ' '.join(cmd))
        # Fallback sang TCP connect scan (không cần root)
        try:
            if ports == "-":
                cmd = ['nmap', '-sT', '-p-', '-oX', temp_path, target]
            elif ports.isdigit() and str(ports).startswith('top-'):
                # Chỉ dùng --top-ports nếu có prefix 'top-'
                top_count = ports.replace('top-', '')
                cmd = ['nmap', '-sT', '--top-ports', top_count, '-oX', temp_path, target]
            elif ports.isdigit():
                # Single port number - use -p instead of --top-ports
                cmd = ['nmap', '-sT', '-p', str(ports), '-oX', temp_path, target]
            elif '-' in str(ports) and all(x.isdigit() for x in str(ports).replace('-',',').split(',')):
                cmd = ['nmap', '-sT', '-p', str(ports), '-oX', temp_path, target]
            else:
                cmd = ['nmap', '-sT', '-p', str(ports), '-oX', temp_path, target]
            logger.info("Running fallback nmap command: %s (timeout=%ss)", ' '.join(cmd), timeout)
            subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout)
        except subprocess.TimeoutExpired:
            logger.warning("Fallback nmap command timed out after %s s: %s", timeout, ' '.join(cmd))
            os.remove(temp_path)
            return {'open_ports': []}
        except Exception as e:
            logger.error("Both scan methods failed: %s", e)
            os.remove(temp_path)
            return {'open_ports': []}
    except subprocess.CalledProcessError as e:
        logger.error("Nmap command failed: %s", e)
        # Fallback sang TCP connect scan (không cần root)
        try:
            if ports == "-":
                cmd = ['nmap', '-sT', '-p-', '-oX', temp_path, target]
            elif ports.isdigit() and str(ports).startswith('top-'):
                # Chỉ dùng --top-ports nếu có prefix 'top-'
                top_count = ports.replace('top-', '')
                cmd = ['nmap', '-sT', '--top-ports', top_count, '-oX', temp_path, target]
            elif ports.isdigit():
                # Single port number - use -p instead of --top-ports
                cmd = ['nmap', '-sT', '-p', str(ports), '-oX', temp_path, target]
            elif '-' in str(ports) and all(x.isdigit() for x in str(ports).replace('-',',').split(',')):
                cmd = ['nmap', '-sT', '-p', str(ports), '-oX', temp_path, target]
            else:
                cmd = ['nmap', '-sT', '-p', str(ports), '-oX', temp_path, target]
            logger.info("Running fallback nmap command: %s (timeout=%ss)", ' '.join(cmd), timeout)
            subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout)
        except subprocess.TimeoutExpired:
            logger.warning("Fallback nmap command timed out after %s s: %s", timeout, ' '.join(cmd))
            os.remove(temp_path)
            return {'open_ports': []}
        except Exception as e:
            logger.error("Both scan methods failed: %s", e)
            os.remove(temp_path)
            return {'open_ports': []}

    # parse XML
    try:
        tree = ET.parse(temp_path)
        os.remove(temp_path)
        ports_found = []
        for p in tree.findall(".//port"):
            if p.find('state').attrib.get('state') == 'open':
                port_info = {
                    "port": int(p.attrib['portid']),
                    "protocol": p.attrib.get('protocol', 'tcp')
                }
                # Get service info if available
                service = p.find('service')
                if service is not None:
                    port_info["service"] = service.attrib.get('name', 'unknown')
                    port_info["version"] = service.attrib.get('version', '')
                ports_found.append(port_info)
        
        logger.info("Found %s open ports for %s", len(ports_found), target)
        return {'open_ports': ports_found}
    except Exception as e:
        logger.error("Error parsing nmap XML: %s", e)
        if os.path.exists(temp_path):
            os.remove(temp_path)
        return {'open_ports': []}

if __name__ == "__main__":
    logger.info("Starting Port scan with VPN...")
    
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
        
        logger.info("Port scan starting for targets: %s", targets)
        logger.info("Options: %s", options)
        
        # Scan từng target
        all_results = []
        for target in targets:
            t = target.strip()
            # Loại bỏ tiền tố http://, https:// nếu có
            if t.startswith('http://'):
                t = t[7:]
            elif t.startswith('https://'):
                t = t[8:]
            # Nếu còn dấu / ở cuối, loại bỏ
            t = t.rstrip('/')
            if t:
                logger.info("Scanning %s...", t)
                result = scan(t, options)
                logger.info("Result for %s: %s open ports", t, len(result.get('open_ports', [])))
                all_results.append({
                    "target": target.strip(),
                    "open_ports": result.get("open_ports", [])
                })
        
        # Gửi kết quả về Controller nếu có callback URL
        if controller_url and all_results:
            try:
                for result in all_results:
                    has_findings = bool(result["open_ports"])
                    payload = {
                        "target": result["target"],
                        "resolved_ips": [],
                        "open_ports": result["open_ports"],
                        "workflow_id": workflow_id,
                        "has_findings": has_findings,
                        "scan_metadata": {
                            "tool": "port-scan",
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
        
        logger.info("Port scan completed")
        
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
