import requests
import random
import subprocess
import os
import time
import sys
import logging

# Configure module logger to stdout so kubectl logs will show it
logger = logging.getLogger("vpn_manager")
if not logger.handlers:
    handler = logging.StreamHandler(stream=sys.stdout)
    formatter = logging.Formatter("[VPN] %(levelname)s: %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

class VPNManager:
    def __init__(self, proxy_node="http://10.102.199.37:8000"):
        self.proxy_node = proxy_node
        self.vpn_process = None
        
    def fetch_vpns(self):
        """Lấy danh sách VPN từ proxy server"""
        try:
            response = requests.get(f"{self.proxy_node}/vpns", timeout=10)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.warning(f"Không lấy được danh sách VPN: {e}")
            return []
    
    def download_vpn(self, filename):
        """Download VPN config file"""
        try:
            r = requests.get(f"{self.proxy_node}/vpn/{filename}", timeout=30)
            r.raise_for_status()
            vpn_path = f"/tmp/{filename}"
            with open(vpn_path, "wb") as f:
                f.write(r.content)
            # Restrict permissions for security
            try:
                os.chmod(vpn_path, 0o600)
            except Exception:
                logger.debug("Không thể chmod file VPN (ignore)")
            logger.info(f"Đã tải file cấu hình: {filename}")
            return vpn_path
        except Exception as e:
            logger.warning(f"Lỗi tải file cấu hình {filename}: {e}")
            return None
    
    def connect_vpn(self, vpn_file):
        """Kết nối VPN với network configuration"""
        logger.info(f"Đang kết nối: {os.path.basename(vpn_file)}")
        # Prepare openvpn command with resilience options
        cmd = [
            "openvpn", "--config", vpn_file,
            "--data-ciphers", "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305:AES-128-CBC",
            "--redirect-gateway", "def1",
            "--script-security", "2",
            "--persist-key",
            "--persist-tun",
            "--auth-nocache",
            "--verb", "3",
            "--ping", "10",
            "--ping-restart", "60",
        ]

        try:
            # Start openvpn and monitor stdout for initialization completion
            self.vpn_process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            start = time.time()
            timeout = 90
            init_ok = False
            # Read lines until we find success or timeout
            while True:
                if self.vpn_process.poll() is not None:
                    # process exited unexpectedly
                    out = self.vpn_process.stdout.read() if self.vpn_process.stdout else ""
                    logger.warning("openvpn process exited early: %s", out.splitlines()[-1] if out else "(no output)")
                    break
                line = self.vpn_process.stdout.readline()
                if line:
                    # Only log important lines to avoid noise
                    if "Initialization Sequence Completed" in line:
                        init_ok = True
                        logger.info("openvpn initialization completed")
                        break
                    # Debug log other lines at debug level
                    logger.debug(line.strip())
                if time.time() - start > timeout:
                    logger.warning("Không thể kết nối (timeout waiting init)")
                    break
            if not init_ok:
                self.disconnect_vpn()
                return False
            # Small wait for routes to be set up then verify
            time.sleep(2)
            try:
                self._setup_vpn_routing()
            except Exception:
                logger.debug("_setup_vpn_routing failed (ignored)")
            return True
        except Exception as e:
            logger.exception(f"Lỗi khi chạy openvpn: {e}")
            self.disconnect_vpn()
            return False
    
    def is_vpn_connected(self):
        """Kiểm tra VPN đã kết nối chưa"""
        try:
            # Check for any tun interface (tun0, tun1, ...)
            result = subprocess.run(['ip', '-o', 'link', 'show'], capture_output=True, text=True)
            if result.returncode != 0:
                return False
            for line in result.stdout.splitlines():
                if line.startswith('tun') or ': tun' in line:
                    return True
            return False
        except Exception:
            return False
    
    def _setup_vpn_routing(self):
        try:
            result = subprocess.run(['ip', 'route', 'show'], capture_output=True, text=True)
            if result.returncode == 0 and 'tun' in result.stdout:
                # apply dns changes and cluster routes
                self._setup_vpn_dns()
                # best-effort add cluster routes (ignore errors)
                subprocess.run(['ip', 'route', 'add', '10.244.0.0/16', 'via', '10.244.0.1', 'dev', 'eth0'], capture_output=True)
                subprocess.run(['ip', 'route', 'add', '10.96.0.0/12', 'via', '10.244.0.1', 'dev', 'eth0'], capture_output=True)
            else:
                logger.debug("No tun route found yet")
        except Exception as e:
            logger.debug(f"Lỗi setup routing: {e}")
    
    def _setup_vpn_dns(self):
        try:
            # Backup resolv.conf if present
            try:
                subprocess.run(['cp', '/etc/resolv.conf', '/etc/resolv.conf.backup'], capture_output=True)
            except Exception:
                logger.debug('Could not backup /etc/resolv.conf')
            original_dns = ""
            try:
                with open('/etc/resolv.conf.backup', 'r') as f:
                    original_dns = f.read()
            except Exception:
                original_dns = ""
            dns_config = """nameserver 10.96.0.10
nameserver 8.8.8.8
nameserver 8.8.4.4
"""
            # preserve any non-k8s nameservers from original
            if "nameserver" in original_dns:
                for line in original_dns.split('\n'):
                    if line.startswith('nameserver') and '10.96.0.10' not in line:
                        dns_config += line + '\n'
            try:
                with open('/etc/resolv.conf', 'w') as f:
                    f.write(dns_config)
            except Exception as e:
                logger.debug(f'Could not write /etc/resolv.conf: {e}')
        except Exception as e:
            logger.debug(f"Lỗi setup DNS: {e}")
    
    def disconnect_vpn(self):
        """Ngắt kết nối VPN và restore DNS"""
        if self.vpn_process and self.vpn_process.poll() is None:
            logger.info("Ngắt kết nối VPN")
            try:
                self.vpn_process.terminate()
                self.vpn_process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.vpn_process.kill()
            finally:
                self.vpn_process = None
        # restore resolv.conf if backup exists
        try:
            subprocess.run(['mv', '/etc/resolv.conf.backup', '/etc/resolv.conf'], capture_output=True)
        except Exception:
            pass
    
    def setup_specific_vpn(self, vpn_config):
        """Setup VPN từ config được assign từ Controller"""
        # Lấy IP ban đầu
        original_ip = self.get_current_ip()
        logger.debug(f"IP ban đầu: {original_ip}")
        
        # Kiểm tra môi trường container
        self._check_container_capabilities()
        
        # Extract filename from VPN config
        vpn_filename = vpn_config.get('filename')
        if not vpn_filename:
            logger.warning("VPN config missing filename")
            return False

        logger.info(f"Connecting to assigned VPN: {vpn_filename}")
        logger.debug(f"    - Hostname: {vpn_config.get('hostname', 'Unknown')}")
        logger.debug(f"    - Country: {vpn_config.get('country', 'Unknown')}")

        vpn_path = self.download_vpn(vpn_filename)
        # Try with simple retry/backoff for assigned VPN and return metadata on success
        max_attempts = 3
        for attempt in range(1, max_attempts + 1):
            if vpn_path and self.connect_vpn(vpn_path):
                new_ip = self.get_current_ip()
                logger.debug(f"IP after VPN: {new_ip}")
                if self.is_vpn_working():
                    logger.info(f"Assigned VPN connected")
                    return {"filename": vpn_filename, "hostname": vpn_config.get("hostname")}
                else:
                    logger.debug("Assigned VPN connected but health check failed, disconnecting and retrying")
                    self.disconnect_vpn()
            else:
                logger.debug(f"connect_vpn returned False on attempt {attempt}")
            # backoff
            time.sleep(1 * attempt)
        logger.debug(f"Failed to connect to assigned VPN after {max_attempts} attempts: {vpn_filename}")
        return None
    
    def setup_random_vpn(self):
        """Setup VPN ngẫu nhiên"""
        # Lấy IP ban đầu
        original_ip = self.get_current_ip()
        logger.debug(f"IP ban đầu: {original_ip}")
        
        # Kiểm tra môi trường container
        self._check_container_capabilities()
        
        vpns = self.fetch_vpns()
        if not vpns:
            logger.warning("Không có VPN nào available")
            return False
        # Try several different vpns with backoff and avoid immediate repeats
        tried = set()
        max_trials = min(6, len(vpns) * 2)
        trial = 0
        while trial < max_trials and len(tried) < len(vpns):
            chosen_vpn = random.choice(vpns)
            if chosen_vpn in tried:
                trial += 1
                continue
            tried.add(chosen_vpn)
            trial += 1
            logger.info(f"Trying VPN: {chosen_vpn} ({trial}/{max_trials})")
            vpn_path = self.download_vpn(chosen_vpn)
            if not vpn_path:
                logger.debug("download_vpn failed, continue")
                time.sleep(1)
                continue
            # attempt connection with small retries
            for attempt in range(1, 3):
                if self.connect_vpn(vpn_path):
                    new_ip = self.get_current_ip()
                    logger.debug(f"IP after VPN: {new_ip}")
                    if self.is_vpn_working():
                        logger.info(f"VPN working: {chosen_vpn}")
                        return {"filename": chosen_vpn, "hostname": None}
                    else:
                        logger.debug("VPN connected but not healthy, disconnecting")
                        self.disconnect_vpn()
                logger.debug(f"Attempt {attempt} failed for {chosen_vpn}")
                time.sleep(attempt)
            # small pause before next vpn
            time.sleep(1)
        logger.debug("Cannot connect to any VPN")
        return None
    
    def _check_container_capabilities(self):
        """Kiểm tra khả năng networking của container"""
        logger.debug("Checking container networking capabilities")
        # Check if we can create TUN devices
        try:
            result = subprocess.run(['ls', '/dev/net/tun'], capture_output=True, text=True)
            tun_available = result.returncode == 0
            logger.debug(f"TUN device: {'Y' if tun_available else 'N'}")
        except Exception:
            logger.debug("TUN device: N")
        # Check NET_ADMIN capability
        try:
            result = subprocess.run(['ip', 'route', 'show'], capture_output=True, text=True)
            routing_ok = result.returncode == 0
            logger.debug(f"Routing access: {'Y' if routing_ok else 'N'}")
        except Exception:
            logger.debug("Routing access: N")
        # Check external connectivity
        try:
            result = subprocess.run(['ping', '-c', '1', '-W', '3', '8.8.8.8'], capture_output=True, text=True, timeout=5)
            external_ok = result.returncode == 0
            logger.debug(f"External connectivity: {'Y' if external_ok else 'N'}")
        except Exception:
            logger.debug("External connectivity: N")
    
    def is_vpn_working(self):
        """Kiểm tra VPN có thực sự hoạt động không - simplified version"""
        # lightweight health check: tun exists and routing has tun route
        tun_ok = self.is_vpn_connected()
        route_ok = False
        try:
            result = subprocess.run(['ip', 'route', 'show'], capture_output=True, text=True)
            route_ok = 'tun' in result.stdout
        except Exception:
            route_ok = False
        # prefer to allow VPN even if ICMP/DNS blocked by server; require tun and route
        logger.debug(f"VPN health: tun_ok={tun_ok} route_ok={route_ok}")
        return tun_ok and route_ok
    
    def get_current_ip(self):
        """Lấy IP hiện tại - ưu tiên external IP services, fallback to VPN interface"""
        # Trước tiên thử get IP từ VPN interface
        vpn_ip = self._get_vpn_interface_ip()
        if vpn_ip:
            logger.debug(f"Detected VPN interface IP: {vpn_ip}")
        
        # Thử các external services với timeout ngắn hơn
        external_methods = [
            (['curl', '-s', '--max-time', '5', '--interface', 'tun0', 'https://api.ipify.org'], 'tun0'),
            (['curl', '-s', '--max-time', '5', 'https://api.ipify.org'], 'default'),
            (['curl', '-s', '--max-time', '5', 'http://ipinfo.io/ip'], 'default'),
            (['curl', '-s', '--max-time', '5', 'http://checkip.amazonaws.com'], 'default'),
            (['wget', '-qO-', '--timeout=5', 'https://api.ipify.org'], 'default')
        ]
        
        for method, interface in external_methods:
            try:
                logger.debug(f"Trying IP detection via {interface}: {' '.join(method[:3])}")
                result = subprocess.run(method, capture_output=True, text=True, timeout=8)
                if result.returncode == 0 and result.stdout.strip():
                    ip = result.stdout.strip()
                    if self._is_valid_ip(ip):
                        logger.debug(f"External IP detected: {ip}")
                        return ip
                else:
                    logger.debug(f"Method failed: {result.stderr.strip() if result.stderr else 'No output'}")
            except subprocess.TimeoutExpired:
                logger.debug(f"Method timeout: {' '.join(method[:3])}")
                continue
            except Exception as e:
                logger.debug(f"Method error: {e}")
                continue
        
        # If external detection fails, use VPN interface IP (this is actually the correct behavior)
        if vpn_ip:
            logger.debug(f"External detection failed, using VPN interface IP: {vpn_ip}")
            return vpn_ip
                
        # Last fallback: check local interface IPs
        try:
            result = subprocess.run(['hostname', '-I'], capture_output=True, text=True)
            if result.returncode == 0:
                ips = result.stdout.strip().split()
                for ip in ips:
                    if self._is_valid_ip(ip) and not ip.startswith('127.') and not ip.startswith('10.244.'):
                        return ip
        except Exception:
            pass
            
        return "Unknown"
    
    def _get_vpn_interface_ip(self):
        """Lấy IP từ VPN interface"""
        try:
            result = subprocess.run(['ip', 'addr', 'show', 'tun0'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'inet ' in line and 'scope global' in line:
                        return line.split()[1].split('/')[0]
        except:
            pass
        return None
    
    def _is_valid_ip(self, ip):
        """Kiểm tra IP hợp lệ"""
        try:
            parts = ip.split('.')
            return len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts)
        except:
            return False
    
    def get_network_info(self):
        """Lấy thông tin network chi tiết"""
        info = {
            "public_ip": self.get_current_ip(),
            "tun_interface": False,
            "local_ip": None,
            "default_route": None
        }
        
        try:
            # Kiểm tra tun interface
            result = subprocess.run(['ip', 'addr', 'show', 'tun0'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                info["tun_interface"] = True
                # Extract local IP từ tun0
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'inet ' in line and 'scope global' in line:
                        info["local_ip"] = line.split()[1].split('/')[0]
            
            # Kiểm tra default route
            result = subprocess.run(['ip', 'route', 'show', 'default'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                info["default_route"] = result.stdout.strip()
                
        except Exception as e:
            logger.debug(f"Error getting network info: {e}")
            
        return info
    
    def print_vpn_status(self):
        info = self.get_network_info()
        logger.info(f"Public IP: {info['public_ip']} | TUN: {'Y' if info['tun_interface'] else 'N'} | Local: {info['local_ip'] or '-'}")
        return info
