import requests
import re
import os
from typing import List, Dict, Optional
from collections import defaultdict
from app.core.config import settings # <--- Thêm import này
from sqlalchemy.orm import Session
from app.crud import crud_vpn_profile
import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class VPNService:
    def get_available_vpn_profiles(self, db: Session | None = None) -> List[Dict]:
        """Trả về danh sách VPN chưa bị sử dụng.

        If a DB session is provided, prefer controller DB state and return only
        profiles that are idle / not in use. Otherwise fall back to fetching
        list from the proxy node.
        """
        # When controller DB is available, use it to avoid assigning VPNs
        # that are already reserved/used according to controller state.
        try:
            if db is not None:
                # release expired reservations first
                try:
                    self.release_expired_reservations(db)
                except Exception:
                    logger.exception("Error releasing expired VPN reservations")

                vpn_objs = crud_vpn_profile.get_all(db)
                vpns = []
                now = datetime.utcnow()
                for v in vpn_objs:
                    # skip reserved and still-valid reservations
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

                    # only include VPNs that are idle and not currently in use
                    in_use = bool(getattr(v, 'in_use_by', None))
                    status = getattr(v, 'status', None) or 'idle'
                    if not in_use and status == 'idle':
                        vpns.append({
                            'filename': getattr(v, 'filename', None),
                            'hostname': getattr(v, 'hostname', None),
                            'ip': getattr(v, 'ip', None),
                            'country': getattr(v, 'country', None),
                            'status': status
                        })
                return vpns
        except Exception:
            # If anything goes wrong reading DB, fall back to proxy fetch
            logger.exception("get_available_vpn_profiles: db read failed, falling back to proxy fetch")

        return self.fetch_vpns_sync()

    def reserve_vpn_profile(self, filename: str, reserved_by: str, ttl_seconds: int, db: Session, force: bool = False) -> bool:
        """Reserve a vpn profile in the controller DB until now + ttl_seconds.

        Returns True when reservation succeeded, False otherwise.
        """
        if db is None:
            logger.warning("reserve_vpn_profile called without db")
            return False
        try:
            vpn = crud_vpn_profile.get_by_filename(db, filename=filename)
            if not vpn:
                logger.warning("reserve_vpn_profile: vpn not found %s", filename)
                return False

            # If already in use, cannot reserve unless caller forces
            if vpn.in_use_by and not force:
                logger.info("reserve_vpn_profile: vpn %s already in use: %s", filename, vpn.in_use_by)
                return False

            reserved_until = datetime.utcnow() + timedelta(seconds=ttl_seconds)
            reserved_until_iso = reserved_until.isoformat()
            success = crud_vpn_profile.set_reserved(db, filename=filename, reserved_by=reserved_by, reserved_until_iso=reserved_until_iso)
            if success:
                logger.info("Reserved vpn %s until %s for %s", filename, reserved_until_iso, reserved_by)
            return success
        except Exception:
            logger.exception("reserve_vpn_profile failed for %s", filename)
            return False

    def release_expired_reservations(self, db: Session):
        """Clear reservations that have expired (reserved_until <= now)."""
        try:
            now = datetime.utcnow()
            vpn_objs = crud_vpn_profile.get_all(db)
            for v in vpn_objs:
                reserved_until = getattr(v, 'reserved_until', None)
                if not reserved_until:
                    continue
                try:
                    reserved_dt = datetime.fromisoformat(reserved_until) if isinstance(reserved_until, str) else reserved_until
                except Exception:
                    # malformed, clear it
                    crud_vpn_profile.clear_reservation(db, v)
                    continue
                if reserved_dt <= now:
                    crud_vpn_profile.clear_reservation(db, v)
                    logger.info("Released expired reservation for %s", getattr(v, 'filename', '<unknown>'))
        except Exception:
            logger.exception("release_expired_reservations failed")

    def reset_vpn_profiles(self, db: Session) -> int:
        """Reset all vpn profiles in DB to default idle state. Returns count."""
        return crud_vpn_profile.reset_all(db)
    """
    VPN Service cho Controller.
    
    Controller KHÔNG kết nối VPN trực tiếp, chỉ:
    1. Lấy danh sách VPN từ proxy node
    2. Assign VPN cho scan jobs
    3. Forward VPN config đến Scanner nodes
    
    Scanner nodes mới thực sự kết nối VPN.
    """
    def __init__(self): # <--- Bỏ tham số proxy_node_url
        # Controller chỉ làm trung gian điều phối VPN, không kết nối trực tiếp
        # Controller chỉ làm trung gian điều phối VPN, không kết nối trực tiếp
        self.proxy_node = settings.VPN_PROXY_NODE # <--- Lấy từ settings

    def clear_proxy_env(self):
        """Xóa proxy khỏi environment variables"""
        proxy_vars = ['http_proxy', 'https_proxy', 'HTTP_PROXY', 'HTTPS_PROXY']
        old_proxies = {}
        for var in proxy_vars:
            if var in os.environ:
                old_proxies[var] = os.environ[var]
                del os.environ[var]
        return old_proxies
    
    def restore_proxy_env(self, old_proxies: Dict[str, str]):
        """Restore proxy environment"""
        for var, value in old_proxies.items():
            os.environ[var] = value
    
    def fetch_vpns_sync(self) -> List[Dict]:
        """
        Sync version - Lấy danh sách VPN từ proxy server.
        """
        old_proxies = self.clear_proxy_env()
        
        try:
            import requests
            response = requests.get(f"{self.proxy_node}/vpns", timeout=10)
            response.raise_for_status()
            
            vpn_list = response.json()
            print(f"[*] Controller fetched {len(vpn_list)} VPNs from proxy node")
            
            # Convert to standard format nếu cần
            if isinstance(vpn_list, list) and vpn_list:
                if isinstance(vpn_list[0], str):
                    # Convert filename list to VPN objects
                    return [{"filename": vpn, "hostname": vpn.replace('.ovpn', '')} for vpn in vpn_list]
                else:
                    return vpn_list
            return []
            
        except Exception as e:
            print(f"[!] Controller error fetching VPNs from proxy: {e}")
            return []
        finally:
            self.restore_proxy_env(old_proxies)

    async def fetch_vpns(self) -> List[Dict]:
        """
        Async wrapper cho sync method
        """
        import asyncio
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.fetch_vpns_sync)
    
    def fetch_proxies(self) -> List[str]:
        """Lấy danh sách proxy từ proxy server"""
        old_proxies = self.clear_proxy_env()
        
        try:
            response = requests.get(f"{self.proxy_node}/proxies", timeout=10)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"[!] Lỗi khi fetch proxy list: {e}")
            return []
        finally:
            self.restore_proxy_env(old_proxies)
    
    def get_country_from_ip(self, ip: str) -> str:
        """Lấy mã quốc gia từ IP address"""
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}", 
                                  timeout=5, proxies={'http': None, 'https': None})
            if response.status_code == 200:
                data = response.json()
                return data.get('countryCode', 'Unknown')
            return 'Unknown'
        except:
            return 'Unknown'
    
    async def categorize_vpns_by_country(self, vpns: List[Dict]) -> Dict[str, List[Dict]]:
        """Phân loại VPN theo quốc gia dựa trên IP trong tên file"""
        categorized = defaultdict(list)
        
        for vpn in vpns:
            if isinstance(vpn, dict):
                # VPN object format
                filename = vpn.get('filename', '')
                hostname = vpn.get('hostname', '')
            else:
                # String format
                filename = str(vpn)
                hostname = filename.replace('.ovpn', '')
            
            # Trích xuất IP từ tên file VPN
            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', filename)
            if ip_match:
                ip = ip_match.group(1)
                country = self.get_country_from_ip(ip)
                categorized[country].append({
                    'filename': filename,
                    'hostname': hostname,
                    'ip': ip,
                    'country': country
                })
            else:
                categorized['Unknown'].append({
                    'filename': filename,
                    'hostname': hostname,
                    'ip': 'Unknown',
                    'country': 'Unknown'
                })
        
        return dict(categorized)
    
    def categorize_proxies_by_country(self, proxies: List[str]) -> Dict[str, List[str]]:
        """Phân loại proxy theo quốc gia"""
        categorized = defaultdict(list)
        
        for proxy in proxies:
            try:
                ip = proxy.strip().split()[0]
                country = self.get_country_from_ip(ip)
                categorized[country].append({
                    'proxy': proxy.strip(),
                    'ip': ip,
                    'country': country
                })
            except:
                categorized['Unknown'].append({
                    'proxy': proxy.strip(),
                    'ip': 'Unknown',
                    'country': 'Unknown'
                })
        
        return dict(categorized)
    
    def get_random_vpn(self, country: str = None) -> Optional[Dict[str, str]]:
        """Lấy random VPN, có thể filter theo country"""
        import random
        
        vpns = self.fetch_vpns()
        if not vpns:
            return None
        
        if country:
            categorized = self.categorize_vpns_by_country(vpns)
            if country in categorized and categorized[country]:
                return random.choice(categorized[country])
            return None
        else:
            # Random VPN từ tất cả
            categorized = self.categorize_vpns_by_country(vpns)
            all_vpns = []
            for country_vpns in categorized.values():
                all_vpns.extend(country_vpns)
            
            return random.choice(all_vpns) if all_vpns else None
    
    def download_vpn_content(self, filename: str) -> Optional[bytes]:
        """Download VPN config content"""
        old_proxies = self.clear_proxy_env()
        
        try:
            response = requests.get(f"{self.proxy_node}/vpn/{filename}", timeout=30)
            response.raise_for_status()
            return response.content
        except Exception as e:
            print(f"[!] Lỗi khi download VPN {filename}: {e}")
            return None
        finally:
            self.restore_proxy_env(old_proxies)
