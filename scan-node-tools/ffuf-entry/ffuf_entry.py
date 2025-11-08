#!/usr/bin/env python3
import argparse, json, os, re, subprocess, tempfile, sys, time
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from vpn_manager import VPNManager

# Configure concise logger (match dns_lookup style)
import logging
logger = logging.getLogger("ffuf")
if not logger.handlers:
    h = logging.StreamHandler(stream=sys.stdout)
    h.setFormatter(logging.Formatter("[FFUF] %(levelname)s: %(message)s"))
    logger.addHandler(h)
    logger.setLevel(logging.INFO)

# ====== cấu hình mặc định cho wordlist ffuf ======
DEFAULT_WORDS = [
    "login", "signin", "sign-in", "auth", "account/login", "user/login",
    "wp-login.php", "administrator/index.php", "admin/login", "session",
    "users/sign_in", "auth/login", "members/login", "portal/login"
]



# ====== ffuf runner ======
def run_ffuf(base_url, wordlist, rate, threads, codes, timeout, proxy):
    """
    Chạy ffuf với path mode: -u BASE/FUZZ -w wordlist (fuzz đường dẫn)
    """
    out_json = tempfile.NamedTemporaryFile(delete=False, suffix=".json").name
    
    # Path fuzzing: /FUZZ
    url_template = base_url.rstrip("/") + "/FUZZ"
    
    cmd = [
        "ffuf",
        "-u", url_template,
        "-w", wordlist,
        "-of", "json", "-o", out_json,
        "-mc", codes,
        "-maxtime", str(timeout),
        "-t", str(threads),
    ]
    if rate:
        cmd += ["-rate", str(rate)]
    if proxy:
        cmd += ["-x", proxy]

    # Không nổ job nếu ffuf exit!=0; cố đọc file kết quả
    subprocess.run(cmd, capture_output=True, text=True)
    try:
        with open(out_json, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        data = {"results": []}
    try:
        os.unlink(out_json)
    except Exception:
        pass
    return data.get("results", [])

# ====== lọc URL ứng viên login ======
def pick_login_candidates(results):
    cands, seen = [], set()
    rx = re.compile(r"(login|sign[\-_ ]?in|auth|wp-login|user/login|account/login)", re.I)
    for r in results:
        url = r.get("url") or r.get("input")
        if not url or url in seen:
            continue
        seen.add(url)
        # Ưu tiên URL có keyword + các mã 200/301/302/401/403
        if rx.search(url) or r.get("status") in [200, 301, 302, 401, 403]:
            cands.append(url)
    return cands

# ====== heuristics lấy tên field ======
def choose_username_field(inputs):
    prefs = re.compile(r"(user(name)?|email|login|account)", re.I)
    text_fields = [i for i in inputs if (i.get("type") or "text").lower() in ("text", "email") and i.get("name")]
    for i in text_fields:
        if prefs.search(i["name"]):
            return i["name"]
    return text_fields[0]["name"] if text_fields else None

def find_csrf_token(inputs, soup):
    cand_names = [
        "csrf", "_csrf", "csrf_token", "_token", "__RequestVerificationToken",
        "xsrf", "X-CSRF-Token", "authenticity_token", "XSRF-TOKEN"
    ]
    for i in inputs:
        n = (i.get("name") or "").strip()
        t = (i.get("type") or "").lower()
        if n and t in ("hidden", "text") and any(n.lower() == cn.lower() for cn in cand_names):
            return n, f"input[name='{n}']@value"
    m = soup.select_one("meta[name=csrf-token], meta[name='xsrf-token'], meta[name='csrf']")
    if m and m.get("content"):
        return "csrf", "meta[name=csrf-token]@content"
    return None, None

# ====== dựng profile http_form từ 1 trang HTML ======
def build_profile_from_form(base_url, url, html, verify_ssl=True):
    soup = BeautifulSoup(html, "lxml")
    forms = soup.find_all("form")
    targets = []
    
    logger.debug("Found %s forms in HTML from %s", len(forms), url)

    for i, form in enumerate(forms):
        logger.debug("Processing form %s from %s", i+1, url)
        pwd_input = form.select_one("input[type=password]")
        if not pwd_input or not pwd_input.get("name"):
            logger.debug("Form %s has no password field, skipping", i+1)
            continue

        inputs = [{
            "name": inp.get("name"),
            "type": (inp.get("type") or "text").lower(),
            "value": inp.get("value") or ""
        } for inp in form.find_all("input")]
        
        logger.debug("Form %s has %s inputs", i+1, len(inputs))

        user_field = choose_username_field(inputs)
        pass_field = pwd_input.get("name")
        logger.debug("Form %s - user_field: %s, pass_field: %s", i+1, user_field, pass_field)
        if not user_field or not pass_field:
            logger.debug("Form %s missing required fields, skipping", i+1)
            continue

        method = (form.get("method") or "POST").upper()
        action = form.get("action") or url
        action_url = urljoin(url, action)

        csrf_name, csrf_selector = find_csrf_token(inputs, soup)

        parts = [f"{user_field}=§USER§", f"{pass_field}=§PASS§"]
        if csrf_name and csrf_selector:
            parts.append(f"{csrf_name}=§CSRF§")
        body_template = "&".join(parts)

        profile = {
            "protocol": "http_form",
            "host": urlparse(action_url).hostname or urlparse(base_url).hostname,
            "port": urlparse(action_url).port or (443 if action_url.startswith("https") else 80),
            "http": {
                "url": action_url,
                "method": method,
                "content_type": "form",
                "headers": {
                    "Origin": f"{urlparse(action_url).scheme}://{urlparse(action_url).hostname}",
                    "Referer": url
                },
                "body_template": body_template,
                "success": {
                    "any": [
                        {"status": 302, "location_regex": "/(home|dashboard|profile|account)"},
                        {"set_cookie_regex": "(session|auth|token)="}
                    ]
                },
                "failure": {"body_regex": "(Invalid|incorrect|unauthori[sz]ed|sai|không đúng|thất bại)"},
                "mfa_hint_regex": "(OTP|2FA|Authenticator)",
                "verify_ssl": verify_ssl
            }
        }
        pre_login = {"mode": "once", "url": url}
        if csrf_selector:
            pre_login["extract"] = {"csrf": csrf_selector}
            profile["http"]["pre_login_ttl_sec"] = 120
        profile["http"]["pre_login"] = pre_login

        targets.append(profile)
        logger.debug("Created login profile for form %s from %s", i+1, url)
    
    logger.debug("Total %s login profiles created from %s", len(targets), url)
    return targets

# ====== tải HTML một URL ======
def fetch_html(url, headers=None, proxy=None, verify_ssl=True, timeout=10):
    logger.debug("Fetching HTML from: %s", url)
    s = requests.Session()
    if headers:
        s.headers.update(headers)
    if proxy:
        s.proxies = proxy if isinstance(proxy, dict) else {"http": proxy, "https": proxy}
    try:
        r = s.get(url, timeout=timeout, verify=verify_ssl, allow_redirects=True)
        logger.debug("HTTP %s for %s", r.status_code, url)
        ct = (r.headers.get("Content-Type") or "").lower()
        logger.debug("Content-Type: %s", ct)
        if "text/html" in ct or "<html" in r.text.lower():
            logger.debug("HTML content length: %s chars", len(r.text))
            return r.text
        logger.debug("Not HTML content, skipping")
        return ""
    except Exception as e:
        logger.debug("Error fetching %s: %s", url, e)
        return ""

# ====== helper ======
def parse_jitter(s):
    if not s:
        return [100, 300]
    parts = [p.strip() for p in str(s).split(",")]
    if len(parts) != 2:
        return [100, 300]
    try:
        return [int(parts[0]), int(parts[1])]
    except Exception:
        return [100, 300]

# ====== main ======
def main():
    ap = argparse.ArgumentParser(
        description="ffuf entry → sinh targets HTTP / hoặc job.json hoàn chỉnh cho bf_runner"
    )
    ap.add_argument("--url", help="Base URL, ví dụ: https://target.tld (có thể lấy từ TARGETS env)")
    ap.add_argument("targets", nargs="*", help="Target URLs (fallback nếu không có --url hoặc TARGETS)")
    ap.add_argument("--wordlist", help="Wordlist endpoints cho ffuf; nếu không, dùng danh sách mặc định")
    ap.add_argument("--rate", type=int, default=50, help="req/s cho ffuf (default 50)")
    ap.add_argument("--threads", type=int, default=50, help="threads ffuf (default 50)")
    ap.add_argument("--codes", default="200,301,302,401,403", help="HTTP codes quan tâm để giữ kết quả")
    ap.add_argument("--timeout", type=int, default=60, help="maxtime ffuf (giây)")
    ap.add_argument("--proxy", help="Proxy (http://.., https://.., socks5h://..)")
    ap.add_argument("--insecure", action="store_true", help="Bỏ verify SSL khi crawl")
    ap.add_argument("--out", help="Ghi JSON ra file (mặc định in stdout)")

    # ---- Emit job cho bf_runner ----
    ap.add_argument("--emit-job", action="store_true", help="Xuất thẳng job.json cho bf_runner")
    ap.add_argument("--users", help="Path wordlist users (trong container)")
    ap.add_argument("--passwords", help="Path wordlist passwords (trong container)")
    ap.add_argument("--pairs", help="Path wordlist cặp user:pass (tuỳ chọn)")
    ap.add_argument("--strategy", choices=["dictionary", "spray", "stuffing"], default="dictionary")
    ap.add_argument("--concurrency", type=int, default=2)
    ap.add_argument("--rate-per-min", type=int, default=10)
    ap.add_argument("--jitter", default="100,300", help="ví dụ: 100,300 (ms)")
    ap.add_argument("--timeout-sec", type=int, default=15)
    ap.add_argument("--stop-on-success", action="store_true", default=True)
    ap.add_argument("--no-stop-on-success", dest="stop_on_success", action="store_false")

    args = ap.parse_args()
    
    logger.debug("Command line args: %s", sys.argv)
    
    # Determine target URLs from sources (priority: --url > TARGETS env > positional args)
    target_urls = []
    if args.url:
        target_urls = [args.url]
    else:
        # Check environment variable TARGETS (như các tool khác)
        targets_env = os.getenv("TARGETS", "").strip()
        if targets_env:
            target_urls = [t.strip() for t in targets_env.split(",") if t.strip()]
        # Fallback to positional arguments
        if not target_urls and args.targets:
            target_urls = args.targets
    
    if not target_urls:
        logger.error("No URL provided. Use --url, TARGETS env var, or positional argument.")
        sys.exit(1)
        
    verify_ssl = not args.insecure

    # 1) Chọn wordlist
    if args.wordlist and os.path.exists(args.wordlist):
        wl = args.wordlist
    else:
        # Sử dụng wordlist mặc định cho path mode
        default_words = DEFAULT_WORDS
            
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".txt")
        tmp.write(("\n".join(default_words)).encode("utf-8"))
        tmp.close()
        wl = tmp.name

    logger.info("Starting FFUF scan with VPN")

    # Setup VPN trước khi scan (copy logic từ dns_lookup.py)
    vpn_manager = VPNManager()
    vpn_connected = False
    network_info = {}

    # Lấy VPN assignment từ Controller (nếu có)
    assigned_vpn = None
    controller_url = os.getenv("CONTROLLER_CALLBACK_URL")
    vpn_assignment = os.getenv("VPN_ASSIGNMENT")  # VPN được assign từ Controller
    job_id = os.getenv("JOB_ID")
    workflow_id = os.getenv("WORKFLOW_ID")

    if vpn_assignment:
        try:
            assigned_vpn = json.loads(vpn_assignment)
            logger.info(f"Received VPN assignment: {assigned_vpn.get('hostname', 'Unknown')}")
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse VPN assignment: {e}")

    vpn_profile_info = None
    # Thử setup VPN (optional - có thể skip nếu proxy server không available)
    try:
        logger.debug("Checking initial network status")
        initial_info = vpn_manager.get_network_info()
        logger.debug(f"Initial IP: {initial_info['public_ip']}")

        # Sử dụng assigned VPN nếu có, nếu không thì dùng random
        if assigned_vpn:
            meta = vpn_manager.setup_specific_vpn(assigned_vpn)
            if meta:
                logger.info("Connected to assigned VPN")
                vpn_manager.print_vpn_status()
                network_info = vpn_manager.get_network_info()
                vpn_connected = True
                vpn_profile_info = meta
            else:
                logger.info("Failed to connect to assigned VPN, will try random")

        if not vpn_connected:
            logger.info("No VPN assignment from Controller or failed, using random VPN")
            meta = vpn_manager.setup_random_vpn()
            if meta:
                logger.info("VPN setup completed")
                vpn_manager.print_vpn_status()
                network_info = vpn_manager.get_network_info()
                vpn_connected = True
                vpn_profile_info = meta
            else:
                logger.info("VPN connection failed, continuing without VPN")

        # Gửi thông báo connect VPN về controller nếu kết nối thành công
        if vpn_connected and controller_url and vpn_profile_info:
            try:
                payload = {"action": "connect", "scanner_id": job_id}
                if vpn_profile_info.get("filename"):
                    payload["filename"] = vpn_profile_info["filename"]
                logger.info(f"Notify controller connect: {payload}")
                resp = requests.post(f"{controller_url}/api/vpn_profiles/update", json=payload, timeout=10)
                logger.debug(f"Controller connect response: {resp.status_code}")
            except Exception as notify_err:
                logger.warning(f"Failed to notify controller connect: {notify_err}")
    except Exception as e:
        logger.warning(f"VPN setup error: {e}, continuing without VPN...")

    try:
        logger.info(f"FFUF starting for targets: {target_urls}")

        # Scan từng target riêng biệt
        all_results = []
        all_targets_combined = []
        
        for base_url in target_urls:
            if not base_url or not base_url.strip():
                continue
                
            base_url = base_url.strip()
            logger.info(f"Processing target: {base_url}")
            
            # Chạy ffuf để tìm login endpoints cho target này
            logger.debug("base_url: %s, wl: %s", base_url, wl)
            ffuf_results = run_ffuf(base_url, wl, args.rate, args.threads, args.codes, 
                                   args.timeout, args.proxy)
            logger.debug("ffuf_results count: %s", len(ffuf_results) if ffuf_results else 0)
            
            candidates = pick_login_candidates(ffuf_results)
            logger.debug("candidates: %s", candidates)

            # Parse form từng candidate
            targets = []
            for url in candidates:
                logger.debug("Processing candidate: %s", url)
                html = fetch_html(url, proxy=args.proxy, verify_ssl=verify_ssl)
                if not html:
                    logger.debug("Skipping %s - no HTML content", url)
                    continue
                logger.debug("Got HTML for %s, parsing forms...", url)
                form_targets = build_profile_from_form(base_url, url, html, verify_ssl=verify_ssl)
                logger.debug("Found %s form targets from %s", len(form_targets), url)
                targets.extend(form_targets)

            logger.debug("targets for %s: %s", base_url, len(targets))
            all_results.append({"target": base_url, "targets": targets, "candidates": candidates})
            all_targets_combined.extend(targets)

        logger.debug("Total targets found across all URLs: %s", len(all_targets_combined))

        # Tạo output payload
        if not args.emit_job:
            output_payload = {"job_id": f"ffuf-entry-{int(time.time())}", "targets": all_targets_combined}
            job_json_data = None
        else:
            # kiểm tra tham số bắt buộc
            if not args.users or (not args.passwords and not args.pairs and args.strategy != "spray"):
                logger.error("--emit-job requires --users and (--passwords | --pairs) unless strategy=spray")
                sys.exit(2)
            
            # Tạo job.json data cho brute force
            job_json_data = {
                "job_id": f"bf-from-ffuf-{int(time.time())}",
                "strategy": args.strategy,
                "targets": all_targets_combined,
                "wordlists": {"users": args.users},
                "limits": {
                    "concurrency": args.concurrency,
                    "rate_per_min": args.rate_per_min,
                    "jitter_ms": parse_jitter(args.jitter),
                    "timeout_sec": args.timeout_sec,
                    "stop_on_success": args.stop_on_success
                }
            }
            if args.passwords:
                job_json_data["wordlists"]["passwords"] = args.passwords
            if args.pairs:
                job_json_data["wordlists"]["pairs"] = args.pairs
            
            output_payload = job_json_data.copy()

        # Gửi kết quả về Controller cho từng target riêng biệt (như dns_lookup.py)
        if controller_url and all_results:
            try:
                job_json_sent = False
                
                for result in all_results:
                    target_url = result["target"]
                    target_findings = result["targets"]
                    target_candidates = result["candidates"]
                    has_findings = bool(target_findings)
                    
                    payload = {
                        "target": target_url,
                        "resolved_ips": [],
                        "open_ports": [],
                        "workflow_id": workflow_id,
                        "has_findings": has_findings,
                        "scan_metadata": {
                            "tool": "ffuf-entry",
                            "job_id": job_id,
                            "vpn_used": vpn_connected,
                            "scan_ip": network_info.get("public_ip", "Unknown"),
                            "vpn_local_ip": network_info.get("local_ip"),
                            "tun_interface": network_info.get("tun_interface", False),
                            "total_candidates": len(target_candidates),
                            "total_targets": len(target_findings),
                            "candidates": target_candidates[:10],  # Limit to first 10 for brevity
                            "targets": target_findings[:5] if target_findings else [],  # Limit to first 5 targets
                            "emit_job_mode": args.emit_job
                        }
                    }
                    
                    # Gửi job_json chỉ một lần với target đầu tiên có findings
                    if args.emit_job and job_json_data and has_findings and not job_json_sent:
                        payload["job_json"] = job_json_data
                        job_json_sent = True
                        logger.info(f"Including job.json data in controller payload for {target_url}")
                    
                    logger.debug(f"Sending result to Controller for {target_url}: {payload}")
                    response = requests.post(f"{controller_url}/api/scan_results", json=payload)
                    logger.debug(f"Controller response for {target_url}: {response.status_code}")
                
                # Nếu không có target nào có findings nhưng có emit-job, gửi job_json với target đầu tiên
                if args.emit_job and job_json_data and not job_json_sent and all_results:
                    first_result = all_results[0]
                    payload = {
                        "target": first_result["target"],
                        "resolved_ips": [],
                        "open_ports": [],
                        "workflow_id": workflow_id,
                        "has_findings": False,
                        "scan_metadata": {
                            "tool": "ffuf-entry",
                            "job_id": job_id,
                            "vpn_used": vpn_connected,
                            "scan_ip": network_info.get("public_ip", "Unknown"),
                            "emit_job_mode": True,
                            "note": "No login forms found but job.json generated for manual targets"
                        },
                        "job_json": job_json_data
                    }
                    response = requests.post(f"{controller_url}/api/scan_results", json=payload)
                    logger.info("Sent job.json data even though no findings (for manual targets)")
                    
            except Exception as e:
                logger.warning(f"Error sending results to Controller: {e}")
        
        # Xuất JSON cho local output
        out = json.dumps(output_payload, ensure_ascii=False, indent=2)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as f:
                f.write(out)
        else:
            print(out)

        logger.info("FFUF scan completed")

    except Exception as e:
        logger.warning(f"Scan error: {e}")

    finally:
        # Gửi thông báo disconnect VPN về controller nếu đã connect VPN
        if vpn_connected and controller_url and vpn_profile_info:
            try:
                payload = {"action": "disconnect", "scanner_id": job_id}
                if vpn_profile_info.get("filename"):
                    payload["filename"] = vpn_profile_info["filename"]
                logger.info(f"Notify controller disconnect: {payload}")
                resp = requests.post(f"{controller_url}/api/vpn_profiles/update", json=payload, timeout=10)
                logger.debug(f"Controller disconnect response: {resp.status_code}")
            except Exception as notify_err:
                logger.warning(f"Failed to notify controller disconnect: {notify_err}")
        # Cleanup VPN
        if vpn_connected:
            logger.info("Disconnecting VPN")
            vpn_manager.disconnect_vpn()

if __name__ == "__main__":
    main()
