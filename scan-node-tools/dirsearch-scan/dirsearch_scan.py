#!/usr/bin/env python3
import argparse, subprocess, sys, json, tempfile, re, os, requests, logging
from vpn_manager import VPNManager

# Configure concise logger
logger = logging.getLogger("dirsearch")
if not logger.handlers:
    h = logging.StreamHandler(stream=sys.stdout)
    h.setFormatter(logging.Formatter("[DIRSEARCH] %(levelname)s: %(message)s"))
    logger.addHandler(h)
    logger.setLevel(logging.INFO)

def has_json_report():
    try:
        help_txt = subprocess.run(
            ["python3", "/opt/dirsearch/dirsearch.py", "-h"],
            capture_output=True, text=True
        ).stdout.lower()
        return "--json-report" in help_txt
    except Exception:
        return False

def run(cmd):
    """Chạy lệnh, nếu lỗi thì trả JSON báo lỗi kèm stderr"""
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode != 0:
        err = (p.stderr or p.stdout or "").strip()
        print(json.dumps({"error": "dirsearch failed", "code": p.returncode, "stderr": err}, ensure_ascii=False))
        sys.exit(p.returncode)
    return p

# ví dụ chạy test nhanh
# docker run --rm dirsearch-scan:dev `
#   --url http://testphp.vulnweb.com `
#   --no-extensions `
#   --wordlist /opt/dirsearch/db/dicc.txt `
#   --include-status 200,204,301,302,307,401,403 `
#   --threads 5


if __name__ == "__main__":
    logger.info("Starting dirsearch scan with VPN...")
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
    try:
        # ...existing VPN setup and scan logic...
        logger.info("Checking initial network status...")
        initial_info = vpn_manager.get_network_info()
        logger.info("Initial IP: %s", initial_info.get('public_ip'))
        if assigned_vpn:
            meta = vpn_manager.setup_specific_vpn(assigned_vpn)
            if meta:
                logger.info("Connected to assigned VPN: %s", assigned_vpn.get('hostname', 'Unknown'))
                vpn_manager.print_vpn_status()
                network_info = vpn_manager.get_network_info()
                vpn_connected = True
                vpn_profile_info = meta
                # Notify controller: connect
                if controller_url:
                    try:
                        job_id = os.getenv("JOB_ID")
                        payload = {"action": "connect", "scanner_id": job_id}
                        if vpn_profile_info.get("filename"):
                            payload["filename"] = vpn_profile_info.get("filename")
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
                    # Notify controller: connect (random)
                    vpn_profile_info = meta
                    if controller_url:
                        try:
                            job_id = os.getenv("JOB_ID")
                            payload = {"action": "connect", "scanner_id": job_id}
                            if vpn_profile_info.get("filename"):
                                payload["filename"] = vpn_profile_info.get("filename")
                            logger.info("Notify controller: connect %s", payload)
                            resp = requests.post(f"{controller_url}/api/vpn_profiles/update", json=payload, timeout=10)
                            logger.info("Controller connect response: %s", resp.status_code)
                        except Exception as notify_err:
                            logger.error("Failed to notify controller connect: %s", notify_err)
        else:
            logger.info("No VPN assignment from Controller, using random VPN...")
            meta = vpn_manager.setup_random_vpn()
            if meta:
                logger.info("VPN setup completed!")
                vpn_manager.print_vpn_status()
                network_info = vpn_manager.get_network_info()
                vpn_connected = True
                vpn_profile_info = meta
                if controller_url:
                    try:
                        job_id = os.getenv("JOB_ID")
                        payload = {"action": "connect", "scanner_id": job_id}
                        if vpn_profile_info.get("filename"):
                            payload["filename"] = vpn_profile_info.get("filename")
                        logger.info("Notify controller: connect %s", payload)
                        resp = requests.post(f"{controller_url}/api/vpn_profiles/update", json=payload, timeout=10)
                        logger.info("Controller connect response: %s", resp.status_code)
                    except Exception as notify_err:
                        logger.error("Failed to notify controller connect: %s", notify_err)

        # --- Robust argument handling: convert positional/ENV targets to --url/--url-file ---
        targets_env = os.getenv("TARGETS", "").split(",") if os.getenv("TARGETS") else []
        targets_env = [t.strip() for t in targets_env if t.strip()]

        import shlex
        extra_targets = []
        new_argv = [sys.argv[0]]
        i = 1
        while i < len(sys.argv):
            arg = sys.argv[i]
            if arg.startswith('-'):
                new_argv.append(arg)
                i += 1
                # copy value nếu là flag có value
                if arg in ["--url", "--url-file", "--threads", "--wordlist", "--include-status", "--extensions", "--wordlist-start", "--wordlist-end"]:
                    if i < len(sys.argv):
                        new_argv.append(sys.argv[i])
                        i += 1
            else:
                extra_targets.append(arg)
                i += 1

        # Nếu có extra_targets, ưu tiên --url-file nếu nhiều target, --url nếu 1 target
        if extra_targets:
            if len(extra_targets) == 1:
                new_argv.extend(["--url", extra_targets[0]])
            else:
                with open('/tmp/targets.txt', 'w') as f:
                    for t in extra_targets:
                        f.write(f"{t}\n")
                new_argv.extend(["--url-file", '/tmp/targets.txt'])

        # Nếu có targets_env, ghi ra file tạm (ưu tiên targets_env hơn positional)
        if targets_env:
            with open('/tmp/targets.txt', 'w') as f:
                for target in targets_env:
                    f.write(f"{target}\n")
            if '--url-file' not in new_argv:
                new_argv.extend(['--url-file', '/tmp/targets.txt'])

        # Parse SCAN_OPTIONS env (JSON) và truyền vào sys.argv nếu có
        scan_options_env = os.getenv("SCAN_OPTIONS")
        random_agent_flag = False
        if scan_options_env:
            try:
                import json
                scan_options = json.loads(scan_options_env)
                logger.debug("Parsed SCAN_OPTIONS: %s", scan_options)
                # Map key -> arg
                option_map = {
                    "wordlist": "--wordlist",
                    "wordlist_start": "--wordlist-start",
                    "wordlist_end": "--wordlist-end",
                    "threads": "--threads",
                    "extensions": "--extensions",
                    "include_status": "--include-status",
                    "recursive": "--recursive",
                    "no_extensions": "--no-extensions"
                }
                for k, v in scan_options.items():
                    if k == "random_agent" and v:
                        random_agent_flag = True
                        continue
                    arg_name = option_map.get(k)
                    if not arg_name:
                        continue
                    # Boolean flags
                    if arg_name in ["--recursive", "--no-extensions"]:
                        if v:
                            new_argv.append(arg_name)
                    else:
                        # Handle list values (e.g. include_status might be [200] instead of "200")
                        if isinstance(v, list):
                            if k == "include_status":
                                # Convert list to comma-separated string: [200, 301] -> "200,301"
                                value_str = ",".join(str(x) for x in v)
                            else:
                                # For other list params, join with comma
                                value_str = ",".join(str(x) for x in v)
                        else:
                            value_str = str(v)
                        new_argv.extend([arg_name, value_str])
            except Exception as e:
                logger.debug("Failed to parse SCAN_OPTIONS env: %s", e)

        sys.argv = new_argv

        parser = argparse.ArgumentParser(description="Wrapper cho dirsearch -> JSON")
        parser.add_argument("--url", help="URL đơn lẻ")
        parser.add_argument("--url-file", help="File chứa nhiều URL, mỗi dòng một URL")
        parser.add_argument("--threads", type=int, default=30)
        parser.add_argument("--recursive", action="store_true")
        parser.add_argument("--wordlist", help="Đường dẫn wordlist trong container")
        parser.add_argument("--wordlist-start", type=int, default=None, help="Dòng bắt đầu (0-based)")
        parser.add_argument("--wordlist-end", type=int, default=None, help="Dòng kết thúc (0-based, inclusive)")
        parser.add_argument("--include-status", help="VD: 200,204,301,302,307,401,403")
        parser.add_argument("--extensions", default=None, help="VD: php,js,txt (mặc định None)")
        parser.add_argument("--no-extensions", action="store_true", help="Không dùng -e để quét cả đường dẫn không đuôi")
        args = parser.parse_args()

        # Debug thông tin scan ngay sau khi parse args
        logger.debug("job_id: %s", os.getenv('JOB_ID'))
        logger.debug("wordlist_path: %s", getattr(args, 'wordlist', None))
        logger.debug("wordlist_start: %s", getattr(args, 'wordlist_start', None))
        logger.debug("wordlist_end: %s", getattr(args, 'wordlist_end', None))
        try:
            if getattr(args, 'wordlist', None):
                with open(args.wordlist, "r", encoding="utf-8", errors="ignore") as f:
                    debug_lines = f.readlines()
                logger.debug("wordlist_lines: %s", len(debug_lines))
        except Exception as e:
            logger.debug("wordlist read error: %s", e)
        logger.debug("targets: %s", getattr(args, 'url', None) or getattr(args, 'url_file', None))
        logger.debug("threads: %s", getattr(args, 'threads', None))
        logger.debug("extensions: %s", getattr(args, 'extensions', None))
        logger.debug("include_status: %s", getattr(args, 'include_status', None))
        logger.debug("recursive: %s", getattr(args, 'recursive', None))

        if not args.url and not args.url_file:
            print(json.dumps({"error":"missing --url or --url-file"})); sys.exit(2)
        if args.extensions and args.no_extensions:
            print(json.dumps({"error":"conflict: --extensions và --no-extensions"})); sys.exit(2)

        # Xử lý wordlist_start/end nếu có
        wordlist_path = args.wordlist
        if args.wordlist and args.wordlist_start is not None and args.wordlist_end is not None:
            # Tạo file wordlist tạm chỉ chứa các dòng từ start đến end
            with open(args.wordlist, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
            start = max(0, args.wordlist_start)
            end = min(len(lines)-1, args.wordlist_end)
            subset = lines[start:end+1]
            with tempfile.NamedTemporaryFile(delete=False, suffix=".txt", mode="w", encoding="utf-8") as tf:
                for idx, line in enumerate(subset):
                    tf.write(line)
                    logger.info("Preparing to scan line %s: %s", start + idx, line.strip())
                wordlist_path = tf.name
        # Prepare allowed_status for post-filtering
        # Lấy đúng tham số include_status từ request (params)
        include_status_raw = getattr(args, "include_status", None)
        if include_status_raw:
            allowed_status = set(int(s.strip()) for s in include_status_raw.split(",") if s.strip().isdigit())
        else:
            allowed_status = set()
        # Base command
        base_cmd = ["python3", "/opt/dirsearch/dirsearch.py", "-t", str(args.threads)]
        if args.recursive:
            base_cmd += ["-r"]
        if wordlist_path:
            base_cmd += ["-w", wordlist_path]
        if include_status_raw:
            base_cmd += ["-i", include_status_raw]
            logger.debug("Adding status filter: -i %s", include_status_raw)
        if args.extensions and not args.no_extensions:
            base_cmd += ["-e", args.extensions]
        if 'random_agent_flag' in locals() and random_agent_flag:
            base_cmd += ["--random-agent"]
        # Mục tiêu
        if args.url_file:
            base_cmd += ["-l", args.url_file]
        else:
            base_cmd += ["-u", args.url]

        # Debug thông tin quét
        logger.debug("job_id: %s", os.getenv('JOB_ID'))
        logger.debug("wordlist_path: %s", wordlist_path)
        logger.debug("wordlist_start: %s", getattr(args, 'wordlist_start', None))
        logger.debug("wordlist_end: %s", getattr(args, 'wordlist_end', None))
        try:
            with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                debug_lines = f.readlines()
            logger.debug("wordlist_lines: %s", len(debug_lines))
        except Exception as e:
            logger.debug("wordlist read error: %s", e)
        logger.debug("targets: %s", args.url or args.url_file)
        logger.debug("threads: %s", args.threads)
        logger.debug("extensions: %s", args.extensions)
        logger.debug("include_status: %s", getattr(args, 'include_status', None))
        logger.debug("recursive: %s", args.recursive)
        logger.debug("Final command: %s", " ".join(base_cmd))

        # Xác định danh sách target
        if args.url_file:
            with open(args.url_file, "r", encoding="utf-8", errors="ignore") as f:
                targets_list = [line.strip() for line in f if line.strip()]
        elif args.url:
            targets_list = [args.url]
        else:
            targets_list = []

        # Quét từng target riêng biệt và gửi kết quả từng lần
        for target_url in targets_list:
            findings = []
            # Build command cho từng target
            cmd = base_cmd.copy()
            # Xóa -u/-l nếu có
            if "-u" in cmd:
                idx = cmd.index("-u")
                del cmd[idx:idx+2]
            if "-l" in cmd:
                idx = cmd.index("-l")
                del cmd[idx:idx+2]
            cmd += ["-u", target_url]

            if has_json_report():
                with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as f:
                    out = f.name
                cmd_target = cmd + ["--json-report", out]
                run(cmd_target)
                with open(out, "r", encoding="utf-8", errors="ignore") as fh:
                    raw = fh.read().strip()
                try:
                    all_results = json.loads(raw).get("results", []) if raw else []
                    if allowed_status:
                        findings = [item for item in all_results if int(item.get("status", 0)) in allowed_status]
                    else:
                        findings = all_results
                    print(json.dumps({"findings": findings}, ensure_ascii=False))
                except Exception:
                    print(json.dumps({"error":"invalid json report", "path": out}, ensure_ascii=False))
            else:
                with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
                    out = f.name
                cmd_target = cmd + ["-o", out]
                run(cmd_target)
                pat = re.compile(
                    r"^(?:\[[^\]]+\]\s*)?"               # optional [time] prefix
                    r"(?P<code>\d{3})\s+"                # status
                    r"(?P<size>\S+)?\s*"                 # optional size "169B", "5KB"
                    r"(?P<url>https?://\S+?)"            # source URL (non-greedy)
                    r"(?:\s*->\s*(?P<redirect>\S+))?"    # optional "-> target"
                    r"\s*$",
                    re.IGNORECASE
                )
                with open(out, "r", encoding="utf-8", errors="ignore") as fh:
                    for line in fh:
                        m = pat.search(line)
                        if not m:
                            continue
                        code = int(m.group("code"))
                        if allowed_status and code not in allowed_status:
                            continue
                        url  = m.group("url").rstrip(",);")
                        size = (m.group("size") or "").strip()
                        red  = m.group("redirect")
                        if red:
                            red = red.rstrip(",);")
                        item = {"status": code, "url": url}
                        if size:
                            item["size"] = size
                        if red:
                            item["redirect_to"] = red
                        findings.append(item)
                print(json.dumps({"findings": findings}, ensure_ascii=False))

            # Gửi metadata về Controller cho từng target
            job_id = os.getenv("JOB_ID")
            workflow_id = os.getenv("WORKFLOW_ID")
            if controller_url and target_url:
                try:
                    has_findings = bool(findings)
                    payload = {
                        "target": target_url,
                        "resolved_ips": [],
                        "open_ports": [],
                        "workflow_id": workflow_id,
                        "has_findings": has_findings,
                        "scan_metadata": {
                            "tool": "dirsearch-scan",
                            "job_id": job_id,
                            "vpn_used": vpn_connected,
                            "scan_ip": network_info.get("public_ip", "Unknown"),
                            "vpn_local_ip": network_info.get("local_ip"),
                            "tun_interface": network_info.get("tun_interface", False),
                            "dirsearch_results": findings,
                            "total_findings": len(findings)
                        }
                    }
                    logger.info("Sending result to Controller for %s: %s findings", target_url, len(findings))
                    response = requests.post(f"{controller_url}/api/scan_results", json=payload, timeout=30)
                    logger.info("Controller response: %s", response.status_code)
                except Exception as e:
                    logger.error("Error sending results to Controller: %s", e)
    except Exception as main_err:
        logger.exception("Unhandled error: %s", main_err)
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
        if vpn_connected:
            logger.info("Disconnecting VPN...")
            vpn_manager.disconnect_vpn()


