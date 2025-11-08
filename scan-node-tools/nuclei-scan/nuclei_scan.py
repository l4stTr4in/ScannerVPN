#!/usr/bin/env python3
import argparse, subprocess, sys, json, os, requests, logging
from vpn_manager import VPNManager

# Configure concise logger (match dns_lookup style)
logger = logging.getLogger("nuclei")
if not logger.handlers:
    h = logging.StreamHandler(stream=sys.stdout)
    h.setFormatter(logging.Formatter("[NUCLEI] %(levelname)s: %(message)s"))
    logger.addHandler(h)
    logger.setLevel(logging.INFO)

SEV_ORDER = {"info":0, "low":1, "medium":2, "high":3, "critical":4}

def sev_ok(sev: str, min_sev: str) -> bool:
    s = (sev or "").lower()
    return SEV_ORDER.get(s, 0) >= SEV_ORDER.get(min_sev.lower(), 0)

def pick_json_flag():
    # Ưu tiên -jsonl (v3.x). Nếu không có thì fallback -json (rất cũ).
    try:
        h = subprocess.run(["nuclei", "-h"], capture_output=True, text=True).stdout
        if "-jsonl" in h or "--jsonl" in h:
            return "-jsonl"
        if "-json" in h or "--json" in h:
            return "-json"
    except Exception:
        pass
    return "-jsonl"

def build_cmd(args, json_flag):
    cmd = ["nuclei", json_flag, "-silent", "-nc"]  # -nc: no-color
    # target
    if args.list_file: cmd += ["-list", args.list_file]
    else:              cmd += ["-u", args.target]
    # templates/filters
    def add_multi(flag, val):
        for x in val.split(","):
            x = x.strip()
            if x: cmd.extend([flag, x])
    if args.templates:           add_multi("-t", args.templates)
    if args.workflows:           add_multi("-w", args.workflows)
    if args.tags:                cmd += ["-tags", args.tags]
    if args.severity:            cmd += ["-severity", args.severity]
    if args.exclude_templates:   cmd += ["-exclude-templates", args.exclude_templates]
    if args.exclude_tags:        cmd += ["-exclude-tags", args.exclude_tags]
    if args.exclude_severity:    cmd += ["-exclude-severity", args.exclude_severity]
    # perf
    if args.rate_limit:          cmd += ["-rl", str(args.rate_limit)]
    if args.concurrency:         cmd += ["-c", str(args.concurrency)]
    return cmd

# test nhanh
# docker run --rm nuclei-scan:dev `
#   --target http://testphp.vulnweb.com `
#   --templates /root/nuclei-templates/http `
#   --rate-limit 15 `
#   --concurrency 15 `
#   --compact `
#   --min-severity medium

# quét hết lỗi - khá lâu
# docker run --rm nuclei-scan:dev `
#   --target http://testphp.vulnweb.com `
#   --templates /root/nuclei-templates/http/vulnerabilities `
#   --severity medium,high,critical `
#   --rate-limit 8 `
#   --concurrency 8 | Select-Object -First 30

#scan 1 lỗ hổng cụ thể - xss
# docker run --rm nuclei-scan:dev `
#   --target http://testphp.vulnweb.com `
#   --tags xss `
#   --severity low,medium,high,critical `
#   --headless `
#   --rate-limit 8 `
#   --concurrency 8 `
#   --compact `
#   --min-severity low | Select-Object -First 30

# scan theo tag
# docker run --rm nuclei-scan:dev `
#   --target http://testphp.vulnweb.com `
#   --tags sqli,xss,cmdi `
#   --severity medium,high,critical `
#   --rate-limit 10 `
#   --concurrency 10 `
#   --compact `
#   --min-severity medium | Select-Object -First 30

# các kết quả có thể trống vì --min-severity không có mức info nên nếu muốn thêm thông tin thì có thể thay nó bằng info: ví dụ
# docker run --rm nuclei-scan:dev `
#   --target http://testphp.vulnweb.com `
#   --templates /root/nuclei-templates/http `
#   --rate-limit 15 `
#   --concurrency 15 `
#   --compact `
#   --min-severity info 

if __name__ == "__main__":
    logger.info("Starting Nuclei scan with VPN...")
    
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
            logger.error("Failed to parse VPN assignment: %s", e)
    
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
                logger.error("Failed to notify controller connect: %s", notify_err)
    except Exception as e:
        logger.warning("VPN setup error: %s, continuing without VPN...", e)


    try:
        # Parse arguments và targets
        parser = argparse.ArgumentParser(description="Wrapper Nuclei -> JSONL (compact option)")
        # Target
        parser.add_argument("--target", help="URL/IP 1 mục tiêu")
        parser.add_argument("--list-file", help="File danh sách mục tiêu, mỗi dòng 1 URL/IP")
        # Templates / filter
        parser.add_argument("--tags")
        parser.add_argument("--severity")
        parser.add_argument("--templates")
        parser.add_argument("--workflows")
        parser.add_argument("--exclude-templates")
        parser.add_argument("--exclude-tags")
        parser.add_argument("--exclude-severity")
        # Hiệu năng
        parser.add_argument("--rate-limit", type=int)
        parser.add_argument("--concurrency", type=int)
        # Output kiểm soát
        parser.add_argument("--compact", action="store_true", help="In JSONL tối giản cho pentest")
        parser.add_argument("--min-severity", default="info", help="Ngưỡng tối thiểu khi --compact (vd: medium)")
        parser.add_argument("--strip-http", action="store_true", help="Bỏ request/response/curl-command trong output đầy đủ")

        # Lấy targets từ environment hoặc arguments
        targets_env = os.getenv("TARGETS", "").split(",") if os.getenv("TARGETS") else []
        targets_env = [t.strip() for t in targets_env if t.strip()]

        # Xử lý positional arguments (nếu có) thành --target hoặc --list-file
        # Nếu sys.argv có phần tử không phải flag (không bắt đầu bằng '-') thì chuyển thành --target hoặc --list-file
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
                if arg in ["--target", "--list-file", "--tags", "--severity", "--templates", "--workflows", "--exclude-templates", "--exclude-tags", "--exclude-severity", "--rate-limit", "--concurrency", "--min-severity"]:
                    if i < len(sys.argv):
                        new_argv.append(sys.argv[i])
                        i += 1
            else:
                extra_targets.append(arg)
                i += 1

        # Nếu có extra_targets, ưu tiên --list-file nếu nhiều target, --target nếu 1 target
        if extra_targets:
            if len(extra_targets) == 1:
                new_argv.extend(["--target", extra_targets[0]])
            else:
                # Ghi ra file tạm
                with open('/tmp/targets.txt', 'w') as f:
                    for t in extra_targets:
                        f.write(f"{t}\n")
                new_argv.extend(["--list-file", '/tmp/targets.txt'])

        # Nếu có targets_env, ghi ra file tạm (ưu tiên targets_env hơn positional)
        if targets_env:
            with open('/tmp/targets.txt', 'w') as f:
                for target in targets_env:
                    f.write(f"{target}\n")
            if '--list-file' not in new_argv:
                new_argv.extend(['--list-file', '/tmp/targets.txt'])

        sys.argv = new_argv
        args = parser.parse_args()

        if not args.target and not args.list_file:
            print(json.dumps({"error":"missing --target or --list-file"})); 
            sys.exit(2)

        # Chạy Nuclei scan
        job_id = os.getenv("JOB_ID")
        workflow_id = os.getenv("WORKFLOW_ID")
        
        logger.info("Starting Nuclei scan...")
        logger.info("Job ID: %s", job_id)
        logger.info("Workflow ID: %s", workflow_id)
        
        json_flag = pick_json_flag()
        cmd = build_cmd(args, json_flag)
        
        logger.info("Running command: %s", ' '.join(cmd))
        
        # Chạy streaming, chỉ xử lý các dòng JSON hợp lệ
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)

        dedupe = set()  # chống trùng (id, matched-at)
        err_text = []
        scan_results = []

        try:
            for line in p.stdout:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except Exception:
                    # bỏ qua dòng không phải JSON (bảng update index, banner…)
                    continue

                # Tuỳ chọn lọc & tối giản
                if args.compact:
                    info = rec.get("info", {}) or {}
                    sev  = (info.get("severity") or "").lower()
                    if not sev_ok(sev, args.min_severity):
                        continue
                    out = {
                        "id": rec.get("template-id"),
                        "name": info.get("name"),
                        "sev": sev,
                        "host": rec.get("host"),
                        "url": rec.get("url"),
                        "matched": rec.get("matched-at") or rec.get("url"),
                    }
                    # bằng chứng/evidence: extracted-results nếu có
                    if rec.get("extracted-results"):
                        out["evidence"] = rec["extracted-results"]
                    # chống trùng theo (id, matched)
                    key = (out.get("id"), out.get("matched"))
                    if key in dedupe:
                        continue
                    dedupe.add(key)
                    print(json.dumps(out, ensure_ascii=False))
                    scan_results.append(out)
                    continue

                # Chế độ đầy đủ: có thể strip HTTP
                if args.strip_http:
                    for k in ("request", "response", "curl-command"):
                        if k in rec:
                            del rec[k]
                print(json.dumps(rec, ensure_ascii=False))
                scan_results.append(rec)

            p.wait()
        finally:
            # gom stderr (nếu fail)
            err_text = p.stderr.read().strip().splitlines() if p.stderr else []

        rc = p.returncode
        # Nuclei: 0 (không phát hiện), 1 (có phát hiện) → đều là success
        if rc not in (0, 1):
            print(json.dumps({
                "error":"nuclei failed",
                "code": rc,
                "stderr": "\n".join(err_text)
            }, ensure_ascii=False))
            sys.exit(rc)
            
        # Gửi kết quả về Controller nếu có callback URL
        if controller_url and targets_env:
            try:
                for target in targets_env:
                    # Tìm các kết quả liên quan đến target này
                    target_results = []
                    for result in scan_results:
                        if target in str(result.get("host", "")) or target in str(result.get("url", "")):
                            # Luôn loại bỏ trường response/request/curl-command nếu có
                            filtered = dict(result)
                            for k in ("response", "request", "curl-command"):
                                if k in filtered:
                                    del filtered[k]
                            target_results.append(filtered)
                    has_findings = bool(target_results)
                    payload = {
                        "target": target,
                        "resolved_ips": [],
                        "open_ports": [],
                        "workflow_id": workflow_id,
                        "has_findings": has_findings,
                        "scan_metadata": {
                            "tool": "nuclei-scan",
                            "job_id": job_id,
                            "vpn_used": vpn_connected,
                            "scan_ip": network_info.get("public_ip", "Unknown"),
                            "vpn_local_ip": network_info.get("local_ip"),
                            "tun_interface": network_info.get("tun_interface", False),
                            "nuclei_results": target_results,
                            "total_findings": len(target_results)
                        }
                    }
                    logger.info("Sending result to Controller for %s: %s findings", target, len(target_results))
                    response = requests.post(f"{controller_url}/api/scan_results", json=payload, timeout=30)
                    logger.info("Controller response: %s", response.status_code)
            except Exception as e:
                logger.error("Error sending results to Controller: %s", e)

        logger.info("Nuclei scan completed. Total findings: %s", len(scan_results))
        
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
        # Cleanup temp files
        try:
            if os.path.exists('/tmp/targets.txt'):
                os.remove('/tmp/targets.txt')
        except:
            pass
