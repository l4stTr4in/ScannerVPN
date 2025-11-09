# app/api/endpoints/utils.py
import yaml
import os
import logging
from fastapi import APIRouter

router = APIRouter()

# Sửa lại đường dẫn thành đường dẫn tuyệt đối bên trong container
TOOLS_FILE = "/app/tools.yaml"

try:
    with open(TOOLS_FILE, 'r') as f:
        TOOLS_CONFIG = yaml.safe_load(f).get("tools", [])
except FileNotFoundError:
    print(f"!!! LỖI: Không tìm thấy file cấu hình tools tại '{TOOLS_FILE}'.")
    TOOLS_CONFIG = []


# Trả về danh sách các tool đúng format dashboard yêu cầu
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@router.get("/api/tools", summary="Lấy danh sách các tool scan được hỗ trợ (dashboard format)")
def list_supported_tools():
    """
    Trả về danh sách các tool, đúng format dashboard yêu cầu, bổ sung các param thực tế và các cải tiến UI.
    """
    frontend_tools = [
        {
            "id": "port-scan",
            "name": "Quét Cổng (Port Scan)",
            "description": "Sử dụng Nmap để phát hiện các cổng đang mở trên mục tiêu.",
            "fields": [
                {
                    "name": "ports",
                    "label": "Hoặc nhập các cổng cụ thể",
                    "component": "TextInput",
                    "placeholder": "top-1000 or all or 80,443,8080"
                },
                {
                    "name": "scan_type",
                    "label": "Loại scan",
                    "component": "Select",
                    "defaultValue": "-sS",
                    "data": [
                        {"value": "-sS", "label": "TCP SYN (-sS)"},
                        {"value": "-sT", "label": "TCP Connect (-sT)"}
                    ]
                },
                {
                    "name": "scanner_count",
                    "label": "Số lượng scanner song song",
                    "component": "NumberInput",
                    "min": 1,
                    "max": 20
                }
            ]
        },
        {
            "id": "httpx-scan",
            "name": "Kiểm tra HTTPX",
            "description": "Kiểm tra thông tin HTTP, tiêu đề, trạng thái, SSL, v.v.",
            "fields": [
                {"name": "method", "label": "HTTP Method", "component": "Select", "defaultValue": "GET", "data": [
                {"value": "GET", "label": "GET"},
                {"value": "POST", "label": "POST"},
                {"value": "HEAD", "label": "HEAD"}
                ]},
                {"name": "ports", "label": "Cổng quét", "component": "TextInput", "placeholder": "vd: 80,443"},
                {"name": "timeout", "label": "Timeout (giây)", "component": "NumberInput", "defaultValue": 10},
                {"name": "retries", "label": "Số lần thử lại", "component": "NumberInput", "defaultValue": 2},
                {"name": "threads", "label": "Số luồng", "component": "NumberInput", "defaultValue": 10},
                {"name": "status_codes", "label": "Lọc theo mã trạng thái", "component": "TagsInput", "placeholder": "vd: 200,301,404",
                "data": ["200,204", "301,302,307", "400,401,403", "500,502,503"]},
                {"name": "follow_redirects", "label": "Theo dõi chuyển hướng", "component": "Switch", "defaultValue": True},
                {"name": "tech_detect", "label": "Phát hiện công nghệ", "component": "Switch", "defaultValue": True},
                {"name": "title", "label": "Lấy tiêu đề trang", "component": "Switch", "defaultValue": True},
                {"name": "ip", "label": "Lấy địa chỉ IP", "component": "Switch", "defaultValue": True},
                {"name": "web_server", "label": "Lấy thông tin Web Server", "component": "Switch", "defaultValue": True},
                {"name": "response_time", "label": "Lấy thời gian phản hồi", "component": "Switch", "defaultValue": False},
                {"name": "content_length", "label": "Lấy Content-Length", "component": "Switch", "defaultValue": True},
                {"name": "content_type", "label": "Lấy Content-Type", "component": "Switch", "defaultValue": False},
                {"name": "response_size", "label": "Lấy kích thước phản hồi", "component": "Switch", "defaultValue": False},
                {"name": "include_response", "label": "Bao gồm nội dung phản hồi", "component": "Switch", "defaultValue": False},
                {"name": "location", "label": "Lấy Location Header", "component": "Switch", "defaultValue": False},
                {"name": "cname", "label": "Lấy CNAME", "component": "Switch", "defaultValue": False},
                {"name": "cdn", "label": "Kiểm tra CDN", "component": "Switch", "defaultValue": False}
            ]
        },
        {
            "id": "dirsearch-scan",
            "name": "Quét thư mục (Dirsearch)",
            "description": "Tìm kiếm các thư mục và file ẩn trên web server.",
            "fields": [
                {"name": "wordlist", "label": "Wordlist", "component": "TextInput", "placeholder": "/app/dicc.txt", "defaultValue": "/app/dicc.txt"},
                {"name": "extensions", "label": "Phần mở rộng cần quét", "component": "TagsInput", "placeholder": "vd: php,asp,aspx",
                "data": ["php", "html", "js", "aspx", "jsp", "txt", "bak", "config", "env"]},
                {"name": "include_status", "label": "Trạng thái HTTP cần lấy", "component": "TagsInput", "placeholder": "vd: 200,204,301,302,307,401,403"},
                {"name": "recursive", "label": "Quét đệ quy", "component": "Switch", "defaultValue": False},
                {"name": "no_extensions", "label": "Không dùng extensions (-e)", "component": "Switch", "defaultValue": False},
                {"name": "threads", "label": "Số luồng (threads)", "component": "NumberInput", "defaultValue": 30},
                {"name": "scanner_count", "label": "Số lượng scanner song song", "component": "NumberInput", "min": 1, "max": 20},
                {"name": "random_agent", "label": "Random User-Agent", "component": "Switch", "defaultValue": False}
            ]
        },
        {
            "id": "nuclei-scan",
            "name": "Quét Lỗ hổng (Nuclei)",
            "fields": [
                {"name": "severity", "label": "Mức độ nghiêm trọng", "component": "MultiSelect", "defaultValue": ["high", "critical"], "data": ["info", "low", "medium", "high", "critical"]},
                {"name": "templates", "label": "Chạy các mẫu cụ thể", "component": "MultiSelect", "placeholder": "Để trống để chạy các mẫu đề xuất", "data": ["cves", "default-logins", "exposed-panels", "vulnerabilities"]},
                {"name": "distributed-scanning", "label": "Quét phân tán (Distributed Scanning)", "component": "Switch", "defaultValue": False}
            ]
        },
        {
            "id": "wpscan-scan",
            "name": "Quét WordPress (WPScan)",
            "description": "Quét bảo mật WordPress để phát hiện lỗ hổng, plugins và themes có vấn đề.",
            "fields": [
                {
                    "name": "api_token", 
                    "label": "WPScan API Token", 
                    "component": "TextInput", 
                    "placeholder": "Nhập WPScan API token để có kết quả chi tiết hơn",
                    "description": "API token từ https://wpscan.com/api để lấy thông tin vulnerability mới nhất"
                },
                {
                    "name": "enumerate", 
                    "label": "Phát hiện các thành phần", 
                    "component": "MultiSelect", 
                    "defaultValue": ["p", "t"], 
                    "data": [
                        {"value": "p", "label": "Plugins (p)"},
                        {"value": "t", "label": "Themes (t)"},
                        {"value": "u", "label": "Users (u)"}
                    ]
                },
                {
                    "name": "plugins-detection", 
                    "label": "Mức độ phát hiện Plugins", 
                    "component": "Select", 
                    "defaultValue": "passive", 
                    "data": [
                        {"value": "passive", "label": "Passive - Không gây nhiễu"},
                        {"value": "aggressive", "label": "Aggressive - Toàn diện hơn"}
                    ]
                },
                {
                    "name": "themes-detection", 
                    "label": "Mức độ phát hiện Themes", 
                    "component": "Select", 
                    "defaultValue": "passive", 
                    "data": [
                        {"value": "passive", "label": "Passive - Không gây nhiễu"},
                        {"value": "aggressive", "label": "Aggressive - Toàn diện hơn"}
                    ]
                },
                {
                    "name": "disable-tls-checks", 
                    "label": "Bỏ qua kiểm tra TLS", 
                    "component": "Switch", 
                    "defaultValue": False,
                    "description": "Hữu ích khi target có certificate tự ký"
                },
                {
                    "name": "force", 
                    "label": "Force scan", 
                    "component": "Switch", 
                    "defaultValue": False,
                    "description": "Bắt buộc scan ngay cả khi không phát hiện WordPress"
                },
                {
                    "name": "max-threads", 
                    "label": "Max Threads", 
                    "component": "NumberInput", 
                    "defaultValue": 5,
                    "description": "Số thread tối đa cho scan (1-50)"
                },
                {
                    "name": "request-timeout", 
                    "label": "Request Timeout (s)", 
                    "component": "NumberInput", 
                    "defaultValue": 60,
                    "description": "Timeout cho mỗi HTTP request"
                },
                {
                    "name": "connect-timeout", 
                    "label": "Connect Timeout (s)", 
                    "component": "NumberInput", 
                    "defaultValue": 30,
                    "description": "Timeout cho kết nối"
                },
                {
                    "name": "user-agent", 
                    "label": "Custom User-Agent", 
                    "component": "TextInput", 
                    "placeholder": "Override default random user-agent",
                    "description": "User-Agent tùy chỉnh thay cho random"
                }
            ]
        },
        {
            "id": "dns-lookup",
            "name": "Phân giải DNS",
            "fields": []
        },
        {
            "id": "sqlmap-scan",
            "name": "Quét SQL Injection (SQLMap)",
            "description": "Tự động phát hiện và khai thác các lỗ hổng SQL injection.",
            "fields": [
                {"name": "data", "label": "POST data/raw", "component": "TextInput", "placeholder": "vd: id=1&name=test"},
                {"name": "headers", "label": "Headers (JSON hoặc Key:Value)", "component": "TextInput", "placeholder": "User-Agent:sqlmap;X-Forwarded-For:127.0.0.1"},
                {"name": "cookie", "label": "Cookie string", "component": "TextInput", "placeholder": "vd: PHPSESSID=abc; user=admin"},
                {"name": "parameter", "label": "Tham số cần kiểm tra (-p)", "component": "TextInput", "placeholder": "vd: id,username"},
                {"name": "technique", "label": "Kỹ thuật tấn công", "component": "TextInput", "placeholder": "vd: BEUS (Boolean, Error, Union, Stacked)"},
                {"name": "tamper", "label": "Tamper scripts", "component": "TextInput", "placeholder": "vd: between,randomcase"},
                {"name": "level", "label": "Mức độ kiểm tra (Level)", "component": "Select", "defaultValue": 1, "data": [
                {"value": 1, "label": "1 - Cơ bản"},
                {"value": 2, "label": "2 - Trung bình"},
                {"value": 3, "label": "3 - Nâng cao"},
                {"value": 4, "label": "4 - Toàn diện"},
                {"value": 5, "label": "5 - Chuyên sâu"}
                ]},
                {"name": "risk", "label": "Mức độ rủi ro (Risk)", "component": "Select", "defaultValue": 1, "data": [
                {"value": 1, "label": "1 - Thấp"},
                {"value": 2, "label": "2 - Trung bình"},
                {"value": 3, "label": "3 - Cao"}
                ]},
                {"name": "dbms", "label": "Chỉ định DBMS", "component": "TextInput", "placeholder": "vd: MySQL, PostgreSQL"},
                {"name": "identify_waf", "label": "Thử nhận diện WAF", "component": "Switch", "defaultValue": False},
                {"name": "skip_urlencode", "label": "Không URL-encode payloads", "component": "Switch", "defaultValue": False},
                {"name": "random_agent", "label": "Random User-Agent", "component": "Switch", "defaultValue": False},
                {"name": "batch", "label": "Chạy tự động (batch mode)", "component": "Switch", "defaultValue": True},
                {"name": "threads", "label": "Số luồng (threads)", "component": "NumberInput", "defaultValue": 1},
                {"name": "delay", "label": "Delay giữa requests (giây)", "component": "NumberInput", "defaultValue": 0},
                {"name": "timeout", "label": "Timeout (giây)", "component": "NumberInput", "defaultValue": 30},
                {"name": "retries", "label": "Số lần thử lại", "component": "NumberInput", "defaultValue": 2}
            ]
            },
        {
            "id": "bruteforce",
            "name": "Dò mật khẩu (Bruteforce)",
            "description": "Thực hiện tấn công dò mật khẩu vào các dịch vụ HTTP, SSH, FTP. Có thể nhập thủ công hoặc sử dụng job.json từ FFUF.",
            "fields": [
                # Input Mode Selection
                {"name": "input_mode", "label": "Phương thức nhập liệu", "component": "Select", "defaultValue": "manual", "data": [
                    {"value": "manual", "label": "Nhập thủ công"},
                    {"value": "job_json", "label": "Sử dụng Job JSON từ FFUF"}
                ]},
                
                # Job JSON Mode
                {"name": "job_json_content", "label": "Nội dung Job JSON", "component": "Textarea", "placeholder": "Paste job.json content từ FFUF tool...", "conditional": {"field": "input_mode", "value": "job_json"}},
                {"name": "note", "label": "Lưu ý", "component": "Textarea", "placeholder": "Các tham số dưới đây chỉ nhập khi input_mode là manual"},
                # Manual Mode - Strategy
                {"name": "strategy", "label": "Chiến lược tấn công", "component": "Select", "defaultValue": "dictionary", "data": [
                    {"value": "dictionary", "label": "Dictionary (Một user - nhiều pass)"},
                    {"value": "spray", "label": "Password Spraying (Một pass - nhiều user)"},
                    {"value": "stuffing", "label": "Credential Stuffing (Cặp user:pass)"}
                ], "conditional": {"field": "input_mode", "value": "manual"}},
                
                # Manual Mode - Protocol
                {"name": "protocol", "label": "Giao thức", "component": "Select", "defaultValue": "http_form", "data": [
                    {"value": "http_form", "label": "HTTP Form Login"},
                    {"value": "ssh", "label": "SSH"},
                    {"value": "ftp", "label": "FTP"}
                ], "conditional": {"field": "input_mode", "value": "manual"}},
                
                # Manual Mode - Target Config for HTTP
                {"name": "login_url", "label": "URL trang đăng nhập", "component": "TextInput", "placeholder": "https://example.com/login", "conditional": {"field": "protocol", "value": "http_form"}},
                {"name": "username_field", "label": "Tên field username", "component": "TextInput", "defaultValue": "username", "placeholder": "username, email, user", "conditional": {"field": "protocol", "value": "http_form"}},
                {"name": "password_field", "label": "Tên field password", "component": "TextInput", "defaultValue": "password", "placeholder": "password, pass, pwd", "conditional": {"field": "protocol", "value": "http_form"}},
                {"name": "csrf_token_selector", "label": "CSS Selector cho CSRF token (optional)", "component": "TextInput", "placeholder": "input[name='_token']", "conditional": {"field": "protocol", "value": "http_form"}},
                {"name": "success_indicator", "label": "Dấu hiệu đăng nhập thành công", "component": "Select", "defaultValue": "redirect", "data": [
                    {"value": "redirect", "label": "Redirect (3xx status)"},
                    {"value": "status_200", "label": "Status 200"},
                    {"value": "body_contains", "label": "Body chứa text"},
                    {"value": "cookie_set", "label": "Cookie được set"}
                ], "conditional": {"field": "protocol", "value": "http_form"}},
                {"name": "success_text", "label": "Text thành công (nếu chọn body_contains)", "component": "TextInput", "placeholder": "welcome, dashboard, success", "conditional": {"field": "success_indicator", "value": "body_contains"}},
                
                # Manual Mode - Performance Settings
                {"name": "concurrency", "label": "Số luồng (concurrency)", "component": "NumberInput", "defaultValue": 2, "min": 1, "max": 10, "conditional": {"field": "input_mode", "value": "manual"}},
                {"name": "rate_per_min", "label": "Tốc độ (requests/phút)", "component": "NumberInput", "defaultValue": 10, "min": 1, "max": 100, "conditional": {"field": "input_mode", "value": "manual"}},
                {"name": "timeout_sec", "label": "Timeout (giây)", "component": "NumberInput", "defaultValue": 15, "min": 5, "max": 60, "conditional": {"field": "input_mode", "value": "manual"}},
                {"name": "jitter_ms", "label": "Jitter (ms)", "component": "TextInput", "defaultValue": "100,300", "placeholder": "100,300", "conditional": {"field": "input_mode", "value": "manual"}},
                {"name": "stop_on_success", "label": "Dừng khi tìm thấy credential", "component": "Switch", "defaultValue": True, "conditional": {"field": "input_mode", "value": "manual"}},
                
                # Manual Mode - Wordlist Source
                {"name": "wordlist_source", "label": "Nguồn wordlist", "component": "Select", "defaultValue": "builtin", "data": [
                    {"value": "builtin", "label": "Sử dụng wordlist có sẵn"},
                    {"value": "custom", "label": "Nhập thủ công"}
                ], "conditional": {"field": "input_mode", "value": "manual"}},
                
                # Manual Mode - Built-in Wordlists
                {"name": "users_wordlist", "label": "Wordlist usernames", "component": "Select", "defaultValue": "users.txt", "data": [
                    {"value": "users.txt", "label": "users.txt (82 usernames)"}
                ], "conditional": {"field": "wordlist_source", "value": "builtin"}},
                {"name": "passwords_wordlist", "label": "Wordlist passwords", "component": "Select", "defaultValue": "passwords.txt", "data": [
                    {"value": "passwords.txt", "label": "passwords.txt (120+ passwords)"}
                ], "conditional": {"field": "wordlist_source", "value": "builtin"}},
                {"name": "pairs_wordlist", "label": "Wordlist user:pass pairs", "component": "Select", "defaultValue": "pairs.txt", "data": [
                    {"value": "pairs.txt", "label": "pairs.txt (60+ combinations)"}
                ], "conditional": {"field": "wordlist_source", "value": "builtin"}},
                
                # Manual Mode - Custom Input
                {"name": "users_list", "label": "Danh sách Username", "component": "Textarea", "placeholder": "Nhập mỗi username một dòng...", "conditional": {"field": "wordlist_source", "value": "custom"}},
                {"name": "passwords_list", "label": "Danh sách Password", "component": "Textarea", "placeholder": "Nhập mỗi password một dòng...", "conditional": {"field": "wordlist_source", "value": "custom"}},
                {"name": "pairs_list", "label": "Danh sách cặp User:Pass", "component": "Textarea", "placeholder": "Nhập mỗi cặp user:pass một dòng...", "conditional": {"field": "wordlist_source", "value": "custom"}}
            ]
        },
        {
            "id": "ffuf-entry",
            "name": "Tìm kiếm Login Form (FFUF)",
            "description": "Sử dụng FFUF để tìm kiếm các endpoint login và tự động tạo profile cho bruteforce. Có thể chọn option emit_job để tự động tạo file job.json cho tool bruteforce sử dụng.",
            "fields": [
                {"name": "wordlist", "label": "Wordlist endpoints", "component": "Select", "defaultValue": "default", "data": [
                    {"value": "default", "label": "Sử dụng wordlist mặc định"},
                    {"value": "common.txt", "label": "common.txt"},
                    {"value": "admin-panels.txt", "label": "admin-panels.txt"}
                ]},
                {"name": "rate", "label": "Tốc độ request/giây", "component": "NumberInput", "defaultValue": 50, "min": 1, "max": 200},
                {"name": "threads", "label": "Số luồng FFUF", "component": "NumberInput", "defaultValue": 50, "min": 1, "max": 100},
                {"name": "codes", "label": "HTTP status codes quan tâm", "component": "TagsInput", "defaultValue": ["200", "301", "302", "401", "403"], "placeholder": "200,301,302,401,403"},
                {"name": "timeout", "label": "Timeout scan (giây)", "component": "NumberInput", "defaultValue": 60, "min": 10, "max": 300},
                {"name": "insecure", "label": "Bỏ qua SSL verification", "component": "Switch", "defaultValue": False},
                
                # Emit Job Parameters cho Bruteforce
                {"name": "emit_job", "label": "Tạo job.json sử dụng cho tool bruteforce", "component": "Switch", "defaultValue": True},
                {"name": "note", "label": "Lưu ý", "component": "Textarea", "placeholder": "Các tham số dưới đây chỉ nhập khi input emit_job được bật"},
                {"name": "users_wordlist", "label": "Wordlist usernames", "component": "Select", "defaultValue": "users.txt", "data": [
                    {"value": "users.txt", "label": "users.txt"}
                ], "conditional": {"field": "emit_job", "value": True}},
                {"name": "passwords_wordlist", "label": "Wordlist passwords", "component": "Select", "defaultValue": "passwords.txt", "data": [
                    {"value": "passwords.txt", "label": "passwords.txt"}
                ], "conditional": {"field": "emit_job", "value": True}},
                {"name": "pairs_wordlist", "label": "Wordlist user:pass pairs (optional)", "component": "Select", "defaultValue": "pairs.txt", "data": [
                    {"value": "pairs.txt", "label": "pairs.txt"}
                ], "conditional": {"field": "emit_job", "value": True}},
                
                # Bruteforce Strategy
                {"name": "bf_strategy", "label": "Chiến lược bruteforce", "component": "Select", "defaultValue": "dictionary", "data": [
                    {"value": "dictionary", "label": "Dictionary Attack"},
                    {"value": "spray", "label": "Password Spraying"},
                    {"value": "stuffing", "label": "Credential Stuffing"}
                ], "conditional": {"field": "emit_job", "value": True}},
                {"name": "bf_concurrency", "label": "Số luồng bruteforce", "component": "NumberInput", "defaultValue": 2, "min": 1, "max": 10, "conditional": {"field": "emit_job", "value": True}},
                {"name": "bf_rate_per_min", "label": "Tốc độ bruteforce (req/phút)", "component": "NumberInput", "defaultValue": 10, "min": 1, "max": 100, "conditional": {"field": "emit_job", "value": True}},
                {"name": "bf_jitter", "label": "Jitter (ms)", "component": "TextInput", "defaultValue": "100,300", "placeholder": "100,300", "conditional": {"field": "emit_job", "value": True}},
                {"name": "bf_timeout_sec", "label": "Timeout bruteforce (giây)", "component": "NumberInput", "defaultValue": 15, "min": 5, "max": 60, "conditional": {"field": "emit_job", "value": True}},
                {"name": "bf_stop_on_success", "label": "Dừng khi tìm thấy credential", "component": "Switch", "defaultValue": True, "conditional": {"field": "emit_job", "value": True}}
            ]
        }
    ]
    logger.info(f"API call to /api/tools, returning {len(frontend_tools)} tools (dashboard format)")
    return {"tools": frontend_tools}

# Giữ nguyên endpoint gốc: GET /debug/info
@router.get("/debug/info", summary="Endpoint debug cơ bản")
def get_debug_info():
    return {"status": "ok", "service": "Controller API - Refactored"}