#!/usr/bin/env python3
import os, sys
sys.path.insert(0, os.path.dirname(__file__))
import activity_log
"""
Gobuster-style Directory/File Brute-Force Backend
Pure Python stdlib — no pip installs required

Usage:
    python gobuster_server.py

Endpoints:
    GET /health                    — health check
    GET /scan?url=...&mode=...     — run directory/file/subdomain scan
        params:
            url    : target URL (required)
            mode   : "dir" | "file" | "both" (default: dir)
            ext    : comma-separated extensions e.g. "php,html,txt" (default: php,html,txt,js,json)
            threads: number of concurrent workers (default: 30, max: 50)
"""

import json
import socket
import urllib.request
import urllib.error
import concurrent.futures
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, urljoin


# ── Configuration ──────────────────────────────────────────────────────────────
import os
PORT = int(os.environ.get("PORT", 8767))
ALLOWED_ORIGINS = ["*"]
REQUEST_TIMEOUT = 6
MAX_WORKERS     = 50
USER_AGENT      = "Mozilla/5.0 (GobusterClone/1.0)"
# ──────────────────────────────────────────────────────────────────────────────


# ── Wordlists ──────────────────────────────────────────────────────────────────

DIR_WORDLIST = [
    # Common dirs
    "admin", "administrator", "login", "dashboard", "panel", "cp", "cpanel",
    "wp-admin", "wp-content", "wp-includes", "wp-login", "wordpress",
    "phpmyadmin", "pma", "mysql", "db", "database",
    "api", "api/v1", "api/v2", "rest", "graphql", "swagger", "docs", "documentation",
    "backup", "backups", "bak", "old", "temp", "tmp", "cache",
    "uploads", "upload", "files", "file", "assets", "static", "media",
    "images", "img", "css", "js", "scripts", "fonts",
    "includes", "inc", "lib", "library", "vendor", "node_modules",
    "config", "conf", "settings", "setup", "install", "installer",
    "test", "tests", "dev", "development", "staging", "beta",
    "user", "users", "account", "accounts", "profile", "register",
    "search", "shop", "store", "cart", "checkout", "payment",
    "blog", "news", "forum", "contact", "about", "help", "support",
    "mail", "email", "webmail", "smtp",
    "server-status", "server-info", ".git", ".svn", ".env",
    ".htaccess", ".htpasswd", "robots.txt", "sitemap.xml",
    "crossdomain.xml", "clientaccesspolicy.xml",
    "phpinfo.php", "info.php", "test.php",
    "index", "home", "main", "default", "error", "404",
    "cgi-bin", "bin", "sbin", "etc",
    "private", "secret", "hidden", "internal",
    "log", "logs", "error_log", "access_log",
    "download", "downloads", "report", "reports",
    "xml", "json", "data", "export", "import",
    "mobile", "m", "wap", "app", "apps",
    "portal", "intranet", "extranet",
    "security", "ssl", "ssh", "ftp",
    "console", "terminal", "shell",
    "ajax", "xhr", "callback",
    "feed", "rss", "atom",
    "sitemap", "robots",
    "version", "changelog", "readme", "readme.txt", "readme.md",
    "license", "license.txt",
    "manager", "management", "manage",
    "webservice", "service", "services",
]

FILE_EXTENSIONS = ["php", "html", "htm", "txt", "js", "json", "xml", "bak", "old", "zip", "sql", "log", "cfg", "conf", "ini"]

SENSITIVE_PATHS = {
    ".git/HEAD", ".git/config", ".env", ".env.local", ".env.production",
    ".htaccess", ".htpasswd", "web.config", "config.php", "wp-config.php",
    "database.yml", "database.php", "db_config.php", "config.yml",
    "phpinfo.php", "info.php", "test.php",
    "robots.txt", "sitemap.xml",
    "README.md", "readme.txt", "CHANGELOG.md",
    "composer.json", "package.json", "yarn.lock",
    "Dockerfile", "docker-compose.yml",
    ".DS_Store", "Thumbs.db",
}


# ── HTTP Probe ─────────────────────────────────────────────────────────────────

def probe_url(url: str) -> dict | None:
    """
    Send a HEAD request (fallback GET) to a URL.
    Returns result dict if interesting (not 404/410), None otherwise.
    """
    try:
        req = urllib.request.Request(
            url,
            method="HEAD",
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "*/*",
                "Connection": "close",
            }
        )
        try:
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
                status = resp.status
                content_length = resp.headers.get("Content-Length", "")
                content_type   = resp.headers.get("Content-Type", "").split(";")[0].strip()
                redirect_to    = resp.url if resp.url != url else None
        except urllib.error.HTTPError as e:
            status         = e.code
            content_length = ""
            content_type   = ""
            redirect_to    = None

        # Skip clearly not-found responses
        if status in (404, 410, 400):
            return None

        # Categorise
        if status in (200, 201, 204):
            flag = "found"
        elif status in (301, 302, 303, 307, 308):
            flag = "redirect"
        elif status == 403:
            flag = "forbidden"
        elif status == 401:
            flag = "auth_required"
        elif status in (500, 503):
            flag = "error"
        else:
            flag = "other"

        # Extra sensitivity check
        path     = urlparse(url).path.lstrip("/")
        is_sensitive = any(path.endswith(sp) or sp in path for sp in SENSITIVE_PATHS)

        return {
            "url":         url,
            "path":        "/" + path,
            "status":      status,
            "flag":        flag,
            "size":        content_length or "—",
            "type":        content_type   or "—",
            "redirect":    redirect_to,
            "sensitive":   is_sensitive,
        }

    except (urllib.error.URLError, socket.timeout, OSError):
        return None
    except Exception:
        return None


# ── Scanner ────────────────────────────────────────────────────────────────────

def run_scan(base_url: str, mode: str = "dir", extensions: list[str] | None = None, max_workers: int = 30) -> dict:
    """
    Build target list and probe all paths concurrently.
    mode: "dir" | "file" | "both"
    """
    # Normalise base URL
    if not base_url.startswith(("http://", "https://")):
        base_url = "https://" + base_url
    base_url = base_url.rstrip("/")

    parsed   = urlparse(base_url)
    hostname = parsed.hostname or base_url

    # Validate target is reachable
    try:
        socket.setdefaulttimeout(REQUEST_TIMEOUT)
        socket.gethostbyname(hostname)
    except Exception as e:
        return {"error": f"Cannot resolve host: {hostname} — {e}"}

    if extensions is None:
        extensions = ["php", "html", "txt", "js", "json"]

    targets: list[tuple[str, str]] = []  # (url, scan_type)

    # Directory targets
    if mode in ("dir", "both"):
        for word in DIR_WORDLIST:
            targets.append((f"{base_url}/{word}", "dir"))
            targets.append((f"{base_url}/{word}/", "dir"))

    # File targets (dirs + extensions)
    if mode in ("file", "both"):
        for word in DIR_WORDLIST[:60]:   # keep file list manageable
            for ext in extensions:
                targets.append((f"{base_url}/{word}.{ext}", "file"))
        # Also probe bare sensitive paths directly
        for sp in SENSITIVE_PATHS:
            targets.append((f"{base_url}/{sp}", "file"))

    # Deduplicate
    seen     = set()
    unique   = []
    for t in targets:
        if t[0] not in seen:
            seen.add(t[0])
            unique.append(t)

    total_probed = len(unique)
    results      = []
    lock         = threading.Lock()

    workers = min(max_workers, MAX_WORKERS)

    def probe_entry(entry):
        url, scan_type = entry
        result = probe_url(url)
        if result:
            result["scan_type"] = scan_type
            with lock:
                results.append(result)

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        ex.map(probe_entry, unique)

    # Sort: sensitive first, then by status, then alphabetically
    results.sort(key=lambda r: (
        0 if r["sensitive"] else 1,
        0 if r["flag"] == "found" else
        1 if r["flag"] == "auth_required" else
        2 if r["flag"] == "forbidden" else
        3 if r["flag"] == "redirect" else 4,
        r["path"]
    ))

    # Count by flag
    flag_counts: dict[str, int] = {}
    for r in results:
        flag_counts[r["flag"]] = flag_counts.get(r["flag"], 0) + 1

    return {
        "target":        base_url,
        "hostname":      hostname,
        "mode":          mode,
        "extensions":    extensions,
        "total_probed":  total_probed,
        "total_found":   len(results),
        "flag_counts":   flag_counts,
        "results":       results,
    }


# ── HTTP Handler ───────────────────────────────────────────────────────────────

class GobusterHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def send_cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
        self.send_header("Access-Control-Max-Age", "86400")

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
        self.send_header("Access-Control-Max-Age", "86400")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _json(self, status: int, data: dict):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_cors_headers()
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path == "/health":
            self._json(200, {"status": "ok"})
            return

        if parsed.path == "/scan":
            params     = parse_qs(parsed.query)
            url        = params.get("url",     [""])[0].strip()
            mode       = params.get("mode",    ["dir"])[0].strip().lower()
            ext_raw    = params.get("ext",     ["php,html,txt,js,json"])[0].strip()
            threads    = int(params.get("threads", ["30"])[0])
            user_id    = params.get("user_id", [None])[0]
            user_id    = int(user_id) if user_id else None

            if not url:
                self._json(400, {"error": "Missing required parameter: url"})
                return

            if mode not in ("dir", "file", "both"):
                mode = "dir"

            extensions = [e.strip().lstrip(".") for e in ext_raw.split(",") if e.strip()]
            threads    = max(1, min(threads, MAX_WORKERS))

            scan_id = activity_log.start_scan(user_id, "Directory Scanner", url) if user_id else None
            try:
                result = run_scan(url, mode=mode, extensions=extensions, max_workers=threads)
                if user_id and not result.get("error"):
                    for r in result.get("results", []):
                        if r.get("flag") == "found" and r.get("sensitive"):
                            activity_log.add_finding(
                                user_id, "Directory Scanner", url,
                                f"Sensitive path exposed: {r.get('path', r.get('url', '?'))}",
                                severity="medium", scan_id=scan_id,
                            )
                    activity_log.finish_scan(scan_id, status="completed", tool="Directory Scanner", target=url, user_id=user_id)
                self._json(200, result)
            except Exception as e:
                if user_id and scan_id:
                    activity_log.finish_scan(scan_id, status="failed", tool="Directory Scanner", target=url, user_id=user_id)
                self._json(500, {"error": str(e)})
            return

        self._json(404, {"error": "Not found"})


# ── Entry Point ────────────────────────────────────────────────────────────────

HTTPServer.allow_reuse_address = True

if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", PORT), GobusterHandler)
    print(f"[Gobuster] Running on :{PORT}")
    print(f"  GET /health                         — health check")
    print(f"  GET /scan?url=...&mode=dir|file|both — directory/file scan")
    server.serve_forever()