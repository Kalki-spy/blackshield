#!/usr/bin/env python3
import os, sys
sys.path.insert(0, os.path.dirname(__file__))
import activity_log
"""
Port Scanner Backend
Pure Python — stdlib only (no external deps)

Usage:
    python port_scanner_server.py

Endpoints:
    GET  /health                        - health check
    GET  /portscan/services             - known service + risk map
    POST /portscan                      - TCP scan (body: host, ports, timeout, threads, banners)
    POST /portscan/quick                - common ports only (body: host)
    POST /portscan/range                - range scan (body: host, start, end, timeout, threads)
"""

import socket
import json
import datetime
import concurrent.futures
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
import os
PORT = int(os.environ.get("PORT", 5017))
SCAN_TIMEOUT = 1.0
MAX_PORTS    = 500
MAX_THREADS  = 150

# ── Service / risk maps ───────────────────────────────────────────────────────

COMMON_PORTS = {
    21:    "FTP",
    22:    "SSH",
    23:    "Telnet",
    25:    "SMTP",
    53:    "DNS",
    80:    "HTTP",
    110:   "POP3",
    135:   "MSRPC",
    137:   "NetBIOS-NS",
    139:   "NetBIOS",
    143:   "IMAP",
    443:   "HTTPS",
    445:   "SMB",
    993:   "IMAPS",
    995:   "POP3S",
    1433:  "MSSQL",
    1521:  "Oracle",
    2181:  "Zookeeper",
    3000:  "HTTP-Dev",
    3306:  "MySQL",
    3389:  "RDP",
    4444:  "Metasploit",
    5000:  "Flask/UPnP",
    5432:  "PostgreSQL",
    5900:  "VNC",
    5984:  "CouchDB",
    6379:  "Redis",
    8080:  "HTTP-Alt",
    8443:  "HTTPS-Alt",
    8888:  "HTTP-Dev2",
    9200:  "Elasticsearch",
    9300:  "Elasticsearch-Cluster",
    11211: "Memcached",
    27017: "MongoDB",
    27018: "MongoDB-Shard",
}

RISKY_PORTS  = {21, 23, 135, 137, 139, 445, 1433, 3389, 4444, 5900,
                6379, 11211, 27017, 27018, 9200, 5984, 2181}
LEGACY_PORTS = {21, 23, 110, 995, 143, 993}

# ── Core scan logic ───────────────────────────────────────────────────────────

def _resolve(host: str):
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None


def _tcp_probe(host: str, port: int, timeout: float = SCAN_TIMEOUT):
    t0 = time.time()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, round((time.time() - t0) * 1000, 2)
    except Exception:
        return False, -1.0


def _banner_grab(host: str, port: int, timeout: float = 0.8) -> str:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
            except Exception:
                pass
            try:
                return s.recv(256).decode(errors="ignore").strip()[:120]
            except Exception:
                return ""
    except Exception:
        return ""


def _risk(port: int, open_: bool) -> str:
    if not open_:        return "none"
    if port in RISKY_PORTS:  return "high"
    if port in LEGACY_PORTS: return "medium"
    return "low"


def port_scan(host: str, ports: list, timeout: float = SCAN_TIMEOUT,
              grab_banners: bool = False, threads: int = MAX_THREADS) -> list:
    results = []
    workers = min(len(ports), threads)
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        fm = {ex.submit(_tcp_probe, host, p, timeout): p for p in ports}
        for future in concurrent.futures.as_completed(fm):
            p = fm[future]
            try:
                open_, lat = future.result(timeout=timeout + 1)
            except Exception:
                open_, lat = False, -1.0

            banner = _banner_grab(host, p) if open_ and grab_banners else ""
            results.append({
                "port":    p,
                "open":    open_,
                "service": COMMON_PORTS.get(p, "unknown"),
                "latency": lat if lat >= 0 else None,
                "risk":    _risk(p, open_),
                "banner":  banner,
            })
    return sorted(results, key=lambda r: r["port"])


def _parse_ports(raw: str) -> list:
    raw = raw.strip()
    if not raw or raw.lower() == "common":
        return sorted(COMMON_PORTS.keys())
    ports = []
    for part in raw.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            ports.extend(range(int(lo), min(int(hi) + 1, int(lo) + MAX_PORTS)))
        else:
            ports.append(int(part))
    return ports[:MAX_PORTS]


def _summary(results: list) -> dict:
    open_r = [r for r in results if r["open"]]
    return {
        "total_scanned": len(results),
        "open_count":    len(open_r),
        "high_risk":     sum(1 for r in open_r if r["risk"] == "high"),
        "medium_risk":   sum(1 for r in open_r if r["risk"] == "medium"),
        "low_risk":      sum(1 for r in open_r if r["risk"] == "low"),
        "open_ports":    [r["port"] for r in open_r],
    }

# ── HTTP handler ──────────────────────────────────────────────────────────────

def parse_body(h):
    length = int(h.headers.get("Content-Length", 0))
    raw = h.rfile.read(length) if length else b""
    try:
        return json.loads(raw.decode())
    except Exception:
        return {}


class PortScanHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin",  "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
        self.send_header("Access-Control-Max-Age",       "86400")

    def do_OPTIONS(self):
        self.send_response(200)
        self._cors()
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _json(self, status: int, data: dict):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type",   "application/json")
        self.send_header("Content-Length", str(len(body)))
        self._cors()
        self.end_headers()
        self.wfile.write(body)

    # ── GET ───────────────────────────────────────────────────────────────────

    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path == "/health":
            self._json(200, {"status": "ok", "service": "Port Scanner"})
            return

        if parsed.path == "/portscan/services":
            self._json(200, {
                "services":     COMMON_PORTS,
                "risky_ports":  sorted(RISKY_PORTS),
                "legacy_ports": sorted(LEGACY_PORTS),
            })
            return

        self._json(404, {"error": "Not found"})

    # ── POST ──────────────────────────────────────────────────────────────────

    def do_POST(self):
        parsed = urlparse(self.path)

        # /portscan — flexible port spec ──────────────────────────────────────
        if parsed.path == "/portscan":
            body = parse_body(self)
            host = body.get("host", "").strip()
            if not host:
                self._json(400, {"error": "Missing field: host"}); return

            ip = _resolve(host)
            if not ip:
                self._json(400, {"error": f"Cannot resolve host: {host}"}); return

            user_id     = body.get("user_id")
            ports_raw   = str(body.get("ports", "common"))
            timeout     = float(body.get("timeout", SCAN_TIMEOUT))
            threads     = min(int(body.get("threads", MAX_THREADS)), MAX_THREADS)
            grab_banner = bool(body.get("banners", False))

            try:
                port_list = _parse_ports(ports_raw)
            except ValueError as e:
                self._json(400, {"error": f"Invalid port spec: {e}"}); return

            scan_id = activity_log.start_scan(user_id, "Port Scanner", host) if user_id else None
            try:
                t0      = time.time()
                results = port_scan(host, port_list, timeout, grab_banner, threads)
                elapsed = round(time.time() - t0, 2)

                if user_id:
                    for r in results:
                        if r["open"] and r["risk"] == "high":
                            activity_log.add_finding(
                                user_id, "Port Scanner", host,
                                f"High-risk service exposed on port {r['port']} ({r['service']})",
                                severity="high", scan_id=scan_id,
                            )
                    activity_log.finish_scan(scan_id, status="completed", tool="Port Scanner", target=host, user_id=user_id)
            except Exception:
                if user_id and scan_id:
                    activity_log.finish_scan(scan_id, status="failed", tool="Port Scanner", target=host, user_id=user_id)
                raise

            self._json(200, {
                "host":      host,
                "ip":        ip,
                "timestamp": datetime.datetime.now().isoformat(),
                "elapsed_s": elapsed,
                "summary":   _summary(results),
                "results":   results,
            })
            return

        # /portscan/quick — common ports only ─────────────────────────────────
        if parsed.path == "/portscan/quick":
            body = parse_body(self)
            host = body.get("host", "").strip()
            if not host:
                self._json(400, {"error": "Missing field: host"}); return

            ip = _resolve(host)
            if not ip:
                self._json(400, {"error": f"Cannot resolve host: {host}"}); return

            t0      = time.time()
            results = port_scan(host, sorted(COMMON_PORTS.keys()))
            elapsed = round(time.time() - t0, 2)

            self._json(200, {
                "host":      host,
                "ip":        ip,
                "timestamp": datetime.datetime.now().isoformat(),
                "elapsed_s": elapsed,
                "summary":   _summary(results),
                "results":   results,
            })
            return

        # /portscan/range — numeric range ─────────────────────────────────────
        if parsed.path == "/portscan/range":
            body = parse_body(self)
            host = body.get("host", "").strip()
            if not host:
                self._json(400, {"error": "Missing field: host"}); return

            ip = _resolve(host)
            if not ip:
                self._json(400, {"error": f"Cannot resolve host: {host}"}); return

            try:
                start   = int(body.get("start", 1))
                end     = int(body.get("end",   1024))
                timeout = float(body.get("timeout", SCAN_TIMEOUT))
                threads = min(int(body.get("threads", MAX_THREADS)), MAX_THREADS)
            except (TypeError, ValueError) as e:
                self._json(400, {"error": f"Invalid parameter: {e}"}); return

            if start < 1 or end > 65535 or start > end:
                self._json(400, {"error": "Port range must be 1–65535 with start ≤ end"}); return

            port_list = list(range(start, min(end + 1, start + MAX_PORTS)))
            t0        = time.time()
            results   = port_scan(host, port_list, timeout, False, threads)
            elapsed   = round(time.time() - t0, 2)

            self._json(200, {
                "host":      host,
                "ip":        ip,
                "timestamp": datetime.datetime.now().isoformat(),
                "elapsed_s": elapsed,
                "range":     f"{start}-{end}",
                "summary":   _summary(results),
                "results":   results,
            })
            return

        self._json(404, {"error": "Not found"})


HTTPServer.allow_reuse_address = True

if __name__ == "__main__":
    srv = HTTPServer(("0.0.0.0", PORT), PortScanHandler)
    print(f"[Port Scanner] Running on:{PORT}")
    print(f"  GET  /health              - health check")
    print(f"  GET  /portscan/services   - known service + risk map")
    print(f"  POST /portscan            - full scan (host, ports, timeout, threads, banners)")
    print(f"  POST /portscan/quick      - common ports only (host)")
    print(f"  POST /portscan/range      - range scan (host, start, end, timeout, threads)")
    srv.serve_forever()
