#!/usr/bin/env python3
"""
Port Scanner — logic module for the consolidated app.py
Pure Python — stdlib only (no external deps)

Ported straight from port_scanner_server.py (the standalone dev service on
:5017 that the frontend was actually built and tested against — see
vite.config.ts's proxy target). app.py's /api/network/portscan route had
been calling logic/ddos.py's much simpler scan_ports() instead, which is a
different, older, unrelated implementation (10 hardcoded ports, no risk
tiers beyond one, no banner grab, no activity_log instrumentation, purely
sequential). This module restores full parity with what was verified
working locally.
"""

import socket
import time
import concurrent.futures

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

def resolve(host: str):
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
    if not open_:            return "none"
    if port in RISKY_PORTS:  return "high"
    if port in LEGACY_PORTS: return "medium"
    return "low"


def port_scan(host: str, ports: list, timeout: float = SCAN_TIMEOUT,
              grab_banners: bool = False, threads: int = MAX_THREADS) -> list:
    results = []
    workers = min(len(ports), threads) or 1
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


def parse_ports(raw: str) -> list:
    raw = (raw or "").strip()
    if not raw or raw.lower() == "common":
        return sorted(COMMON_PORTS.keys())
    ports = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            ports.extend(range(int(lo), min(int(hi) + 1, int(lo) + MAX_PORTS)))
        else:
            ports.append(int(part))
    return ports[:MAX_PORTS]


def summary(results: list) -> dict:
    open_r = [r for r in results if r["open"]]
    return {
        "total_scanned": len(results),
        "open_count":    len(open_r),
        "high_risk":     sum(1 for r in open_r if r["risk"] == "high"),
        "medium_risk":   sum(1 for r in open_r if r["risk"] == "medium"),
        "low_risk":      sum(1 for r in open_r if r["risk"] == "low"),
        "open_ports":    [r["port"] for r in open_r],
    }
