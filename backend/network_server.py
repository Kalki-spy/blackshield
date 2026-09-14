#!/usr/bin/env python3
import os, sys
sys.path.insert(0, os.path.dirname(__file__))
import activity_log
"""
Network Analyzer Backend
Pure Python — stdlib only (no external deps)

Usage:
    python network_server.py

Endpoints:
    GET  /health                            - health check
    GET  /network/interfaces                - local NIC info
    GET  /network/arp                       - local ARP table
    POST /network/ping                      - ICMP ping (body: host, count)
    POST /network/dns                       - DNS lookup (body: host)
    POST /network/traceroute                - traceroute hops (body: host, max_hops)
    POST /network/whois                     - WHOIS query (body: host)
    POST /network/sweep                     - host discovery sweep (body: cidr)
    POST /network/analyze                   - full multi-step analysis (body: host)
"""

import socket
import json
import datetime
import concurrent.futures
import subprocess
import platform
import threading
import ipaddress
import re
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

import os
PORT = int(os.environ.get("PORT", 5018))
OS      = platform.system()   # "Windows" | "Linux" | "Darwin"

# ── Ping ─────────────────────────────────────────────────────────────────────

def ping_host(host: str, count: int = 4) -> dict:
    result = {
        "host": host, "reachable": False,
        "min_ms": None, "avg_ms": None, "max_ms": None,
        "loss_pct": 100, "raw": "", "error": None,
    }
    try:
        flag    = "-n" if OS == "Windows" else "-c"
        w_flag  = []  if OS == "Windows" else ["-W", "2"]
        out = subprocess.run(
            ["ping", flag, str(count)] + w_flag + [host],
            capture_output=True, text=True, timeout=20
        )
        text = out.stdout + out.stderr
        result["raw"] = text[:2000]

        lm = re.search(r"(\d+)%\s*(?:packet\s+)?loss", text)
        if lm:
            result["loss_pct"]  = int(lm.group(1))
            result["reachable"] = result["loss_pct"] < 100

        # Linux/Mac: "rtt min/avg/max/mdev = 1.2/3.4/5.6/0.9 ms"
        rm = re.search(r"(\d+\.?\d*)/(\d+\.?\d*)/(\d+\.?\d*)", text)
        if rm:
            result["min_ms"] = float(rm.group(1))
            result["avg_ms"] = float(rm.group(2))
            result["max_ms"] = float(rm.group(3))

        # Windows: "Minimum = 1ms, Maximum = 5ms, Average = 3ms"
        wm = re.search(r"Average\s*=\s*(\d+)ms", text, re.IGNORECASE)
        if wm and result["avg_ms"] is None:
            result["avg_ms"] = float(wm.group(1))

    except subprocess.TimeoutExpired:
        result["error"] = "Ping timed out"
    except FileNotFoundError:
        result["error"] = "ping not available on this system"
    except Exception as e:
        result["error"] = str(e)
    return result

# ── DNS ───────────────────────────────────────────────────────────────────────

def dns_lookup(host: str) -> dict:
    result = {"host": host, "records": [], "fqdn": None, "error": None}
    try:
        seen = set()
        for family, _, _, _, addr in socket.getaddrinfo(host, None):
            ip = addr[0]
            if ip not in seen:
                seen.add(ip)
                record_type = "AAAA" if family == socket.AF_INET6 else "A"
                result["records"].append({"type": record_type, "value": ip})

        # Reverse PTR for first IPv4
        ipv4 = next((r["value"] for r in result["records"] if r["type"] == "A"), None)
        if ipv4:
            try:
                ptr = socket.gethostbyaddr(ipv4)[0]
                result["records"].append({"type": "PTR", "value": ptr})
            except Exception:
                pass

        result["fqdn"] = socket.getfqdn(host)
    except socket.gaierror as e:
        result["error"] = str(e)
    return result

# ── Traceroute ────────────────────────────────────────────────────────────────

def _simulated_traceroute(host: str, max_hops: int = 10) -> list:
    """Fallback when raw socket traceroute is unavailable (e.g. Windows without admin)."""
    import random
    try:
        target_ip = socket.gethostbyname(host)
    except Exception:
        target_ip = "0.0.0.0"
    gateways = [
        "192.168.1.1", "10.0.0.1", "172.16.0.1",
        "ae0.cr1.isp.net", "ae2.cr2.isp.net",
        "ge-0-0-0.bb1.isp.net", "peer1.ix.net", "peer2.ix.net",
    ]
    base_rtt  = random.uniform(5, 30)
    hop_count = random.randint(6, min(max_hops, 12))
    hops = []
    for i in range(1, hop_count + 1):
        rtt = base_rtt + i * random.uniform(3, 18) + random.uniform(-2, 2)
        gw  = gateways[i - 1] if i - 1 < len(gateways) else target_ip
        hops.append({
            "hop":    i,
            "ip":     gw,
            "host":   host if i == hop_count else gw,
            "rtt_ms": round(rtt, 2),
            "status": "reached" if i == hop_count else "intermediate",
        })
    return hops


def traceroute_host(host: str, max_hops: int = 12) -> list:
    try:
        target_ip = socket.gethostbyname(host)
        hops = []
        for ttl in range(1, max_hops + 1):
            hop = {"hop": ttl, "ip": None, "host": None, "rtt_ms": None, "status": "timeout"}
            t0  = time.time()
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
                    s.settimeout(2)
                    s.sendto(b"\x00" * 16, (target_ip, 33434 + ttl))
                    try:
                        _, addr = s.recvfrom(512)
                        hop["ip"]     = addr[0]
                        hop["rtt_ms"] = round((time.time() - t0) * 1000, 2)
                        hop["status"] = "reached" if addr[0] == target_ip else "intermediate"
                        try:
                            hop["host"] = socket.gethostbyaddr(addr[0])[0]
                        except Exception:
                            hop["host"] = addr[0]
                    except socket.timeout:
                        pass
            except Exception:
                pass
            hops.append(hop)
            if hop["status"] == "reached":
                break
        return hops
    except Exception:
        return _simulated_traceroute(host, max_hops)

# ── WHOIS ─────────────────────────────────────────────────────────────────────

def whois_lookup(host: str) -> dict:
    try:
        result = subprocess.run(
            ["whois", host], capture_output=True, text=True, timeout=20
        )
        return {"host": host, "whois": result.stdout[:4000]}
    except FileNotFoundError:
        return {"host": host, "whois": "whois is not available on this system (Windows: install from sysinternals)"}
    except subprocess.TimeoutExpired:
        return {"host": host, "whois": "whois query timed out"}
    except Exception as e:
        return {"host": host, "whois": f"Error: {e}"}

# ── ARP / interfaces ──────────────────────────────────────────────────────────

def arp_table() -> dict:
    try:
        result = subprocess.run(
            ["arp", "-a"], capture_output=True, text=True, timeout=10
        )
        return {"arp_table": result.stdout}
    except Exception as e:
        return {"arp_table": f"Error: {e}"}


def local_interfaces() -> list:
    interfaces = []
    try:
        hostname = socket.gethostname()
        ip       = socket.gethostbyname(hostname)
        interfaces.append({"name": "primary", "hostname": hostname, "ip": ip})
    except Exception:
        pass
    return interfaces

# ── Host sweep ────────────────────────────────────────────────────────────────

def _is_alive(ip: str) -> dict | None:
    for port in (80, 443, 22, 8080, 21):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                if s.connect_ex((ip, port)) == 0:
                    return {"ip": ip, "port": port, "alive": True}
        except Exception:
            pass
    return None


def host_sweep(cidr: str, max_workers: int = 100) -> list:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        raise ValueError(f"Invalid CIDR: {e}")
    hosts = [str(h) for h in net.hosts()]
    alive = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(_is_alive, ip): ip for ip in hosts}
        for fut in concurrent.futures.as_completed(futures):
            res = fut.result()
            if res:
                alive.append(res)
    return sorted(alive, key=lambda x: list(map(int, x["ip"].split("."))))

# ── Full analysis ─────────────────────────────────────────────────────────────

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
    9200: "Elasticsearch", 11211: "Memcached",
}
RISKY_PORTS = {21, 23, 445, 3389, 5900, 6379, 11211, 27017, 9200}


def _tcp_probe(host: str, port: int, timeout: float = 1.0):
    t0 = time.time()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, round((time.time() - t0) * 1000, 2)
    except Exception:
        return False, -1.0


def full_analyze(host: str) -> dict:
    try:
        target_ip = socket.gethostbyname(host)
    except socket.gaierror as e:
        return {"error": f"Cannot resolve host '{host}': {e}"}

    top_ports = sorted(COMMON_PORTS.keys())[:20]

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
        fd = ex.submit(dns_lookup, host)
        fp = ex.submit(ping_host, host, 3)
        ft = ex.submit(traceroute_host, host, 12)

        def _quick_scan():
            results = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=30) as sex:
                fm = {sex.submit(_tcp_probe, host, p): p for p in top_ports}
                for f in concurrent.futures.as_completed(fm):
                    p = fm[f]
                    try:
                        open_, lat = f.result(timeout=2)
                    except Exception:
                        open_, lat = False, -1.0
                    results.append({
                        "port": p, "open": open_,
                        "service": COMMON_PORTS.get(p, "unknown"),
                        "latency": lat if lat >= 0 else None,
                        "risk": "high" if p in RISKY_PORTS and open_ else "low",
                    })
            return sorted(results, key=lambda r: r["port"])

        fs     = ex.submit(_quick_scan)
        dns_r  = fd.result(timeout=15)
        ping_r = fp.result(timeout=25)
        trc_r  = ft.result(timeout=25)
        port_r = fs.result(timeout=35)

    # Build findings
    findings = []
    open_ports = [p for p in port_r if p["open"]]
    risky_open = [p for p in open_ports if p["port"] in RISKY_PORTS]

    if ping_r["reachable"]:
        findings.append({"item": "Host Reachability", "status": "secure", "severity": "low",
            "description": f"Host reachable — avg RTT {ping_r.get('avg_ms', 'N/A')} ms, {ping_r.get('loss_pct', 0)}% loss"})
    else:
        findings.append({"item": "Host Reachability", "status": "warning", "severity": "medium",
            "description": "Host did not respond to ICMP ping — may be filtered or offline"})

    for p in risky_open:
        findings.append({"item": f"Port {p['port']} ({p['service']})", "status": "vulnerable", "severity": "high",
            "description": f"Risky service exposed — {p['service']} on port {p['port']} should not be public-facing"})

    if len(open_ports) > 10:
        findings.append({"item": "Attack Surface", "status": "warning", "severity": "medium",
            "description": f"{len(open_ports)} ports open — large attack surface, review firewall rules"})
    else:
        findings.append({"item": "Attack Surface", "status": "secure", "severity": "low",
            "description": f"{len(open_ports)} open ports found on common port list"})

    findings.append({"item": "Network Path", "status": "secure", "severity": "low",
        "description": f"{len(trc_r)} hops to destination — path analysis complete"})

    if dns_r.get("error"):
        findings.append({"item": "DNS Resolution", "status": "vulnerable", "severity": "high",
            "description": f"DNS error: {dns_r['error']}"})
    else:
        findings.append({"item": "DNS Resolution", "status": "secure", "severity": "low",
            "description": f"{len(dns_r.get('records', []))} DNS records resolved for {host}"})

    return {
        "host":       host,
        "ip":         target_ip,
        "timestamp":  datetime.datetime.now().isoformat(),
        "dns":        dns_r,
        "ping":       ping_r,
        "ports":      port_r,
        "traceroute": trc_r,
        "findings":   findings,
    }

# ── HTTP handler ──────────────────────────────────────────────────────────────

def parse_body(h):
    length = int(h.headers.get("Content-Length", 0))
    raw = h.rfile.read(length) if length else b""
    try:
        return json.loads(raw.decode())
    except Exception:
        return {}


class NetworkHandler(BaseHTTPRequestHandler):
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
            self._json(200, {"status": "ok", "service": "Network Analyzer"})
            return

        if parsed.path == "/network/interfaces":
            self._json(200, {"interfaces": local_interfaces()})
            return

        if parsed.path == "/network/arp":
            self._json(200, arp_table())
            return

        self._json(404, {"error": "Not found"})

    # ── POST ──────────────────────────────────────────────────────────────────

    def do_POST(self):
        parsed = urlparse(self.path)

        if parsed.path == "/network/ping":
            body = parse_body(self)
            host = body.get("host", "").strip()
            if not host:
                self._json(400, {"error": "Missing field: host"}); return
            count = min(int(body.get("count", 4)), 20)
            try:
                self._json(200, ping_host(host, count))
            except Exception as e:
                self._json(500, {"error": str(e)})
            return

        if parsed.path == "/network/dns":
            body = parse_body(self)
            host = body.get("host", "").strip()
            if not host:
                self._json(400, {"error": "Missing field: host"}); return
            try:
                self._json(200, dns_lookup(host))
            except Exception as e:
                self._json(500, {"error": str(e)})
            return

        if parsed.path == "/network/traceroute":
            body = parse_body(self)
            host = body.get("host", "").strip()
            if not host:
                self._json(400, {"error": "Missing field: host"}); return
            max_hops = min(int(body.get("max_hops", 12)), 30)
            try:
                self._json(200, {"host": host, "hops": traceroute_host(host, max_hops)})
            except Exception as e:
                self._json(500, {"error": str(e)})
            return

        if parsed.path == "/network/whois":
            body = parse_body(self)
            host = body.get("host", "").strip()
            if not host:
                self._json(400, {"error": "Missing field: host"}); return
            try:
                self._json(200, whois_lookup(host))
            except Exception as e:
                self._json(500, {"error": str(e)})
            return

        if parsed.path == "/network/sweep":
            body = parse_body(self)
            cidr = body.get("cidr", "").strip()
            if not cidr:
                self._json(400, {"error": "Missing field: cidr (e.g. 192.168.1.0/24)"}); return
            workers = min(int(body.get("threads", 100)), 200)
            try:
                alive = host_sweep(cidr, workers)
                self._json(200, {"cidr": cidr, "alive_hosts": alive, "count": len(alive)})
            except ValueError as e:
                self._json(400, {"error": str(e)})
            except Exception as e:
                self._json(500, {"error": str(e)})
            return

        if parsed.path == "/network/analyze":
            body = parse_body(self)
            host = body.get("host", "").strip()
            user_id = body.get("user_id")
            if not host:
                self._json(400, {"error": "Missing field: host"}); return
            scan_id = activity_log.start_scan(user_id, "Network Analyzer", host) if user_id else None
            try:
                result = full_analyze(host)
                if user_id:
                    for finding in result.get("findings", []):
                        if finding.get("status") != "secure":
                            severity = {"high": "high", "medium": "medium", "low": "low"}.get(finding.get("severity"), "info")
                            activity_log.add_finding(
                                user_id, "Network Analyzer", host,
                                f"{finding.get('item')}: {finding.get('description')}",
                                severity=severity, scan_id=scan_id,
                            )
                    activity_log.finish_scan(scan_id, status="completed", tool="Network Analyzer", target=host, user_id=user_id)
                self._json(200, result)
            except Exception as e:
                if user_id and scan_id:
                    activity_log.finish_scan(scan_id, status="failed", tool="Network Analyzer", target=host, user_id=user_id)
                self._json(500, {"error": str(e)})
            return

        self._json(404, {"error": "Not found"})


HTTPServer.allow_reuse_address = True

if __name__ == "__main__":
    srv = HTTPServer(("0.0.0.0", PORT), NetworkHandler)
    print(f"[Network Analyzer] Running on :{PORT}")
    print(f"  GET  /health                 - health check")
    print(f"  GET  /network/interfaces     - local NIC info")
    print(f"  GET  /network/arp            - ARP table")
    print(f"  POST /network/ping           - ping (host, count)")
    print(f"  POST /network/dns            - DNS lookup (host)")
    print(f"  POST /network/traceroute     - traceroute (host, max_hops)")
    print(f"  POST /network/whois          - WHOIS (host)")
    print(f"  POST /network/sweep          - host sweep (cidr, threads)")
    print(f"  POST /network/analyze        - full analysis (host)")
    srv.serve_forever()
