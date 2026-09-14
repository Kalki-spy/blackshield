#!/usr/bin/env python3
"""
DDoS Detection + Network Analyzer + Port Scanner Backend
Port: 8775

Now supports:
GET  /health
GET  /ddos/live
POST /ddos/simulate
POST /ddos/stop

NEW (for your frontend):
GET  /api/network/network/analyze?host=...
POST /api/network/network/portscan
"""

import json, datetime, time, threading, random, collections, socket
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

import os, sys
sys.path.insert(0, os.path.dirname(__file__))
import activity_log

PORT = int(os.environ.get("PORT", 8775))

_lock = threading.Lock()
_traffic_window = collections.deque(maxlen=300)
_ip_counters = {}
_port_counters = {}
_proto_counters = {}
_alert_log = []
_sim_running = False
_sim_thread = None
_sim_user_id = None
_sim_scan_id = None
_sim_total_pkts = 0

# -----------------------------
# TRAFFIC SIMULATION (safe: entirely synthetic, in-memory, no packets
# ever actually sent — see Phase 14 "Controlled Security Simulation").
# A real threshold-based detector runs against this synthetic stream,
# so alerts/severities below are genuinely computed, not scripted.
# -----------------------------
ATTACK_PROFILES = {
    "syn_flood":  {"proto": "TCP",  "ports": [80],               "spoofed": True,  "size": (40, 60)},
    "udp_flood":  {"proto": "UDP",  "ports": [53, 123, 19],       "spoofed": True,  "size": (512, 1400)},
    "http_flood": {"proto": "TCP",  "ports": [80, 443],           "spoofed": False, "size": (200, 800)},
    "icmp_flood": {"proto": "ICMP", "ports": [0],                 "spoofed": True,  "size": (32, 64)},
    "botnet":     {"proto": "TCP",  "ports": [80, 443, 22, 8080], "spoofed": False, "size": (60, 300)},
    "slowloris":  {"proto": "TCP",  "ports": [80],                "spoofed": False, "size": (10, 40)},
    "amplify":    {"proto": "UDP",  "ports": [53, 123],           "spoofed": True,  "size": (1200, 4000)},
    "normal":     {"proto": "TCP",  "ports": [80, 443, 22, 53],   "spoofed": False, "size": (60, 400)},
}
# Fixed small pool of "regular user" IPs vs a large randomized pool for
# spoofed/botnet-style attacks — this contrast is what the detector below
# actually keys off of, same as a real flow-based DDoS detector would.
_NORMAL_IPS = [f"10.0.0.{n}" for n in range(2, 8)]


def _random_ip(spoofed: bool) -> str:
    if spoofed:
        return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    return random.choice(_NORMAL_IPS)


def _detect(window_seconds=5):
    """Simple, real threshold detector over the synthetic window — flags a
    source IP or port that dominates recent traffic, same technique a basic
    real-world flow-based DDoS detector uses."""
    cutoff = time.time() - window_seconds
    recent = [p for p in _traffic_window if p["_epoch"] >= cutoff]
    if len(recent) < 20:
        return
    by_ip = collections.Counter(p["src"] for p in recent)
    by_port = collections.Counter(p["port"] for p in recent)
    top_ip, ip_count = by_ip.most_common(1)[0]
    top_port, port_count = by_port.most_common(1)[0]

    if ip_count / len(recent) > 0.6 and ip_count > 30:
        _alert_log.append({
            "type": "volumetric", "severity": "critical" if ip_count > 100 else "high",
            "src": top_ip, "detail": f"{ip_count} packets from a single source in {window_seconds}s window",
            "ts": _now_ts(), "rule": "single-source-volume-threshold",
        })
    elif len(set(p["src"] for p in recent)) > 40 and len(recent) > 80:
        _alert_log.append({
            "type": "distributed", "severity": "high",
            "src": "multiple", "detail": f"{len(set(p['src'] for p in recent))} distinct sources flooding port {top_port}",
            "ts": _now_ts(), "rule": "distributed-source-fanout",
        })
    if len(_alert_log) > 100:
        del _alert_log[:-100]


def _run_simulation(attack_type: str, duration: int, pps: int):
    global _sim_running, _sim_total_pkts
    profile = ATTACK_PROFILES.get(attack_type, ATTACK_PROFILES["normal"])
    duration = max(1, min(duration, 120))   # safety cap
    pps = max(1, min(pps, 2000))            # safety cap — synthetic events/sec, not real traffic
    tick_hz = 10
    per_tick = max(1, pps // tick_hz)
    end_at = time.time() + duration

    while time.time() < end_at and _sim_running:
        with _lock:
            for _ in range(per_tick):
                port = random.choice(profile["ports"])
                src = _random_ip(profile["spoofed"])
                size = random.randint(*profile["size"])
                pkt = {
                    "ts": _now_ts(), "src": src, "port": port,
                    "proto": profile["proto"], "size": size, "_epoch": time.time(),
                }
                _traffic_window.append(pkt)
                _ip_counters[src] = _ip_counters.get(src, 0) + 1
                _port_counters[port] = _port_counters.get(port, 0) + 1
                _proto_counters[profile["proto"]] = _proto_counters.get(profile["proto"], 0) + 1
                _sim_total_pkts += 1
            if attack_type != "normal":
                _detect()
        time.sleep(1 / tick_hz)

    with _lock:
        _sim_running = False
        if _sim_user_id:
            critical_alerts = [a for a in _alert_log if a["severity"] in ("critical", "high")]
            for a in critical_alerts[-5:]:
                activity_log.add_finding(
                    _sim_user_id, "DDoS Simulation", a["src"],
                    f"{a['type']}: {a['detail']}", severity=a["severity"], scan_id=_sim_scan_id,
                )
            activity_log.finish_scan(_sim_scan_id, status="completed", tool="DDoS Simulation",
                                      target=attack_type, user_id=_sim_user_id)


def _parse_multipart(handler) -> dict:
    """Minimal multipart/form-data parser for simple text fields (no file
    uploads needed here) — avoids depending on the deprecated cgi module."""
    length = int(handler.headers.get("Content-Length", 0))
    raw = handler.rfile.read(length)
    content_type = handler.headers.get("Content-Type", "")
    if "boundary=" not in content_type:
        return {}
    boundary = content_type.split("boundary=")[-1].strip().encode()
    fields = {}
    for part in raw.split(b"--" + boundary):
        if b'name="' not in part:
            continue
        try:
            header, _, value = part.partition(b"\r\n\r\n")
            name = header.split(b'name="')[1].split(b'"')[0].decode()
            fields[name] = value.rstrip(b"\r\n--").decode(errors="replace")
        except Exception:
            continue
    return fields

# -----------------------------
# UTIL
# -----------------------------
def _now_ts():
    return datetime.datetime.now().strftime("%H:%M:%S")

def _json(handler, status, data):
    body = json.dumps(data).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Access-Control-Allow-Origin", "*")
    handler.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
    handler.send_header("Access-Control-Allow-Headers", "Content-Type")
    handler.end_headers()
    handler.wfile.write(body)

# -----------------------------
# SIMPLE PORT SCAN
# -----------------------------
COMMON_PORTS = {
    80: "HTTP", 443: "HTTPS", 21: "FTP",
    22: "SSH", 25: "SMTP", 53: "DNS",
    110: "POP3", 143: "IMAP", 3306: "MySQL",
    8080: "HTTP-ALT"
}

def scan_ports(host, ports):
    results = []
    for port in ports:
        sock = socket.socket()
        sock.settimeout(0.8)
        start = time.time()
        try:
            sock.connect((host, port))
            latency = (time.time() - start) * 1000
            results.append({
                "port": port,
                "open": True,
                "service": COMMON_PORTS.get(port, "unknown"),
                "latency": round(latency, 2),
                "risk": "medium" if port in [21, 22] else "low"
            })
        except:
            results.append({
                "port": port,
                "open": False,
                "service": COMMON_PORTS.get(port, "unknown"),
                "latency": None,
                "risk": "low"
            })
        sock.close()
    return results

# -----------------------------
# HANDLER
# -----------------------------
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        # HEALTH
        if path == "/health":
            return _json(self, 200, {"status": "ok"})

        if path == "/ddos/live":
            with _lock:
                recent = [{k: v for k, v in p.items() if k != "_epoch"} for p in list(_traffic_window)[-50:]]
                top_ips = sorted(_ip_counters.items(), key=lambda x: -x[1])[:8]
                top_ports = sorted(_port_counters.items(), key=lambda x: -x[1])[:8]
                return _json(self, 200, {
                    "running": _sim_running,
                    "total_pkts": _sim_total_pkts,
                    "recent": recent,
                    "alerts": list(_alert_log[-30:]),
                    "top_ips": [{"ip": ip, "count": c} for ip, c in top_ips],
                    "top_ports": [{"port": p, "count": c} for p, c in top_ports],
                    "protocols": dict(_proto_counters),
                })

        # Note: real network analysis lives in network_server.py (see
        # vite.config.ts proxy for /api/network/analyze) — this file's old
        # /api/network/network/analyze route returned hardcoded fake ping/
        # traceroute/findings data and has been removed rather than left as
        # a trap for future confusion.

        return _json(self, 404, {"error": "Not found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/ddos/simulate":
            global _sim_running, _sim_thread, _sim_user_id, _sim_scan_id, _sim_total_pkts
            fields = _parse_multipart(self)
            attack_type = fields.get("attack_type", "normal")
            try:
                duration = int(fields.get("duration", 20))
                pps = int(fields.get("pps", 50))
            except ValueError:
                return _json(self, 400, {"error": "duration and pps must be numbers"})
            user_id = fields.get("user_id")
            user_id = int(user_id) if user_id else None

            with _lock:
                if _sim_running:
                    return _json(self, 409, {"error": "A simulation is already running — stop it first"})
                _traffic_window.clear()
                _ip_counters.clear(); _port_counters.clear(); _proto_counters.clear()
                _alert_log.clear()
                _sim_total_pkts = 0
                _sim_running = True
                _sim_user_id = user_id
                _sim_scan_id = activity_log.start_scan(user_id, "DDoS Simulation", attack_type) if user_id else None

            _sim_thread = threading.Thread(target=_run_simulation, args=(attack_type, duration, pps), daemon=True)
            _sim_thread.start()
            return _json(self, 200, {"ok": True, "attack_type": attack_type, "duration": duration, "pps": pps})

        if path == "/ddos/stop":
            with _lock:
                was_running = _sim_running
                _sim_running = False
                if was_running and _sim_user_id and _sim_scan_id:
                    activity_log.finish_scan(_sim_scan_id, status="completed", tool="DDoS Simulation",
                                              target="stopped early", user_id=_sim_user_id)
            return _json(self, 200, {"ok": True})

        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or "{}")

        # Note: real port scanning lives in port_scanner_server.py (see
        # vite.config.ts proxy for /api/network/portscan) — this file's old
        # duplicate implementation under a differently-named path has been
        # removed to avoid two diverging copies of the same feature.

        return _json(self, 404, {"error": "Not found"})

# -----------------------------
# START SERVER
# -----------------------------
if __name__ == "__main__":
    print(f"[DDoS Simulator] Running on :{PORT}")
    HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()