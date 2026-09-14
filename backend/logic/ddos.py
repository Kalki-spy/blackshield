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

import os
PORT = int(os.environ.get("PORT", 8775))

_lock = threading.Lock()
_traffic_window = collections.deque(maxlen=300)
_ip_counters = {}
_port_counters = {}
_proto_counters = {}
_alert_log = []
_sim_running = False
_sim_thread = None

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
# DDoS TRAFFIC SIMULATOR
# (state vars above were already wired up for this, but the actual
#  simulate/live/stop logic was never implemented — added here)
# -----------------------------

ATTACK_PROFILES = {
    "syn_flood":  {"protocols": {"TCP": 0.9,  "UDP": 0.05, "ICMP": 0.05},               "ports": [80, 443, 22],   "concentrated": True},
    "udp_flood":  {"protocols": {"UDP": 0.85, "TCP": 0.1,  "ICMP": 0.05},               "ports": [53, 123, 19],   "concentrated": True},
    "http_flood": {"protocols": {"HTTP": 0.8, "HTTPS": 0.15, "TCP": 0.05},              "ports": [80, 443],       "concentrated": False},
    "icmp_flood": {"protocols": {"ICMP": 0.9, "TCP": 0.1},                              "ports": [0],             "concentrated": True},
    "botnet":     {"protocols": {"TCP": 0.4,  "UDP": 0.3, "HTTP": 0.3},                 "ports": [80, 443, 8080], "concentrated": False},
    "slowloris":  {"protocols": {"HTTP": 0.95, "TCP": 0.05},                            "ports": [80],            "concentrated": False},
    "amplify":    {"protocols": {"DNS": 0.5,  "NTP": 0.3, "UDP": 0.2},                  "ports": [53, 123],       "concentrated": True},
    "normal":     {"protocols": {"TCP": 0.4,  "HTTPS": 0.3, "UDP": 0.2, "DNS": 0.1},    "ports": [80, 443, 53, 22], "concentrated": False},
}


def _rand_ip():
    return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def _simulate_worker(attack_type: str, duration: float, pps: float):
    global _sim_running
    profile = ATTACK_PROFILES.get(attack_type, ATTACK_PROFILES["normal"])
    protos  = list(profile["protocols"].keys())
    weights = list(profile["protocols"].values())
    pool_size = 3 if profile["concentrated"] else 25
    ip_pool = [_rand_ip() for _ in range(pool_size)]

    end_time = time.time() + max(1, duration)
    interval = 1.0 / max(pps, 1)

    while time.time() < end_time and _sim_running:
        proto = random.choices(protos, weights=weights, k=1)[0]
        ip    = ip_pool[0] if (profile["concentrated"] and random.random() < 0.65) else random.choice(ip_pool)
        port  = 0 if profile["ports"] == [0] else random.choice(profile["ports"])
        size  = random.randint(40, 1500)

        with _lock:
            _traffic_window.append({"ts": _now_ts(), "src": ip, "port": port, "proto": proto, "size": size})
            _ip_counters[ip]       = _ip_counters.get(ip, 0) + 1
            _port_counters[port]   = _port_counters.get(port, 0) + 1
            _proto_counters[proto] = _proto_counters.get(proto, 0) + 1

            total = sum(_ip_counters.values())
            if attack_type != "normal" and total > 20:
                top_ip, top_count = max(_ip_counters.items(), key=lambda kv: kv[1])
                if top_count / total > 0.4 and not any(a["rule"] == "ip_concentration" for a in _alert_log[-3:]):
                    _alert_log.append({
                        "type": "IP Concentration", "severity": "high", "src": top_ip,
                        "detail": f"{top_ip} responsible for {round(top_count/total*100)}% of traffic",
                        "ts": _now_ts(), "rule": "ip_concentration",
                    })
                proto_count = _proto_counters.get(proto, 0)
                if proto_count > 30 and proto in ("TCP", "UDP", "ICMP") and not any(a["rule"] == f"{proto.lower()}_flood" for a in _alert_log[-5:]):
                    _alert_log.append({
                        "type": f"{proto} Flood Detected",
                        "severity": "critical" if proto in ("TCP", "UDP") else "medium",
                        "src": ip, "detail": f"High-volume {proto} packet flood detected ({proto_count} pkts)",
                        "ts": _now_ts(), "rule": f"{proto.lower()}_flood",
                    })
                if proto == "HTTP" and _proto_counters.get("HTTP", 0) > 25 and not any(a["rule"] == "http_flood" for a in _alert_log[-5:]):
                    _alert_log.append({
                        "type": "HTTP Flood Detected", "severity": "high", "src": ip,
                        "detail": "Elevated GET request volume consistent with an L7 flood",
                        "ts": _now_ts(), "rule": "http_flood",
                    })

        time.sleep(interval)

    with _lock:
        _sim_running = False


def start_simulation(attack_type: str, duration: float, pps: float):
    global _sim_running, _sim_thread
    with _lock:
        if _sim_running:
            return {"error": "A simulation is already running. Stop it first."}
        _traffic_window.clear()
        _ip_counters.clear()
        _port_counters.clear()
        _proto_counters.clear()
        _alert_log.clear()
        _sim_running = True
    _sim_thread = threading.Thread(target=_simulate_worker, args=(attack_type, duration, pps), daemon=True)
    _sim_thread.start()
    return {"status": "started", "attack_type": attack_type, "duration": duration, "pps": pps}


def stop_simulation():
    global _sim_running
    with _lock:
        _sim_running = False
    return {"status": "stopped"}


def get_live_snapshot():
    with _lock:
        top_ips   = sorted(_ip_counters.items(),   key=lambda kv: -kv[1])[:10]
        top_ports = sorted(_port_counters.items(), key=lambda kv: -kv[1])[:10]
        return {
            "running":    _sim_running,
            "total_pkts": len(_traffic_window),
            "recent":     list(_traffic_window)[-50:],
            "alerts":     list(_alert_log),
            "top_ips":    [{"ip": ip, "count": c} for ip, c in top_ips],
            "top_ports":  [{"port": p, "count": c} for p, c in top_ports],
            "protocols":  dict(_proto_counters),
        }

# -----------------------------
# HANDLER
# -----------------------------
