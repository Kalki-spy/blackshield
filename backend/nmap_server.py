#!/usr/bin/env python3

import json
import socket
import time
from http.server import HTTPServer, BaseHTTPRequestHandler

import os
PORT = int(os.environ.get("PORT", 8773))
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]

def scan_port(target, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    start = time.time()
    try:
        s.connect((target, port))
        latency = int((time.time() - start) * 1000)

        banner = ""
        try:
            s.send(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = s.recv(1024).decode(errors="ignore")
        except:
            pass

        return {
            "port": port,
            "proto": "tcp",
            "state": "open",
            "reason": "syn-ack",
            "service": guess_service(port),
            "desc": "",
            "version": banner[:50],
            "banner": banner,
            "latency": latency,
        }
    except:
        return {
            "port": port,
            "proto": "tcp",
            "state": "closed",
            "reason": "conn-refused",
            "service": "",
            "desc": "",
            "version": "",
            "banner": "",
            "latency": 0,
        }
    finally:
        s.close()

def guess_service(port):
    return {
        21: "ftp", 22: "ssh", 23: "telnet",
        25: "smtp", 53: "dns", 80: "http",
        443: "https", 3306: "mysql",
        3389: "rdp", 8080: "http-alt"
    }.get(port, "unknown")

def detect_os(open_ports):
    if 3389 in open_ports:
        return "Windows"
    if 22 in open_ports:
        return "Linux/Unix"
    if 80 in open_ports and 443 in open_ports:
        return "Web Server (Linux)"
    return "Unknown"

def http_analysis(target):
    result = {}
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((target, 80))
        s.send(b"HEAD / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
        data = s.recv(2048).decode(errors="ignore")

        headers = data.split("\r\n")

        def check(h):
            return "present" if any(h.lower() in x.lower() for x in headers) else "MISSING"

        result = {
            "hsts": check("strict-transport-security"),
            "csp": check("content-security-policy"),
            "x_frame": check("x-frame-options"),
            "server": next((x.split(":")[1].strip() for x in headers if "Server:" in x), "unknown")
        }

        s.close()
    except:
        pass

    return result

class Handler(BaseHTTPRequestHandler):

    def _set_headers(self):
        self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.send_header("Access-Control-Allow-Methods", "*")
        self.end_headers()

    def do_POST(self):
        if self.path == "/scan":
            length = int(self.headers["Content-Length"])
            body = self.rfile.read(length)
            data = json.loads(body)

            target = data.get("target")
            ports = data.get("ports", COMMON_PORTS)

            start_time = time.time()

            results = []
            open_ports = []

            for port in ports:
                res = scan_port(target, port)
                results.append(res)
                if res["state"] == "open":
                    open_ports.append(port)

            scan_time = round(time.time() - start_time, 2)

            response = {
                "target": target,
                "ip": socket.gethostbyname(target),
                "rdns": "",
                "scan_type": "custom",
                "ports_scanned": len(ports),
                "open_ports": len([p for p in results if p["state"] == "open"]),
                "closed_ports": len([p for p in results if p["state"] == "closed"]),
                "filtered_ports": 0,
                "scan_time": scan_time,
                "avg_latency": int(sum(p["latency"] for p in results) / max(1, len(results))),
                "ports": results,
                "os_info": {
                    "os": detect_os(open_ports),
                    "confidence": 60,
                    "candidates": {},
                    "method": "heuristic port analysis"
                },
                "http_info": http_analysis(target),
                "host_up": True
            }

            self._set_headers()
            self.wfile.write(json.dumps(response).encode())

def run():
    server = HTTPServer(("0.0.0.0", PORT), Handler)
    print(f"[+] Scanner running on {PORT}")
    server.serve_forever()

if __name__ == "__main__":
    run()