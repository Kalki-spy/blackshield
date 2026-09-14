#!/usr/bin/env python3
"""
scenario_server.py — serves scenarios with progress derived from real
completed scans (see scenarios.py). No writes — progress comes from
whatever tools have already logged to activity_log.

Endpoint:
    GET /scenarios?user_id=123
"""

import json
import os
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

import scenarios as scn

PORT = int(os.environ.get("PORT", 8784))


class Handler(BaseHTTPRequestHandler):
    def _send(self, payload, status=200):
        self.send_response(status)
        self.send_header("Content-type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode())

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.send_header("Access-Control-Allow-Methods", "*")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/scenarios":
            params = parse_qs(parsed.query)
            try:
                user_id = int(params.get("user_id", [None])[0])
            except (TypeError, ValueError):
                return self._send({"error": "user_id is required"}, 400)
            return self._send(scn.list_scenarios_with_progress(user_id))

        if parsed.path == "/health":
            return self._send({"status": "ok"})

        self._send({"error": "not found"}, 404)


def run():
    server = HTTPServer(("0.0.0.0", PORT), Handler)
    print(f"[+] Scenario server running on {PORT}")
    server.serve_forever()


if __name__ == "__main__":
    run()
