#!/usr/bin/env python3
"""
activity_server.py — read API for the dashboard home page.

Serves real scan/finding/activity history recorded by activity_log.py.
Returns honest empty arrays/zero counts when a user has no history yet —
never fabricated data.

Endpoints:
    GET /summary?user_id=123
        -> { active_scans, recent_findings, recent_activity, severity_counts }
"""

import json
import os
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

import activity_log as log

PORT = int(os.environ.get("PORT", 8781))


class Handler(BaseHTTPRequestHandler):
    def _set_headers(self, status=200):
        self.send_response(status)
        self.send_header("Content-type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.send_header("Access-Control-Allow-Methods", "*")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        if parsed.path == "/summary":
            user_id_raw = params.get("user_id", [None])[0]
            try:
                user_id = int(user_id_raw) if user_id_raw is not None else None
            except ValueError:
                user_id = None

            if user_id is None:
                self._set_headers(400)
                self.wfile.write(json.dumps({"error": "user_id is required"}).encode())
                return

            response = {
                "active_scans": log.get_active_scans(user_id),
                "recent_findings": log.get_recent_findings(user_id),
                "recent_activity": log.get_recent_activity(user_id),
                "severity_counts": log.get_severity_counts(user_id),
            }
            self._set_headers()
            self.wfile.write(json.dumps(response).encode())
            return

        if parsed.path == "/health":
            self._set_headers()
            self.wfile.write(json.dumps({"status": "ok"}).encode())
            return

        self._set_headers(404)
        self.wfile.write(json.dumps({"error": "not found"}).encode())


def run():
    log.init_db()
    server = HTTPServer(("0.0.0.0", PORT), Handler)
    print(f"[+] Activity server running on {PORT}")
    server.serve_forever()


if __name__ == "__main__":
    run()
