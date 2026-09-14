#!/usr/bin/env python3
"""
ctf_server.py — serves real CTF challenges and verifies flag submissions
server-side. See ctf.py for schema and the seeded, genuinely-solvable
challenge set.

Endpoints:
    GET  /challenges?user_id=123
    POST /submit   { "user_id": 123, "slug": "...", "flag": "..." }
"""

import json
import os
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

import ctf

PORT = int(os.environ.get("PORT", 8782))


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
        if parsed.path == "/challenges":
            params = parse_qs(parsed.query)
            try:
                user_id = int(params.get("user_id", [None])[0])
            except (TypeError, ValueError):
                self._set_headers(400)
                self.wfile.write(json.dumps({"error": "user_id is required"}).encode())
                return
            self._set_headers()
            self.wfile.write(json.dumps(ctf.list_challenges(user_id)).encode())
            return

        if parsed.path == "/health":
            self._set_headers()
            self.wfile.write(json.dumps({"status": "ok"}).encode())
            return

        self._set_headers(404)
        self.wfile.write(json.dumps({"error": "not found"}).encode())

    def do_POST(self):
        if self.path == "/submit":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length) if length else b"{}"
            try:
                data = json.loads(body)
                user_id = int(data["user_id"])
                slug = str(data["slug"])
                flag = str(data.get("flag", ""))
            except (KeyError, ValueError, TypeError, json.JSONDecodeError):
                self._set_headers(400)
                self.wfile.write(json.dumps({"error": "user_id, slug and flag are required"}).encode())
                return

            result, status = ctf.submit_flag(user_id, slug, flag)
            self._set_headers(status)
            self.wfile.write(json.dumps(result).encode())
            return

        self._set_headers(404)
        self.wfile.write(json.dumps({"error": "not found"}).encode())


def run():
    ctf.init_db()
    server = HTTPServer(("0.0.0.0", PORT), Handler)
    print(f"[+] CTF server running on {PORT}")
    server.serve_forever()


if __name__ == "__main__":
    run()
