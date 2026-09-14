#!/usr/bin/env python3
"""
assistant_server.py — read/write API for AI Assistant conversation
history and the minimal reports feature. See assistant_data.py for schema.

Endpoints:
    GET  /conversations?user_id=123
    GET  /conversations/<id>/messages?user_id=123
    POST /conversations           { user_id, title }               -> { id }
    POST /conversations/<id>/messages  { role, content }            -> { ok }
    GET  /reports?user_id=123
    GET  /reports/<id>?user_id=123
    POST /reports                 { user_id, title }                -> { id }
    POST /reports/<id>/items      { content, source }                -> { ok }
"""

import json
import os
import re
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

import assistant_data as data

PORT = int(os.environ.get("PORT", 8783))


class Handler(BaseHTTPRequestHandler):
    def _set_headers(self, status=200):
        self.send_response(status)
        self.send_header("Content-type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

    def _send(self, payload, status=200):
        self._set_headers(status)
        self.wfile.write(json.dumps(payload).encode())

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.send_header("Access-Control-Allow-Methods", "*")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        def user_id():
            try:
                return int(params.get("user_id", [None])[0])
            except (TypeError, ValueError):
                return None

        if parsed.path == "/conversations":
            uid = user_id()
            if uid is None:
                return self._send({"error": "user_id is required"}, 400)
            return self._send(data.list_conversations(uid))

        m = re.match(r"^/conversations/(\d+)/messages$", parsed.path)
        if m:
            uid = user_id()
            if uid is None:
                return self._send({"error": "user_id is required"}, 400)
            messages = data.get_messages(int(m.group(1)), uid)
            if messages is None:
                return self._send({"error": "not found"}, 404)
            return self._send(messages)

        if parsed.path == "/reports":
            uid = user_id()
            if uid is None:
                return self._send({"error": "user_id is required"}, 400)
            return self._send(data.list_reports(uid))

        m = re.match(r"^/reports/(\d+)$", parsed.path)
        if m:
            uid = user_id()
            if uid is None:
                return self._send({"error": "user_id is required"}, 400)
            report = data.get_report(int(m.group(1)), uid)
            if report is None:
                return self._send({"error": "not found"}, 404)
            return self._send(report)

        if parsed.path == "/health":
            return self._send({"status": "ok"})

        self._send({"error": "not found"}, 404)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            return self._send({"error": "invalid JSON"}, 400)

        if self.path == "/conversations":
            try:
                uid = int(payload["user_id"])
                title = str(payload.get("title", "New conversation"))
            except (KeyError, TypeError, ValueError):
                return self._send({"error": "user_id is required"}, 400)
            conv_id = data.create_conversation(uid, title)
            return self._send({"id": conv_id})

        m = re.match(r"^/conversations/(\d+)/messages$", self.path)
        if m:
            try:
                role = str(payload["role"])
                content = str(payload["content"])
            except KeyError:
                return self._send({"error": "role and content are required"}, 400)
            data.add_message(int(m.group(1)), role, content)
            return self._send({"ok": True})

        if self.path == "/reports":
            try:
                uid = int(payload["user_id"])
                title = str(payload.get("title", "Untitled report"))
            except (KeyError, TypeError, ValueError):
                return self._send({"error": "user_id is required"}, 400)
            report_id = data.create_report(uid, title)
            return self._send({"id": report_id})

        m = re.match(r"^/reports/(\d+)/items$", self.path)
        if m:
            try:
                content = str(payload["content"])
            except KeyError:
                return self._send({"error": "content is required"}, 400)
            data.add_report_item(int(m.group(1)), content, payload.get("source"))
            return self._send({"ok": True})

        self._send({"error": "not found"}, 404)


def run():
    data.init_db()
    server = HTTPServer(("0.0.0.0", PORT), Handler)
    print(f"[+] Assistant data server running on {PORT}")
    server.serve_forever()


if __name__ == "__main__":
    run()
