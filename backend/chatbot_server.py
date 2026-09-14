#!/usr/bin/env python3
"""
CyberBot Chat Server — Groq Edition
Same cloud AI provider as production (see app.py). Uses Groq's hosted API
so local dev matches what's deployed — no local model to install or run.

SETUP:
1. Get a free key: https://console.groq.com/keys
2. Put it in backend/.env as GROQ_API_KEY=your_key_here (see .env.example)
3. Run this server — it reads the key from the environment.

Endpoint: POST /chat  { messages: [{role, content}, ...] }
GET  /health  — shows whether GROQ_API_KEY is configured
"""

import json
import os
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

from dotenv import load_dotenv
load_dotenv()

from groq import Groq

PORT = 8000

GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
GROQ_MODEL   = "llama-3.3-70b-versatile"
groq_client  = Groq(api_key=GROQ_API_KEY) if GROQ_API_KEY else None

SYSTEM_PROMPT = """You are CyberBot, an elite cybersecurity AI assistant for BlackShield — a professional cybersecurity analysis and penetration testing platform.

Your expertise covers:
- SSL/TLS certificate analysis and vulnerabilities
- Network scanning, port analysis, and service fingerprinting
- SQL injection detection and web application security
- Password cracking, hash analysis, and cryptography
- CVE vulnerabilities, CVSS scoring, and patch management
- DDoS attack types, detection, and mitigation
- Directory brute-forcing and web enumeration
- Subdomain discovery and DNS analysis
- Red team offensive techniques and Blue team defence
- CTF challenges and penetration testing methodology
- OWASP Top 10, MITRE ATT&CK framework

Rules:
- Be direct and technical — no filler phrases
- Use bullet points and code blocks for clarity
- Bold important terms and CVE IDs
- Answer cybersecurity questions thoroughly
- For BlackShield tool questions, explain how to use them effectively"""


def call_groq(messages: list) -> str:
    completion = groq_client.chat.completions.create(
        model=GROQ_MODEL,
        messages=[{"role": "system", "content": SYSTEM_PROMPT}] + messages,
        temperature=0.7,
        max_tokens=800,
    )
    return completion.choices[0].message.content


# ── HTTP Handler ──────────────────────────────────────────────────────────────
class ChatHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args): pass

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def do_OPTIONS(self):
        self.send_response(200); self._cors()
        self.send_header("Content-Length", "0"); self.end_headers()

    def _json(self, status, data):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self._cors(); self.end_headers(); self.wfile.write(body)

    def do_GET(self):
        if urlparse(self.path).path == "/health":
            self._json(200, {"status": "ok", "ready": bool(GROQ_API_KEY)})
        else:
            self._json(404, {"error": "Not found"})

    def do_POST(self):
        if urlparse(self.path).path != "/chat":
            self._json(404, {"error": "Not found"}); return

        if not groq_client:
            self._json(503, {
                "error": "Chat isn't configured. Set GROQ_API_KEY in backend/.env "
                         "(free key at https://console.groq.com/keys), then restart this server."
            }); return

        length = int(self.headers.get("Content-Length", 0))
        body   = json.loads(self.rfile.read(length)) if length else {}
        messages = body.get("messages", [])

        if not messages:
            self._json(400, {"error": "No messages provided"}); return

        try:
            reply = call_groq(messages)
            self._json(200, {"reply": reply, "model": GROQ_MODEL, "provider": "groq"})
        except Exception as e:
            self._json(502, {"error": f"Groq request failed: {e}"})


# ── Entry ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print(f"[CyberBot Groq] Starting on port {PORT}")
    if GROQ_API_KEY:
        print(f"[CyberBot Groq] Ready — using model {GROQ_MODEL}")
    else:
        print("[CyberBot Groq] WARNING: GROQ_API_KEY not set.")
        print("[CyberBot Groq] Add it to backend/.env — see .env.example. Free key: https://console.groq.com/keys")

    HTTPServer.allow_reuse_address = True
    server = HTTPServer(("0.0.0.0", PORT), ChatHandler)
    server.serve_forever()