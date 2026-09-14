import json
import requests
from http.server import HTTPServer, BaseHTTPRequestHandler

PORT = 8000
OLLAMA_URL = "http://localhost:11434/api/chat"
MODEL = "llama3"

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")

    def json_response(self, status, data):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.cors()
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(200)
        self.cors()
        self.end_headers()

    def do_GET(self):
        if self.path == "/health":
            try:
                requests.get("http://localhost:11434", timeout=2)
                self.json_response(200, {"ready": True})
            except:
                self.json_response(200, {"ready": False})
        else:
            self.json_response(404, {"error": "Not found"})

    def do_POST(self):
        if self.path == "/chat":
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length))
            try:
                res = requests.post(OLLAMA_URL, json={
                    "model": MODEL,
                    "messages": body["messages"],
                    "stream": False
                }, timeout=60)
                reply = res.json()["message"]["content"]
                self.json_response(200, {"reply": reply})
            except Exception as e:
                self.json_response(500, {"error": str(e)})
        else:
            self.json_response(404, {"error": "Not found"})

if __name__ == "__main__":
    HTTPServer.allow_reuse_address = True
    server = HTTPServer(("0.0.0.0", PORT), Handler)
    print(f"[CyberBot] Running on:{PORT}")
    server.serve_forever()