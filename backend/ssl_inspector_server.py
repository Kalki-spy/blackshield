#!/usr/bin/env python3
"""
SSL/TLS Inspector Backend — port 8776
Endpoints:
  GET  /health
  POST /ssl/inspect   {host, port?}
"""
import socket, ssl, json, datetime, hashlib, re
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

import os
PORT = int(os.environ.get("PORT", 8776))

WEAK_CIPHERS   = {"RC4","DES","3DES","EXPORT","NULL","ANON","MD5"}
WEAK_PROTOCOLS = {"SSLv2","SSLv3","TLSv1","TLSv1.1"}
STRONG_PROTOCOLS = {"TLSv1.2","TLSv1.3"}

def _cors(handler):
    handler.send_header("Access-Control-Allow-Origin", "*")
    handler.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
    handler.send_header("Access-Control-Allow-Headers", "Content-Type, Accept, Authorization")
    handler.send_header("Access-Control-Max-Age", "86400")

def _json(handler, status, data):
    body = json.dumps(data).encode()
    handler.send_response(status)
    handler.send_header("Content-Type","application/json")
    handler.send_header("Content-Length", str(len(body)))
    _cors(handler); handler.end_headers(); handler.wfile.write(body)

def parse_body(handler):
    length = int(handler.headers.get("Content-Length",0))
    raw = handler.rfile.read(length) if length else b""
    try: return json.loads(raw.decode())
    except: return {}

def _days_until(dt_str):
    try:
        exp = datetime.datetime.strptime(dt_str, "%b %d %H:%M:%S %Y %Z")
        return (exp - datetime.datetime.utcnow()).days
    except: return None

def inspect_ssl(host, port=443):
    result = {
        "host": host, "port": port,
        "reachable": False, "has_ssl": False,
        "protocol": None, "cipher": None, "cipher_bits": None,
        "cert": {}, "chain_depth": 0,
        "findings": [], "grade": "F", "error": None
    }
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=8) as sock:
            result["reachable"] = True
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                result["has_ssl"] = True
                result["protocol"] = ssock.version()
                cipher_name, proto, bits = ssock.cipher()
                result["cipher"] = cipher_name
                result["cipher_bits"] = bits

                cert = ssock.getpeercert()
                if cert:
                    subj = dict(x[0] for x in cert.get("subject",[]))
                    issuer = dict(x[0] for x in cert.get("issuer",[]))
                    not_after  = cert.get("notAfter","")
                    not_before = cert.get("notBefore","")
                    days_left  = _days_until(not_after)
                    sans = [v for _,v in cert.get("subjectAltName",[])]
                    result["cert"] = {
                        "subject_cn": subj.get("commonName",""),
                        "issuer_cn":  issuer.get("commonName",""),
                        "issuer_org": issuer.get("organizationName",""),
                        "not_before": not_before,
                        "not_after":  not_after,
                        "days_remaining": days_left,
                        "serial": str(cert.get("serialNumber","")),
                        "sans": sans[:10],
                        "san_count": len(sans),
                    }

        # Findings
        findings = []
        proto = result["protocol"] or ""
        if proto in STRONG_PROTOCOLS:
            findings.append({"item":"Protocol","status":"secure","severity":"low","desc":f"{proto} in use — modern and secure"})
        elif proto in WEAK_PROTOCOLS:
            findings.append({"item":"Protocol","status":"vulnerable","severity":"high","desc":f"{proto} is deprecated and insecure — upgrade to TLS 1.2+"})
        else:
            findings.append({"item":"Protocol","status":"warning","severity":"medium","desc":f"Protocol {proto} — verify support policy"})

        cipher = result["cipher"] or ""
        is_weak_cipher = any(w in cipher.upper() for w in WEAK_CIPHERS)
        if is_weak_cipher:
            findings.append({"item":"Cipher Suite","status":"vulnerable","severity":"high","desc":f"Weak cipher in use: {cipher}"})
        elif result["cipher_bits"] and result["cipher_bits"] < 128:
            findings.append({"item":"Cipher Suite","status":"vulnerable","severity":"high","desc":f"Insufficient key length: {result['cipher_bits']} bits"})
        else:
            findings.append({"item":"Cipher Suite","status":"secure","severity":"low","desc":f"{cipher} ({result['cipher_bits']} bits) — acceptable strength"})

        days = result["cert"].get("days_remaining")
        if days is None:
            findings.append({"item":"Certificate Expiry","status":"warning","severity":"medium","desc":"Could not parse expiry date"})
        elif days < 0:
            findings.append({"item":"Certificate Expiry","status":"vulnerable","severity":"critical","desc":f"Certificate EXPIRED {abs(days)} days ago"})
        elif days < 14:
            findings.append({"item":"Certificate Expiry","status":"vulnerable","severity":"high","desc":f"Certificate expires in {days} days — renew immediately"})
        elif days < 30:
            findings.append({"item":"Certificate Expiry","status":"warning","severity":"medium","desc":f"Certificate expires in {days} days — plan renewal"})
        else:
            findings.append({"item":"Certificate Expiry","status":"secure","severity":"low","desc":f"Valid for {days} more days"})

        issuer_cn = result["cert"].get("issuer_cn","").lower()
        if "let's encrypt" in issuer_cn or "sectigo" in issuer_cn or "digicert" in issuer_cn or "comodo" in issuer_cn or "globalsign" in issuer_cn:
            findings.append({"item":"Certificate Authority","status":"secure","severity":"low","desc":f"Issued by trusted CA: {result['cert'].get('issuer_cn','')}"})
        elif issuer_cn == result["cert"].get("subject_cn","").lower():
            findings.append({"item":"Certificate Authority","status":"vulnerable","severity":"high","desc":"Self-signed certificate — not trusted by browsers"})
        else:
            findings.append({"item":"Certificate Authority","status":"warning","severity":"medium","desc":f"CA: {result['cert'].get('issuer_cn','')} — verify trust chain"})

        sans = result["cert"].get("sans",[])
        if host in sans or f"*.{'.'.join(host.split('.')[1:])}" in sans:
            findings.append({"item":"Hostname Match","status":"secure","severity":"low","desc":f"Host matches SAN entries ({len(sans)} SANs)"})
        elif sans:
            findings.append({"item":"Hostname Match","status":"warning","severity":"medium","desc":f"Host not found in {len(sans)} SAN entries — possible mismatch"})

        result["findings"] = findings

        vuln  = sum(1 for f in findings if f["status"]=="vulnerable")
        warn  = sum(1 for f in findings if f["status"]=="warning")
        crit  = sum(1 for f in findings if f["severity"]=="critical")
        if crit or vuln >= 2:    result["grade"] = "F"
        elif vuln == 1:          result["grade"] = "C"
        elif warn >= 2:          result["grade"] = "B"
        elif warn == 1:          result["grade"] = "A"
        else:                    result["grade"] = "A+"

    except ssl.SSLError as e:
        result["error"] = f"SSL error: {e}"
    except socket.timeout:
        result["error"] = "Connection timed out"
    except ConnectionRefusedError:
        result["error"] = f"Connection refused on port {port}"
    except Exception as e:
        result["error"] = str(e)
    return result

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_OPTIONS(self):
        self.send_response(200); _cors(self)
        self.send_header("Content-Length","0"); self.end_headers()
    def do_GET(self):
        if urlparse(self.path).path == "/health":
            _json(self, 200, {"status":"ok","service":"SSL Inspector"})
        else: _json(self, 404, {"error":"not found"})
    def do_POST(self):
        body = parse_body(self)
        if urlparse(self.path).path == "/ssl/inspect":
            host = body.get("host","").strip()
            if not host: _json(self, 400, {"error":"Missing field: host"}); return
            port = int(body.get("port", 443))
            _json(self, 200, inspect_ssl(host, port))
        else: _json(self, 404, {"error":"not found"})

HTTPServer.allow_reuse_address = True
if __name__ == "__main__":
    srv = HTTPServer(("0.0.0.0", PORT), Handler)
    print(f"[SSL Inspector] Running on:{PORT}")
    srv.serve_forever()