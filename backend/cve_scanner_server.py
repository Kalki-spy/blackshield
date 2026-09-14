#!/usr/bin/env python3
import os, sys
sys.path.insert(0, os.path.dirname(__file__))
import activity_log
"""
CVE Vulnerability Scanner Backend — port 8779
Endpoints:
  GET  /health
  POST /cve/scan      {software, version?}
  POST /cve/bulk      {targets: [{software, version}]}
  GET  /cve/search?q=...
"""
import json, re, datetime, hashlib
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

import os
PORT = int(os.environ.get("PORT", 8779))

# Deterministic CVE knowledge base — real CVE IDs mapped to software keywords
CVE_DB = [
    # Apache
    {"cve":"CVE-2021-41773","software":"apache","versions":["2.4.49"],"cvss":9.8,"severity":"critical","desc":"Path traversal and RCE in Apache HTTP Server 2.4.49","vector":"AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","patch":"Upgrade to 2.4.50+"},
    {"cve":"CVE-2021-42013","software":"apache","versions":["2.4.49","2.4.50"],"cvss":9.8,"severity":"critical","desc":"Path traversal bypass in Apache HTTP Server","vector":"AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","patch":"Upgrade to 2.4.51+"},
    {"cve":"CVE-2017-7679","software":"apache","versions":[],"cvss":9.8,"severity":"critical","desc":"Buffer overflow in mod_mime","vector":"AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","patch":"Upgrade to 2.2.33 / 2.4.26+"},
    # OpenSSL
    {"cve":"CVE-2014-0160","software":"openssl","versions":["1.0.1","1.0.1a","1.0.1b","1.0.1c","1.0.1d","1.0.1e","1.0.1f"],"cvss":7.5,"severity":"high","desc":"Heartbleed — remote memory disclosure","vector":"AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","patch":"Upgrade to 1.0.1g+"},
    {"cve":"CVE-2022-0778","software":"openssl","versions":[],"cvss":7.5,"severity":"high","desc":"Infinite loop in BN_mod_sqrt() — DoS","vector":"AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H","patch":"Upgrade to 1.0.2zd / 1.1.1n / 3.0.2+"},
    {"cve":"CVE-2016-0800","software":"openssl","versions":[],"cvss":5.9,"severity":"medium","desc":"DROWN attack — SSLv2 cross-protocol","vector":"AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N","patch":"Disable SSLv2, upgrade OpenSSL"},
    # Nginx
    {"cve":"CVE-2021-23017","software":"nginx","versions":[],"cvss":7.7,"severity":"high","desc":"1-byte memory overwrite in DNS resolver","vector":"AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:L/A:H","patch":"Upgrade to 1.20.1+"},
    {"cve":"CVE-2019-20372","software":"nginx","versions":[],"cvss":5.3,"severity":"medium","desc":"HTTP request smuggling via error_page","vector":"AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N","patch":"Upgrade to 1.17.7+"},
    # WordPress
    {"cve":"CVE-2022-21661","software":"wordpress","versions":[],"cvss":8.8,"severity":"high","desc":"SQL injection via WP_Query","vector":"AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H","patch":"Upgrade to WordPress 5.8.3+"},
    {"cve":"CVE-2019-8942","software":"wordpress","versions":[],"cvss":8.8,"severity":"high","desc":"Path traversal leads to RCE via image upload","vector":"AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H","patch":"Upgrade to 5.0.1+"},
    # MySQL
    {"cve":"CVE-2016-6662","software":"mysql","versions":[],"cvss":9.8,"severity":"critical","desc":"Remote code execution via MySQL config file","vector":"AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","patch":"Upgrade to 5.5.52 / 5.6.33 / 5.7.15+"},
    {"cve":"CVE-2021-2307","software":"mysql","versions":[],"cvss":7.1,"severity":"high","desc":"Privilege escalation in MySQL Server","vector":"AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N","patch":"Upgrade to 8.0.24+"},
    # PHP
    {"cve":"CVE-2021-21703","software":"php","versions":[],"cvss":7.0,"severity":"high","desc":"Local privilege escalation in PHP-FPM","vector":"AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H","patch":"Upgrade to 7.3.31 / 7.4.24 / 8.0.11+"},
    {"cve":"CVE-2019-11043","software":"php","versions":[],"cvss":9.8,"severity":"critical","desc":"Buffer underflow in FPM — remote code execution","vector":"AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","patch":"Upgrade to 7.1.33 / 7.2.24 / 7.3.11+"},
    # SSH / OpenSSH
    {"cve":"CVE-2023-38408","software":"openssh","versions":[],"cvss":9.8,"severity":"critical","desc":"Remote code execution in ssh-agent","vector":"AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","patch":"Upgrade to OpenSSH 9.3p2+"},
    {"cve":"CVE-2016-0777","software":"openssh","versions":[],"cvss":6.5,"severity":"medium","desc":"Roaming feature information leak","vector":"AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N","patch":"Set UseRoaming no or upgrade"},
    # Log4j
    {"cve":"CVE-2021-44228","software":"log4j","versions":["2.0","2.1","2.2","2.3","2.4","2.5","2.6","2.7","2.8","2.9","2.10","2.11","2.12","2.13","2.14"],"cvss":10.0,"severity":"critical","desc":"Log4Shell — JNDI injection RCE","vector":"AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H","patch":"Upgrade to 2.15.0+, set log4j2.formatMsgNoLookups=true"},
    {"cve":"CVE-2021-45046","software":"log4j","versions":["2.15"],"cvss":9.0,"severity":"critical","desc":"Log4Shell bypass — incomplete fix in 2.15","vector":"AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H","patch":"Upgrade to 2.16.0+"},
    # Samba
    {"cve":"CVE-2017-7494","software":"samba","versions":[],"cvss":9.8,"severity":"critical","desc":"SambaCry — RCE via writable share","vector":"AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","patch":"Upgrade to 4.6.4+ or disable wide links"},
    # vsftpd
    {"cve":"CVE-2011-2523","software":"vsftpd","versions":["2.3.4"],"cvss":10.0,"severity":"critical","desc":"Backdoor in vsftpd 2.3.4 — opens shell on port 6200","vector":"AV:N/AC:L/PR:N/UI:N/S:U/C:C/I:C/A:C","patch":"Upgrade to clean version, never use 2.3.4"},
    # Tomcat
    {"cve":"CVE-2020-1938","software":"tomcat","versions":[],"cvss":9.8,"severity":"critical","desc":"Ghostcat — AJP connector arbitrary file read/RCE","vector":"AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","patch":"Upgrade to 6.0.54 / 7.0.100 / 8.5.51 / 9.0.31+"},
    # Elasticsearch
    {"cve":"CVE-2014-3120","software":"elasticsearch","versions":[],"cvss":7.5,"severity":"high","desc":"Dynamic script execution leads to RCE","vector":"AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","patch":"Disable dynamic scripting or upgrade"},
    # Redis
    {"cve":"CVE-2022-0543","software":"redis","versions":[],"cvss":10.0,"severity":"critical","desc":"Lua sandbox escape leads to RCE","vector":"AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H","patch":"Upgrade to Redis 6.2.7 / 7.0+"},
]

def _match(software_query, db_entry):
    sw = software_query.lower().strip()
    entry_sw = db_entry["software"].lower()
    return sw in entry_sw or entry_sw in sw

def scan_software(software, version=None):
    matches = [e for e in CVE_DB if _match(software, e)]
    if version and matches:
        version_matches = [e for e in matches if not e["versions"] or any(version.startswith(v) for v in e["versions"])]
        version_na = [e for e in matches if e["versions"] and not any(version.startswith(v) for v in e["versions"])]
    else:
        version_matches = matches
        version_na = []

    results = []
    for e in version_matches:
        results.append({**e, "affects_version": True})
    for e in version_na:
        results.append({**e, "affects_version": False, "note": "Version not in affected list — verify manually"})

    results.sort(key=lambda r: (-r["cvss"], r["cve"]))

    summary = {
        "total": len(results),
        "critical": sum(1 for r in results if r["severity"]=="critical" and r.get("affects_version",True)),
        "high":     sum(1 for r in results if r["severity"]=="high"     and r.get("affects_version",True)),
        "medium":   sum(1 for r in results if r["severity"]=="medium"   and r.get("affects_version",True)),
        "max_cvss": max((r["cvss"] for r in results), default=0),
    }
    risk = "critical" if summary["critical"] > 0 else "high" if summary["high"] > 0 else "medium" if summary["medium"] > 0 else "low" if results else "unknown"
    return {"software":software,"version":version,"cves":results,"summary":summary,"risk":risk,
            "scanned_at":datetime.datetime.now().isoformat()}

class Handler(BaseHTTPRequestHandler):
    def log_message(self,*a): pass
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin","*")
        self.send_header("Access-Control-Allow-Methods","GET,POST,OPTIONS")
        self.send_header("Access-Control-Allow-Headers","Content-Type")
        self.send_header("Content-Length","0"); self.end_headers()
    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Accept, Authorization")
        self.send_header("Access-Control-Max-Age", "86400")
    def _json(self, status, data):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(body)))
        self._cors(); self.end_headers(); self.wfile.write(body)
    def parse_body(self):
        length = int(self.headers.get("Content-Length",0))
        raw = self.rfile.read(length) if length else b""
        try: return json.loads(raw.decode())
        except: return {}
    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/health": self._json(200,{"status":"ok","service":"CVE Scanner"})
        elif parsed.path == "/cve/search":
            q = parse_qs(parsed.query).get("q",[""])[0].strip()
            if not q: self._json(400,{"error":"Missing query param: q"}); return
            results = [e for e in CVE_DB if q.lower() in e["software"] or q.upper() in e["cve"] or q.lower() in e["desc"].lower()]
            self._json(200,{"query":q,"results":results,"count":len(results)})
        else: self._json(404,{"error":"not found"})
    def do_POST(self):
        path = urlparse(self.path).path
        body = self.parse_body()
        if path == "/cve/scan":
            sw = body.get("software","").strip()
            user_id = body.get("user_id")
            if not sw: self._json(400,{"error":"Missing: software"}); return
            scan_id = activity_log.start_scan(user_id, "CVE Scanner", sw) if user_id else None
            result = scan_software(sw, body.get("version","").strip() or None)
            if user_id:
                for cve in result.get("cves", []):
                    if cve.get("affects_version", True):
                        activity_log.add_finding(
                            user_id, "CVE Scanner", sw,
                            f"{cve.get('cve')} (CVSS {cve.get('cvss')}): {cve.get('desc', '')[:80]}",
                            severity=cve.get("severity", "medium"), scan_id=scan_id,
                        )
                activity_log.finish_scan(scan_id, status="completed", tool="CVE Scanner", target=sw, user_id=user_id)
            self._json(200, result)
        elif path == "/cve/bulk":
            targets = body.get("targets",[])[:20]
            user_id = body.get("user_id")
            results = [scan_software(t.get("software",""), t.get("version","").strip() or None) for t in targets]
            critical_count = sum(1 for r in results if r["risk"]=="critical")
            if user_id:
                names = ", ".join(t.get("software","?") for t in targets)[:100]
                scan_id = activity_log.start_scan(user_id, "CVE Scanner", names)
                if critical_count:
                    activity_log.add_finding(
                        user_id, "CVE Scanner", names,
                        f"{critical_count} of {len(results)} scanned components have critical CVEs",
                        severity="critical", scan_id=scan_id,
                    )
                activity_log.finish_scan(scan_id, status="completed", tool="CVE Scanner", target=names, user_id=user_id)
            self._json(200,{"results":results,"total":len(results),
                "critical_count": critical_count})
        else: self._json(404,{"error":"not found"})

HTTPServer.allow_reuse_address = True
if __name__ == "__main__":
    srv = HTTPServer(("0.0.0.0", PORT), Handler)
    print(f"[CVE Scanner] Running on:{PORT}")
    srv.serve_forever()