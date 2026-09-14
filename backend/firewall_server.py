#!/usr/bin/env python3
import os, sys
sys.path.insert(0, os.path.dirname(__file__))
import activity_log
"""
Firewall Rule Tester Backend — port 8777
Endpoints:
  GET  /health
  POST /firewall/test   {host, ports, protocol?}
  POST /firewall/analyze {rules}
"""
import socket, json, concurrent.futures, time, datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

import os
PORT = int(os.environ.get("PORT", 8777))

WELL_KNOWN = {
    20:"FTP-Data",21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",
    53:"DNS",67:"DHCP",68:"DHCP",69:"TFTP",80:"HTTP",
    110:"POP3",119:"NNTP",123:"NTP",135:"RPC",137:"NetBIOS",
    138:"NetBIOS",139:"NetBIOS",143:"IMAP",161:"SNMP",
    194:"IRC",389:"LDAP",443:"HTTPS",445:"SMB",465:"SMTPS",
    514:"Syslog",587:"SMTP",636:"LDAPS",993:"IMAPS",995:"POP3S",
    1433:"MSSQL",1521:"Oracle",3306:"MySQL",3389:"RDP",
    5432:"PostgreSQL",5900:"VNC",6379:"Redis",8080:"HTTP-Alt",
    8443:"HTTPS-Alt",9200:"Elasticsearch",27017:"MongoDB",11211:"Memcached",
}
SHOULD_BE_BLOCKED = {23,135,137,138,139,445,1433,3389,5900,6379,9200,11211,27017}
SHOULD_BE_OPEN    = {22,80,443}

def _cors(h):
    h.send_header("Access-Control-Allow-Origin","*")
    h.send_header("Access-Control-Allow-Methods","GET,POST,OPTIONS")
    h.send_header("Access-Control-Allow-Headers","Content-Type")

def _json(h, status, data):
    body = json.dumps(data).encode()
    h.send_response(status)
    h.send_header("Content-Type","application/json")
    h.send_header("Content-Length",str(len(body)))
    _cors(h); h.end_headers(); h.wfile.write(body)

def parse_body(h):
    length = int(h.headers.get("Content-Length",0))
    raw = h.rfile.read(length) if length else b""
    try: return json.loads(raw.decode())
    except: return {}

def probe_port(host, port, timeout=2.5):
    t0 = time.time()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            latency = round((time.time()-t0)*1000, 1)
            return {"port":port,"state":"open","latency_ms":latency,
                    "service":WELL_KNOWN.get(port,"unknown")}
    except socket.timeout:
        return {"port":port,"state":"filtered","latency_ms":None,
                "service":WELL_KNOWN.get(port,"unknown")}
    except ConnectionRefusedError:
        return {"port":port,"state":"closed","latency_ms":None,
                "service":WELL_KNOWN.get(port,"unknown")}
    except Exception:
        return {"port":port,"state":"filtered","latency_ms":None,
                "service":WELL_KNOWN.get(port,"unknown")}

def test_firewall(host, ports):
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(ports),40)) as ex:
        fmap = {ex.submit(probe_port, host, p): p for p in ports}
        for f in concurrent.futures.as_completed(fmap):
            try: results.append(f.result(timeout=4))
            except: results.append({"port":fmap[f],"state":"error","latency_ms":None,"service":"unknown"})

    results.sort(key=lambda r: r["port"])

    findings = []
    for r in results:
        p = r["port"]
        state = r["state"]
        svc = r["service"]
        if p in SHOULD_BE_BLOCKED and state == "open":
            findings.append({"port":p,"service":svc,"severity":"critical",
                "issue":f"Dangerous service {svc} (:{p}) is OPEN — should be blocked",
                "recommendation":f"Block port {p} at firewall unless explicitly required"})
        elif p in SHOULD_BE_OPEN and state in ("closed","filtered"):
            findings.append({"port":p,"service":svc,"severity":"warning",
                "issue":f"Expected service {svc} (:{p}) appears {state}",
                "recommendation":f"Verify {svc} is intentionally disabled or misconfigured"})

    summary = {
        "open":     sum(1 for r in results if r["state"]=="open"),
        "closed":   sum(1 for r in results if r["state"]=="closed"),
        "filtered": sum(1 for r in results if r["state"]=="filtered"),
        "critical_findings": sum(1 for f in findings if f["severity"]=="critical"),
    }
    return {"host":host,"timestamp":datetime.datetime.now().isoformat(),
            "results":results,"findings":findings,"summary":summary}

def analyze_rules(rules_text):
    """Parse and audit iptables/ufw style rules text."""
    lines = [l.strip() for l in rules_text.strip().splitlines() if l.strip() and not l.strip().startswith("#")]
    parsed = []
    issues = []
    for i, line in enumerate(lines):
        rule = {"line":i+1,"raw":line,"action":None,"port":None,"proto":None,"src":None,"issue":None}
        upper = line.upper()
        if "ACCEPT" in upper: rule["action"] = "ACCEPT"
        elif "DROP" in upper or "DENY" in upper: rule["action"] = "DROP"
        elif "REJECT" in upper: rule["action"] = "REJECT"
        import re
        pm = re.search(r"--dport\s+(\d+)|port\s+(\d+)", line, re.I)
        if pm: rule["port"] = int(pm.group(1) or pm.group(2))
        if "tcp" in upper: rule["proto"] = "TCP"
        elif "udp" in upper: rule["proto"] = "UDP"
        src_m = re.search(r"-s\s+([\d./]+)|from\s+([\d./]+)", line, re.I)
        if src_m: rule["src"] = src_m.group(1) or src_m.group(2)
        if rule["action"]=="ACCEPT" and rule["src"] and rule["src"]=="0.0.0.0/0":
            if rule["port"] and rule["port"] in SHOULD_BE_BLOCKED:
                rule["issue"] = f"Rule allows dangerous port {rule['port']} from ANY source"
                issues.append({"line":i+1,"severity":"critical","issue":rule["issue"]})
        if rule["action"]=="ACCEPT" and not rule["src"]:
            if rule["port"] and rule["port"] in SHOULD_BE_BLOCKED:
                rule["issue"] = f"Unrestricted ACCEPT on risky port {rule['port']}"
                issues.append({"line":i+1,"severity":"high","issue":rule["issue"]})
        parsed.append(rule)
    return {"parsed":parsed,"issues":issues,"total_rules":len(parsed),
            "accept_rules":sum(1 for r in parsed if r["action"]=="ACCEPT"),
            "drop_rules":sum(1 for r in parsed if r["action"] in ("DROP","REJECT"))}

class Handler(BaseHTTPRequestHandler):
    def log_message(self,*a): pass
    def do_OPTIONS(self):
        self.send_response(200); _cors(self)
        self.send_header("Content-Length","0"); self.end_headers()
    def do_GET(self):
        if urlparse(self.path).path=="/health": _json(self,200,{"status":"ok","service":"Firewall Tester"})
        else: _json(self,404,{"error":"not found"})
    def do_POST(self):
        path = urlparse(self.path).path
        body = parse_body(self)
        if path == "/firewall/test":
            host = body.get("host","").strip()
            user_id = body.get("user_id")
            if not host: _json(self,400,{"error":"Missing: host"}); return
            raw_ports = body.get("ports",[])
            if isinstance(raw_ports, str):
                try:
                    if "-" in raw_ports:
                        lo,hi = map(int,raw_ports.split("-",1))
                        raw_ports = list(range(lo,min(hi+1,lo+200)))
                    else:
                        raw_ports = [int(p.strip()) for p in raw_ports.split(",") if p.strip()]
                except: raw_ports = list(WELL_KNOWN.keys())
            if not raw_ports: raw_ports = list(WELL_KNOWN.keys())
            raw_ports = raw_ports[:200]
            scan_id = activity_log.start_scan(user_id, "Firewall Tester", host) if user_id else None
            try:
                result = test_firewall(host,raw_ports)
                if user_id:
                    for f in result.get("findings", []):
                        severity = "critical" if f.get("severity") == "critical" else "medium"
                        activity_log.add_finding(
                            user_id, "Firewall Tester", host,
                            f"Port {f.get('port')} ({f.get('service')}) not properly filtered",
                            severity=severity, scan_id=scan_id,
                        )
                    activity_log.finish_scan(scan_id, status="completed", tool="Firewall Tester", target=host, user_id=user_id)
                _json(self,200,result)
            except Exception as e:
                if user_id and scan_id:
                    activity_log.finish_scan(scan_id, status="failed", tool="Firewall Tester", target=host, user_id=user_id)
                _json(self,500,{"error":str(e)})
        elif path == "/firewall/analyze":
            rules = body.get("rules","")
            user_id = body.get("user_id")
            if not rules: _json(self,400,{"error":"Missing: rules"}); return
            scan_id = activity_log.start_scan(user_id, "Firewall Tester", "rule set") if user_id else None
            try:
                result = analyze_rules(rules)
                if user_id:
                    for issue in result.get("issues", []):
                        activity_log.add_finding(
                            user_id, "Firewall Tester", "rule set",
                            f"Line {issue.get('line')}: {issue.get('issue')}",
                            severity=issue.get("severity", "medium"), scan_id=scan_id,
                        )
                    activity_log.finish_scan(scan_id, status="completed", tool="Firewall Tester", target="rule set", user_id=user_id)
                _json(self,200,result)
            except Exception as e:
                if user_id and scan_id:
                    activity_log.finish_scan(scan_id, status="failed", tool="Firewall Tester", target="rule set", user_id=user_id)
                _json(self,500,{"error":str(e)})
        else: _json(self,404,{"error":"not found"})

HTTPServer.allow_reuse_address = True
if __name__ == "__main__":
    srv = HTTPServer(("0.0.0.0",PORT), Handler)
    print(f"[Firewall Tester] Running on:{PORT}")
    srv.serve_forever()