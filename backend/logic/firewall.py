#!/usr/bin/env python3
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

