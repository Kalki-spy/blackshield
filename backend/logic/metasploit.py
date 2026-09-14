#!/usr/bin/env python3
"""
Metasploit-style Vulnerability Scanner — core logic
Pure Python — no external dependencies
"""

import socket
import concurrent.futures
import time
import ssl
from urllib.parse import urlparse

# ── CVE / Vulnerability Database ─────────────────────────────────────────────

CVE_DB = {
    21:  [{"id": "CVE-2010-4221", "name": "ProFTPD Buffer Overflow",          "severity": "CRITICAL", "cvss": 9.3,  "desc": "Remote code execution via buffer overflow in ProFTPD < 1.3.3c"},
          {"id": "CVE-2015-3306", "name": "ProFTPD mod_copy Unauthenticated", "severity": "CRITICAL", "cvss": 10.0, "desc": "Allows unauthenticated copy of files via mod_copy module"}],
    22:  [{"id": "CVE-2018-15473", "name": "OpenSSH User Enumeration",        "severity": "MEDIUM",   "cvss": 5.3,  "desc": "OpenSSH through 7.7 allows user enumeration via timing side-channel"},
          {"id": "CVE-2016-0777",  "name": "OpenSSH Information Leak",         "severity": "MEDIUM",   "cvss": 6.5,  "desc": "UseRoaming in OpenSSH client leaks private keys"}],
    23:  [{"id": "CVE-2011-4862", "name": "Telnet Plaintext Protocol",        "severity": "HIGH",     "cvss": 8.1,  "desc": "Telnet transmits credentials in plaintext — trivially sniffed"}],
    25:  [{"id": "CVE-2014-3566", "name": "POODLE via SMTP STARTTLS",         "severity": "MEDIUM",   "cvss": 4.3,  "desc": "SMTP STARTTLS downgrade to SSLv3 enables POODLE attack"},
          {"id": "CVE-2020-7247", "name": "OpenSMTPD RCE",                    "severity": "CRITICAL", "cvss": 9.8,  "desc": "Remote code execution in OpenSMTPD < 6.6.2p1"}],
    80:  [{"id": "CVE-2021-41773", "name": "Apache Path Traversal",           "severity": "CRITICAL", "cvss": 9.8,  "desc": "Path traversal and RCE in Apache HTTP Server 2.4.49"},
          {"id": "CVE-2017-5638",  "name": "Apache Struts2 RCE",               "severity": "CRITICAL", "cvss": 10.0, "desc": "Remote code execution via Content-Type header in Struts 2"},
          {"id": "CVE-2014-6271",  "name": "Shellshock (Bash RCE)",            "severity": "CRITICAL", "cvss": 10.0, "desc": "CGI scripts trigger arbitrary command execution via Bash env vars"}],
    443: [{"id": "CVE-2014-0160",  "name": "Heartbleed (OpenSSL)",             "severity": "CRITICAL", "cvss": 7.5,  "desc": "Memory disclosure in OpenSSL 1.0.1 through 1.0.1f"},
          {"id": "CVE-2016-2183",  "name": "SWEET32 (3DES)",                   "severity": "MEDIUM",   "cvss": 5.9,  "desc": "3DES cipher in TLS enables birthday attack after 785GB of traffic"},
          {"id": "CVE-2014-3566",  "name": "POODLE (SSLv3)",                   "severity": "MEDIUM",   "cvss": 4.3,  "desc": "SSLv3 padding oracle allows session decryption"}],
    445: [{"id": "CVE-2017-0144",  "name": "EternalBlue (MS17-010)",           "severity": "CRITICAL", "cvss": 9.8,  "desc": "SMBv1 RCE used by WannaCry and NotPetya ransomware"},
          {"id": "CVE-2020-0796",  "name": "SMBGhost",                         "severity": "CRITICAL", "cvss": 10.0, "desc": "SMBv3 compression buffer overflow — wormable RCE"}],
    3306:[{"id": "CVE-2012-2122",  "name": "MySQL Auth Bypass",                "severity": "CRITICAL", "cvss": 9.8,  "desc": "Timing attack allows login bypass without valid password"},
          {"id": "CVE-2016-6662",  "name": "MySQL RCE via my.cnf",             "severity": "CRITICAL", "cvss": 9.8,  "desc": "Attacker can overwrite my.cnf and execute malicious plugins"}],
    3389:[{"id": "CVE-2019-0708",  "name": "BlueKeep (RDP RCE)",               "severity": "CRITICAL", "cvss": 9.8,  "desc": "Pre-auth RCE in Windows Remote Desktop Services — wormable"},
          {"id": "CVE-2019-1182",  "name": "DejaBlue (RDP RCE)",               "severity": "CRITICAL", "cvss": 9.8,  "desc": "Similar to BlueKeep, affects newer Windows versions"}],
    5432:[{"id": "CVE-2019-9193",  "name": "PostgreSQL COPY TO/FROM PROGRAM",  "severity": "HIGH",     "cvss": 7.2,  "desc": "Superuser can execute OS commands via COPY TO/FROM PROGRAM"}],
    6379:[{"id": "CVE-2022-0543",  "name": "Redis Lua Sandbox Escape",         "severity": "CRITICAL", "cvss": 10.0, "desc": "Lua sandbox escape allows RCE in Redis 2:5.0.7-2.1 on Debian"}],
    8080:[{"id": "CVE-2020-1938",  "name": "Ghostcat (Apache Tomcat AJP)",     "severity": "CRITICAL", "cvss": 9.8,  "desc": "AJP connector reads any file from webapps directory"}],
    27017:[{"id": "CVE-2013-2132", "name": "MongoDB Unauth Access",            "severity": "HIGH",     "cvss": 7.5,  "desc": "Default MongoDB install has no authentication — full DB access"}],
}

SERVICE_BANNERS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    27017: "MongoDB",
}

DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
                 993, 995, 1433, 3306, 3389, 5432, 5900, 6379,
                 8080, 8443, 27017]

# ── Scanner ───────────────────────────────────────────────────────────────────

def probe_port(host: str, port: int, timeout: float = 1.2) -> dict | None:
    """Try to connect to a port. Returns info if open, None if closed."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        banner = ""
        try:
            sock.settimeout(1.0)
            data = sock.recv(256)
            banner = data.decode(errors="replace").strip()[:120]
        except Exception:
            pass
        sock.close()
        return {
            "port":    port,
            "service": SERVICE_BANNERS.get(port, "unknown"),
            "state":   "open",
            "banner":  banner,
            "cves":    CVE_DB.get(port, []),
        }
    except Exception:
        return None


def grab_http_info(host: str, port: int) -> dict:
    """Grab HTTP headers for fingerprinting."""
    info = {}
    try:
        scheme = "https" if port in (443, 8443) else "http"
        ctx = ssl.create_default_context() if scheme == "https" else None
        if ctx:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        conn_cls = __import__("http.client", fromlist=["HTTPSConnection" if scheme == "https" else "HTTPConnection"])
        ConnCls = conn_cls.HTTPSConnection if scheme == "https" else conn_cls.HTTPConnection
        conn = ConnCls(host, port, timeout=4, **({"context": ctx} if ctx else {}))
        conn.request("HEAD", "/")
        resp = conn.getresponse()
        info["http_status"] = resp.status
        info["server"]      = resp.getheader("Server", "")
        info["powered_by"]  = resp.getheader("X-Powered-By", "")
        info["x_frame"]     = resp.getheader("X-Frame-Options", "missing")
        info["csp"]         = "present" if resp.getheader("Content-Security-Policy") else "missing"
        info["hsts"]        = "present" if resp.getheader("Strict-Transport-Security") else "missing"
    except Exception:
        pass
    return info


def scan_target(target: str, ports: list[int] | None = None, scan_type: str = "full") -> dict:
    """Full vulnerability scan."""
    parsed = urlparse(target if "://" in target else "http://" + target)
    host = parsed.hostname or target.split(":")[0]

    try:
        ip = socket.gethostbyname(host)
    except Exception as e:
        return {"error": f"Cannot resolve {host}: {e}"}

    if ports is None:
        ports = DEFAULT_PORTS if scan_type == "full" else [80, 443, 22, 21, 445, 3306, 3389]

    start = time.time()
    open_ports = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=40) as ex:
        futures = {ex.submit(probe_port, host, p): p for p in ports}
        for fut in concurrent.futures.as_completed(futures):
            result = fut.result()
            if result:
                open_ports.append(result)

    http_info = {}
    for p in open_ports:
        if p["port"] in (80, 443, 8080, 8443):
            http_info = grab_http_info(host, p["port"])
            p["http_info"] = http_info
            break

    open_ports.sort(key=lambda x: x["port"])

    all_cves = []
    for p in open_ports:
        for cve in p.get("cves", []):
            all_cves.append({**cve, "port": p["port"], "service": p["service"]})

    critical = sum(1 for c in all_cves if c["severity"] == "CRITICAL")
    high     = sum(1 for c in all_cves if c["severity"] == "HIGH")
    medium   = sum(1 for c in all_cves if c["severity"] == "MEDIUM")
    risk_score = min(100, critical * 20 + high * 10 + medium * 5)

    if risk_score >= 80:   risk_level = "CRITICAL"
    elif risk_score >= 50: risk_level = "HIGH"
    elif risk_score >= 20: risk_level = "MEDIUM"
    elif risk_score > 0:   risk_level = "LOW"
    else:                  risk_level = "CLEAN"

    return {
        "target":       host,
        "ip":           ip,
        "scan_type":    scan_type,
        "ports_scanned":len(ports),
        "open_ports":   len(open_ports),
        "scan_time":    round(time.time() - start, 2),
        "ports":        open_ports,
        "cves":         all_cves,
        "total_cves":   len(all_cves),
        "critical":     critical,
        "high":         high,
        "medium":       medium,
        "risk_score":   risk_score,
        "risk_level":   risk_level,
        "http_info":    http_info,
    }
