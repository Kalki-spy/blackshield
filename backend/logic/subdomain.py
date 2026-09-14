#!/usr/bin/env python3
"""
Subdomain Finder Backend
Uses DNS resolution + crt.sh certificate transparency logs + common wordlist

Usage:
    python subdomain_server.py

Endpoints:
    GET /health                — health check
    GET /find?domain=...       — find subdomains for a domain
"""

import socket
import json
import re
import urllib.request
import concurrent.futures
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs


# ── Configuration ─────────────────────────────────────────────────────────────
import os
PORT = int(os.environ.get("PORT", 8770))
ALLOWED_ORIGINS = ["*"]
DNS_TIMEOUT = 3
MAX_WORKERS = 50
# ──────────────────────────────────────────────────────────────────────────────

WORDLIST = [
    "www", "mail", "ftp", "smtp", "pop", "ns1", "ns2", "ns3", "ns4",
    "webmail", "remote", "blog", "web", "dev", "staging", "test", "api",
    "m", "mobile", "shop", "store", "forum", "wiki", "admin", "portal",
    "vpn", "ssh", "sftp", "pop3", "imap", "mx", "mx1", "mx2",
    "app", "apps", "static", "cdn", "assets", "media", "img", "images",
    "secure", "login", "auth", "sso", "oauth", "id", "identity",
    "dashboard", "panel", "cp", "cpanel", "whm", "webmin",
    "git", "gitlab", "github", "svn", "repo", "ci", "jenkins", "build",
    "db", "database", "mysql", "postgres", "mongo", "redis", "elastic",
    "support", "help", "docs", "documentation", "kb", "status",
    "monitor", "monitoring", "grafana", "kibana", "metrics",
    "beta", "alpha", "preview", "demo", "sandbox", "uat", "qa", "prod",
    "v1", "v2", "v3", "api1", "api2", "backend", "frontend",
    "internal", "intranet", "corp", "office", "files", "download",
    "upload", "share", "cloud", "backup", "archive", "old", "new",
    "ns", "dns", "rdns", "smtp1", "smtp2", "mail1", "mail2",
    "video", "stream", "live", "tv", "radio", "podcast",
    "careers", "jobs", "hr", "pay", "billing", "invoice", "account",
    "accounts", "my", "customer", "partner", "vendor",
    "news", "press", "events", "calendar",
    "search", "proxy", "gateway", "lb", "fw", "firewall",
    "owa", "autodiscover", "exchange", "outlook", "autoconfig",
    "meet", "conference", "chat", "analytics", "tracking",
    "test1", "test2", "dev1", "dev2", "stage", "stg",
    "smtp", "imap", "pop", "mail3", "ns5", "ns6",
    "ciphershield", "secure", "vpn2", "remote2",
]


def extract_root_domain(domain: str) -> str:
    """
    Strip scheme, path, port, and ALL subdomains.
    Always returns the registrable root domain (last 2 labels,
    or last 3 for known two-part TLDs like co.uk).

    Examples:
      www.certifiedhacker.com      -> certifiedhacker.com
      sub.deep.example.co.uk       -> example.co.uk
      https://api.example.com/path -> example.com
      example.com                  -> example.com
    """
    domain = domain.lower().strip()

    # Strip scheme
    if "://" in domain:
        parsed = urlparse(domain)
        domain = parsed.hostname or domain

    # Strip port and path
    domain = domain.split(":")[0].split("/")[0].strip(".")

    parts = domain.split(".")
    if len(parts) < 2:
        return domain

    # Known two-part TLDs (second-level + TLD) e.g. co.uk, com.au, org.uk
    two_part_tlds = {
        "co.uk", "co.in", "co.nz", "co.za", "co.jp", "co.kr",
        "com.au", "com.br", "com.cn", "com.mx", "com.ar",
        "org.uk", "net.au", "gov.uk", "ac.uk", "me.uk",
    }
    last_two = ".".join(parts[-2:])
    if last_two in two_part_tlds and len(parts) >= 3:
        return ".".join(parts[-3:])

    # Default: always return last 2 labels (strips all subdomains)
    return ".".join(parts[-2:])


def resolve_host(fqdn: str) -> tuple[str | None, str | None]:
    """Resolve a hostname to IP and attempt reverse DNS. Returns (ip, reverse)."""
    try:
        socket.setdefaulttimeout(DNS_TIMEOUT)
        ip = socket.gethostbyname(fqdn)
        try:
            reverse = socket.gethostbyaddr(ip)[0]
        except Exception:
            reverse = None
        return ip, reverse
    except Exception:
        return None, None


def fetch_crtsh(root_domain: str) -> set[str]:
    """
    Query crt.sh for all certificate SANs matching *.root_domain.
    Returns a set of unique FQDNs.
    """
    found = set()
    try:
        url = f"https://crt.sh/?q=%.{root_domain}&output=json"
        req = urllib.request.Request(url, headers={"User-Agent": "SubdomainFinder/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())

        for entry in data:
            for name in entry.get("name_value", "").splitlines():
                name = name.strip().lower().lstrip("*.")
                if name == root_domain or name.endswith(f".{root_domain}"):
                    found.add(name)
    except Exception:
        pass
    return found


def bruteforce_wordlist(root_domain: str) -> set[str]:
    """
    DNS brute-force using wordlist. Returns set of FQDNs that resolve.
    """
    found = set()

    def try_word(word):
        fqdn = f"{word}.{root_domain}"
        ip, _ = resolve_host(fqdn)
        return fqdn if ip else None

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        for result in ex.map(try_word, WORDLIST):
            if result:
                found.add(result)

    return found


def find_subdomains(input_domain: str) -> dict:
    """
    Full subdomain discovery. Combines crt.sh + wordlist brute-force,
    merges sources, resolves IPs.
    """
    root_domain = extract_root_domain(input_domain)

    # Validate root domain resolves
    try:
        socket.setdefaulttimeout(DNS_TIMEOUT)
        base_ip = socket.gethostbyname(root_domain)
    except Exception:
        return {"error": f"Cannot resolve domain: {root_domain}"}

    # 1. Certificate transparency
    crt_names = fetch_crtsh(root_domain)

    # 2. Wordlist brute-force
    wl_names = bruteforce_wordlist(root_domain)

    # 3. Merge and tag sources
    all_names = crt_names | wl_names

    # 4. Resolve all in parallel
    results = []

    def resolve_entry(fqdn):
        if fqdn in crt_names and fqdn in wl_names:
            source = "both"
        elif fqdn in crt_names:
            source = "certificate"
        else:
            source = "bruteforce"

        ip, reverse = resolve_host(fqdn)
        return {
            "subdomain": fqdn,
            "ip": ip,
            "reverse": reverse,
            "source": source,
        }

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        results = list(ex.map(resolve_entry, sorted(all_names)))

    # Sort alphabetically
    results.sort(key=lambda x: x["subdomain"])

    resolved = [r for r in results if r["ip"]]
    sources: dict[str, int] = {}
    for r in results:
        sources[r["source"]] = sources.get(r["source"], 0) + 1

    return {
        "domain": root_domain,
        "input_domain": input_domain,
        "base_ip": base_ip,
        "total": len(results),
        "resolved": len(resolved),
        "subdomains": results,
        "sources": sources,
    }


# ── HTTP Handler ──────────────────────────────────────────────────────────────

