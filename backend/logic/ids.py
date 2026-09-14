#!/usr/bin/env python3
"""
IDS Analyzer Server — port 8774
URL/file threat scanning. Uses VirusTotal API v3 if key is set,
otherwise runs a deterministic offline simulation.
"""

import json
import hashlib
import time
import urllib.request
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler

import os
PORT = int(os.environ.get("PORT", 8774))
VT_API_KEY = os.environ.get("VT_API_KEY", "")   # Set as an environment variable — never hardcode. Free key: https://www.virustotal.com/gui/join-us

CORS = {
    "Access-Control-Allow-Origin":  "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Content-Type":                 "application/json",
}

# ── Simulation data ────────────────────────────────────────────────────────────

ENGINES = [
    "Avast","AVG","Bitdefender","Kaspersky","McAfee","Norton","Malwarebytes",
    "ESET","Sophos","TrendMicro","F-Secure","Panda","Dr.Web","Comodo","Fortinet",
    "CrowdStrike","SentinelOne","CarbonBlack","Cylance","Symantec","Webroot",
    "Avira","Emsisoft","GData","Ikarus","K7","Kingsoft","Lionic","MAX",
    "MicroWorld","NANO-Antivirus","QuickHeal","Rising","Sangfor","VIPRE",
    "ViRobot","ZoneAlarm","Acronis","AhnLab","ALYac","Arcabit","Baidu",
    "ClamAV","Cynet","DeepInstinct","Elastic","Jiangmin","K7GW","MaxSecure",
    "Microsoft","Paloalto","Qihoo-360","VBA32","Xcitium","Yandex","Zillya",
    "Zoner","AegisLab","Antiy-AVL","CAT-QuickHeal","CMC","TotalDefense",
    "Trustlook","VirusDie","SUPERAntiSpyware","WhiteArmor","ThreatTrack",
]

THREAT_RESULTS = [
    "Malware.Generic","Trojan.GenericKD","Phishing.URL.Agent",
    "PUP.Optional.Bundler","Exploit.Script.Agent","Backdoor.Generic",
    "Ransomware.Filecoder","Spyware.Keylogger","Adware.CrossRider",
    "Downloader.Agent","Rootkit.Agent","Trojan.Dropper",
]

# Explicit ground-truth: domain → (malicious_count, suspicious_count)
# Anything not listed is scored by URL feature analysis
KNOWN_SAFE = {
    "google.com","github.com","microsoft.com","apple.com","amazon.com",
    "cloudflare.com","mozilla.org","wikipedia.org","stackoverflow.com",
    "youtube.com","twitter.com","linkedin.com","reddit.com","medium.com",
    "dev.to","npmjs.com","pypi.org","certifiedhacker.com","hackthebox.com",
    "tryhackme.com","owasp.org","kali.org","offensive-security.com",
}

KNOWN_MALICIOUS_DOMAINS = {
    "malware-traffic-analysis.net":  (45, 8),
    "thepiratebay.org":              (12, 15),
    "fakeupdate.net":                (55, 5),
    "pornhub.com":                   (3, 18),
}

# TLDs that are statistically high-risk
RISKY_TLDS = {".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".click",
              ".download", ".zip", ".loan", ".work", ".party", ".stream"}

# URL signals that indicate phishing / malicious intent
PHISHING_SIGNALS = [
    "paypal-", "amazon-", "apple-", "microsoft-", "google-",
    "secure-login", "verify-account", "update-billing", "signin-",
    "confirm-payment", "-webscr", "account-suspended",
]

MALICIOUS_PATH_SIGNALS = [
    "/wp-content/uploads/", "/admin/shell", "/../", "/etc/passwd",
    "cmd=", "exec(", "eval(", "base64_decode", "/phpmyadmin/",
    "/cgi-bin/", ".php?id=", "UNION SELECT", "<script>",
]


def extract_domain(target: str) -> str:
    if "://" not in target:
        target = "https://" + target
    try:
        parsed = urllib.parse.urlparse(target)
        host = parsed.netloc.lower()
        # strip port
        return host.split(":")[0]
    except Exception:
        return target.lower()


def score_url(target: str) -> tuple[int, int]:
    """
    Return (malicious_count, suspicious_count) out of len(ENGINES) engines.
    Uses deterministic feature analysis — same input always returns same result.
    """
    domain = extract_domain(target)
    url_lower = target.lower()
    total = len(ENGINES)

    # Explicit safe list → clean
    for safe in KNOWN_SAFE:
        if domain == safe or domain.endswith("." + safe):
            return (0, 0)

    # Explicit malicious list
    for mal_domain, counts in KNOWN_MALICIOUS_DOMAINS.items():
        if domain == mal_domain or domain.endswith("." + mal_domain):
            return counts

    # ── Feature scoring ────────────────────────────────────────────────────
    mal_score  = 0  # 0–100
    sus_score  = 0  # 0–100

    # Risky TLD
    for tld in RISKY_TLDS:
        if domain.endswith(tld):
            mal_score += 20
            sus_score += 15

    # Phishing keyword in subdomain / path
    for sig in PHISHING_SIGNALS:
        if sig in url_lower:
            mal_score += 35
            break

    # Malicious path patterns
    for sig in MALICIOUS_PATH_SIGNALS:
        if sig.lower() in url_lower:
            mal_score += 40
            break

    # IP address as host (rare for legit sites)
    import re
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
        sus_score += 25
        mal_score += 15

    # Excessive subdomains (e.g. a.b.c.d.example.com)
    if domain.count(".") >= 4:
        sus_score += 20

    # Very long domain
    if len(domain) > 50:
        sus_score += 15

    # Lots of hyphens in domain (typosquatting signal)
    if domain.count("-") >= 3:
        sus_score += 20

    # Numeric-heavy domain
    digit_ratio = sum(c.isdigit() for c in domain.split(".")[0]) / max(len(domain.split(".")[0]), 1)
    if digit_ratio > 0.5:
        sus_score += 20

    # Cap at 100
    mal_score  = min(mal_score, 100)
    sus_score  = min(sus_score, 100)

    # Convert score → engine counts (deterministic, no random)
    mal_count = round((mal_score / 100) * total * 0.85)
    sus_count = round((sus_score / 100) * total * 0.60)

    # Ensure counts don't exceed total
    if mal_count + sus_count > total:
        sus_count = total - mal_count

    return (max(0, mal_count), max(0, sus_count))


def score_file(filename: str, content_hash: str) -> tuple[int, int]:
    """Score a file by name and hash."""
    total = len(ENGINES)
    fn_lower = filename.lower()

    # Known safe extensions with normal names
    safe_exts = {".pdf", ".docx", ".xlsx", ".pptx", ".jpg", ".png", ".gif", ".mp4", ".mp3", ".txt", ".csv"}
    risky_exts = {".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".scr", ".pif", ".com"}
    very_risky_names = ["virus", "malware", "trojan", "keylogger", "ransomware", "backdoor", "exploit", "payload", "shellcode", "rootkit"]

    if any(fn_lower.endswith(ext) for ext in safe_exts):
        # Safe extension but check for double extension trick
        if fn_lower.count(".") >= 3:
            return (round(total * 0.25), round(total * 0.15))
        return (0, 0)

    if any(name in fn_lower for name in very_risky_names):
        return (round(total * 0.72), round(total * 0.10))

    if any(fn_lower.endswith(ext) for ext in risky_exts):
        return (round(total * 0.15), round(total * 0.30))

    # Unknown extension — mildly suspicious
    return (0, round(total * 0.12))


def build_engine_results(mal_count: int, sus_count: int, seed: str) -> dict:
    """
    Assign engine verdicts deterministically using hash-seeded ordering.
    """
    # Create a stable permutation of engines using the seed
    seed_bytes = hashlib.sha256(seed.encode()).digest()
    # Use seed bytes to create an index permutation
    indexed = [(seed_bytes[i % len(seed_bytes)] ^ (i * 37), eng) for i, eng in enumerate(ENGINES)]
    indexed.sort()
    ordered_engines = [eng for _, eng in indexed]

    # Also stable permutation of threat results
    threat_indexed = [(seed_bytes[i % len(seed_bytes)] ^ (i * 13), t) for i, t in enumerate(THREAT_RESULTS)]
    threat_indexed.sort()
    ordered_threats = [t for _, t in threat_indexed]

    mal_set = set(ordered_engines[:mal_count])
    sus_set = set(ordered_engines[mal_count:mal_count + sus_count])

    results = {}
    threat_i = 0
    for eng in ENGINES:
        if eng in mal_set:
            results[eng] = {
                "category": "malicious",
                "result": ordered_threats[threat_i % len(ordered_threats)],
                "method": "blacklist",
                "engine_version": f"{(seed_bytes[threat_i % 32] % 9) + 1}.{seed_bytes[(threat_i+1) % 32] % 10}.{seed_bytes[(threat_i+2) % 32] % 900 + 100}",
            }
            threat_i += 1
        elif eng in sus_set:
            results[eng] = {
                "category": "suspicious",
                "result": "Suspicious.Heuristic",
                "method": "heuristic",
                "engine_version": f"{(seed_bytes[threat_i % 32] % 9) + 1}.{seed_bytes[(threat_i+1) % 32] % 10}.{seed_bytes[(threat_i+2) % 32] % 900 + 100}",
            }
            threat_i += 1
        else:
            results[eng] = {
                "category": "harmless",
                "result": None,
                "method": "blacklist",
                "engine_version": f"{(seed_bytes[threat_i % 32] % 9) + 1}.{seed_bytes[(threat_i+1) % 32] % 10}.0",
            }
    return results


def simulate_scan(target: str, scan_type: str) -> dict:
    total = len(ENGINES)

    if scan_type == "file":
        content_hash = hashlib.sha256(target.encode()).hexdigest()
        mal_count, sus_count = score_file(target, content_hash)
        meta = {
            "name": target,
            "sha256": content_hash,
            "md5": hashlib.md5(target.encode()).hexdigest(),
        }
    else:
        mal_count, sus_count = score_url(target)
        domain = extract_domain(target)
        meta = {"url": target, "domain": domain}

    # Clamp
    mal_count = min(mal_count, total)
    sus_count = min(sus_count, total - mal_count)

    engine_results = build_engine_results(mal_count, sus_count, seed=target)

    harmless = total - mal_count - sus_count

    if mal_count >= 5:
        verdict = "malicious"
    elif mal_count > 0 or sus_count >= 8:
        verdict = "suspicious"
    else:
        verdict = "clean"

    return {
        "source": "simulation",
        "scan_type": scan_type,
        "target": target,
        "meta": meta,
        "stats": {
            "malicious":  mal_count,
            "suspicious": sus_count,
            "harmless":   max(0, harmless),
            "undetected": 0,
            "total":      total,
        },
        "verdict": verdict,
        "results": engine_results,
        "scan_date": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


# ── VirusTotal live scan ───────────────────────────────────────────────────────

def vt_scan_url(url: str) -> dict:
    data = urllib.parse.urlencode({"url": url}).encode()
    req = urllib.request.Request(
        "https://www.virustotal.com/api/v3/urls",
        data=data,
        headers={"x-apikey": VT_API_KEY, "Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as r:
        submission = json.loads(r.read())

    analysis_id = submission["data"]["id"]
    for _ in range(5):
        time.sleep(3)
        poll = urllib.request.Request(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers={"x-apikey": VT_API_KEY},
        )
        with urllib.request.urlopen(poll, timeout=15) as r:
            analysis = json.loads(r.read())
        if analysis["data"]["attributes"]["status"] == "completed":
            break

    attrs  = analysis["data"]["attributes"]
    stats  = attrs.get("stats", {})
    raw    = attrs.get("results", {})

    results = {
        eng: {
            "category": v.get("category", "undetected"),
            "result":   v.get("result"),
            "method":   v.get("method", ""),
            "engine_version": v.get("engine_version", ""),
        }
        for eng, v in raw.items()
    }

    total      = sum(stats.values()) or 1
    malicious  = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)

    verdict = "malicious" if malicious >= 5 else ("suspicious" if malicious > 0 or suspicious >= 3 else "clean")

    return {
        "source": "virustotal",
        "scan_type": "url",
        "target": url,
        "meta": {"url": url},
        "stats": {
            "malicious":  malicious,
            "suspicious": suspicious,
            "harmless":   stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "total":      total,
        },
        "verdict": verdict,
        "results": results,
        "scan_date": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


# ── HTTP handler ───────────────────────────────────────────────────────────────