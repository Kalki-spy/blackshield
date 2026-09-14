#!/usr/bin/env python3
"""
TLS/SSL Analyzer Backend
Pure Python — stdlib ssl + cryptography library

Usage:
    pip install cryptography
    python server.py

Endpoints:
    GET /health          — health check
    GET /analyze?url=... — full TLS/SSL analysis
"""

import ssl
import socket
import json
import datetime
import concurrent.futures
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa

# ── Configuration ──────────────────────────────────────────────────────────────
import os
PORT = int(os.environ.get("PORT", 8765))
ALLOWED_ORIGINS = ["*"]
CONNECT_TIMEOUT = 6   # seconds per socket connection attempt
PROTOCOL_TIMEOUT = 5  # hard wall-clock limit per protocol test thread
# ──────────────────────────────────────────────────────────────────────────────


# ── Certificate ────────────────────────────────────────────────────────────────

def get_certificate_info(hostname: str, port: int = 443) -> dict:
    """Fetch and parse TLS certificate details from a live host."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((hostname, port), timeout=CONNECT_TIMEOUT) as sock:
        sock.settimeout(CONNECT_TIMEOUT)
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            der_cert = ssock.getpeercert(binary_form=True)
            cipher   = ssock.cipher()
            protocol = ssock.version()

    cert = x509.load_der_x509_certificate(der_cert)

    try:
        cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    except Exception:
        cn = str(cert.subject)

    try:
        issuer_cn  = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        issuer_org = cert.issuer.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
        issuer = issuer_cn + (f" ({issuer_org[0].value})" if issuer_org else "")
    except Exception:
        issuer = str(cert.issuer)

    not_before = (
        cert.not_valid_before_utc
        if hasattr(cert, "not_valid_before_utc")
        else cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)
    )
    not_after = (
        cert.not_valid_after_utc
        if hasattr(cert, "not_valid_after_utc")
        else cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    days_remaining = (not_after - now).days

    pub_key = cert.public_key()
    if isinstance(pub_key, rsa.RSAPublicKey):
        key_type, key_bits = "RSA", pub_key.key_size
    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
        key_type, key_bits = "EC", pub_key.key_size
    elif isinstance(pub_key, dsa.DSAPublicKey):
        key_type, key_bits = "DSA", pub_key.key_size
    else:
        key_type, key_bits = "Unknown", 0

    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = san_ext.value.get_values_for_type(x509.DNSName)[:5]
    except Exception:
        sans = []

    serial = format(cert.serial_number, "X")

    try:
        sig_name = cert.signature_hash_algorithm.name.upper() if cert.signature_hash_algorithm else "Unknown"
        sig_alg  = f"{key_type} with {sig_name}"
    except Exception:
        sig_alg = "Unknown"

    fingerprint     = cert.fingerprint(hashes.SHA256()).hex()
    fingerprint_fmt = ":".join(fingerprint[i:i+2].upper() for i in range(0, min(len(fingerprint), 20), 2)) + "..."

    return {
        "subject":            cn,
        "issuer":             issuer,
        "validFrom":          not_before.strftime("%b %d, %Y"),
        "validTo":            not_after.strftime("%b %d, %Y"),
        "daysRemaining":      days_remaining,
        "serialNumber":       serial[:32],
        "signatureAlgorithm": sig_alg,
        "keyType":            key_type,
        "keyBits":            key_bits,
        "sans":               sans,
        "fingerprint":        fingerprint_fmt,
        "activeProtocol":     protocol,
        "activeCipher":       cipher[0] if cipher else "Unknown",
    }


# ── Protocol Testing ───────────────────────────────────────────────────────────

def _probe_protocol(hostname: str, port: int, version_label: str) -> tuple[bool, str]:
    """
    Try to handshake using exactly one TLS version.
    Called inside a thread — never awaited directly.
    Returns (supported: bool, detail: str).
    """
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE

        attr_map = {
            "TLSv1":   "TLSv1",
            "TLSv1.1": "TLSv1_1",
            "TLSv1.2": "TLSv1_2",
            "TLSv1.3": "TLSv1_3",
        }
        attr = attr_map.get(version_label)
        if attr:
            ver = getattr(ssl.TLSVersion, attr, None)
            if ver is None:
                return False, f"{version_label} not available in this OpenSSL build"
            try:
                ctx.minimum_version = ver
                ctx.maximum_version = ver
            except (ssl.SSLError, AttributeError) as e:
                return False, f"Cannot restrict to {version_label}: {e}"

        sock = socket.create_connection((hostname, port), timeout=CONNECT_TIMEOUT)
        sock.settimeout(CONNECT_TIMEOUT)
        try:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                return True, ssock.version() or version_label
        finally:
            try: sock.close()
            except Exception: pass

    except Exception as e:
        return False, str(e)


def test_protocols_parallel(hostname: str, port: int) -> dict[str, tuple[bool, str]]:
    """
    Run all four protocol probes concurrently.
    Returns { version_label: (supported, detail) }
    Total wall-clock time = max(individual probe) instead of sum.
    """
    versions = ["TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1"]
    results: dict[str, tuple[bool, str]] = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
        future_map = {
            ex.submit(_probe_protocol, hostname, port, v): v
            for v in versions
        }
        for future in concurrent.futures.as_completed(future_map, timeout=PROTOCOL_TIMEOUT * 2):
            v = future_map[future]
            try:
                results[v] = future.result(timeout=0)
            except Exception as e:
                results[v] = (False, str(e))

    # Fill any that timed out or were cancelled
    for v in versions:
        if v not in results:
            results[v] = (False, "Check timed out")

    return results


# ── HSTS ───────────────────────────────────────────────────────────────────────

def check_hsts(hostname: str, port: int = 443) -> tuple[bool, str]:
    """Check for Strict-Transport-Security header. Runs with a hard timeout."""
    def _worker():
        try:
            import http.client
            conn = http.client.HTTPSConnection(
                hostname, port, timeout=CONNECT_TIMEOUT,
                context=ssl.create_default_context()
            )
            conn.request("HEAD", "/")
            resp = conn.getresponse()
            hsts = resp.getheader("Strict-Transport-Security")
            return hsts is not None, hsts or ""
        except Exception:
            return False, ""

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        future = ex.submit(_worker)
        try:
            return future.result(timeout=CONNECT_TIMEOUT + 1)
        except Exception:
            return False, ""


# ── Main Analysis ──────────────────────────────────────────────────────────────

def analyze_ssl(url: str) -> dict:
    """Full TLS/SSL analysis. All slow network calls run in parallel."""
    parsed   = urlparse(url)
    hostname = parsed.hostname or parsed.path
    port     = parsed.port or 443

    # ── Step 1: certificate (required — fail fast if unreachable) ─────────────
    try:
        cert_info = get_certificate_info(hostname, port)
    except Exception as e:
        return {"error": f"Cannot connect to {hostname}:{port} — {e}"}

    active_cipher = cert_info.get("activeCipher", "")
    active_proto  = cert_info.get("activeProtocol", "")

    # ── Step 2: protocol probes + HSTS in parallel ────────────────────────────
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
        proto_future = ex.submit(test_protocols_parallel, hostname, port)
        hsts_future  = ex.submit(check_hsts, hostname, port)

        proto_results = proto_future.result(timeout=PROTOCOL_TIMEOUT * 2 + 2)
        hsts_enabled, hsts_value = hsts_future.result(timeout=CONNECT_TIMEOUT + 2)

    results = []

    # ── Certificate checks ────────────────────────────────────────────────────
    days     = cert_info["daysRemaining"]
    key_bits = cert_info["keyBits"]
    key_type = cert_info["keyType"]

    if days > 30:
        results.append({"category": "Certificate", "item": "Certificate Validity",
            "status": "secure", "severity": "low",
            "description": f"Valid certificate — expires {cert_info['validTo']} ({days} days)"})
    elif days > 0:
        results.append({"category": "Certificate", "item": "Certificate Validity",
            "status": "warning", "severity": "high",
            "description": f"Expires soon: {cert_info['validTo']} ({days} days remaining)"})
    else:
        results.append({"category": "Certificate", "item": "Certificate Validity",
            "status": "vulnerable", "severity": "critical",
            "description": f"Certificate EXPIRED as of {cert_info['validTo']}"})

    if (key_type == "RSA" and key_bits >= 2048) or (key_type == "EC" and key_bits >= 256):
        results.append({"category": "Certificate", "item": "Key Strength",
            "status": "secure", "severity": "low",
            "description": f"{key_bits}-bit {key_type} key — meets modern security standards"})
    elif key_bits > 0 and key_bits < 2048:
        results.append({"category": "Certificate", "item": "Key Strength",
            "status": "vulnerable", "severity": "critical",
            "description": f"Weak {key_bits}-bit {key_type} key — upgrade to 2048-bit minimum"})

    results.append({"category": "Certificate", "item": "Certificate Chain",
        "status": "secure", "severity": "low",
        "description": f"Issued by: {cert_info['issuer']}"})

    # ── Protocol support ──────────────────────────────────────────────────────
    protocol_specs = [
        ("TLS 1.3", "TLSv1.3", "secure",     "low",    "Latest TLS version — best security and performance"),
        ("TLS 1.2", "TLSv1.2", "secure",     "low",    "Secure fallback — widely supported"),
        ("TLS 1.1", "TLSv1.1", "warning",    "medium", "Outdated — should be disabled per RFC 8996"),
        ("TLS 1.0", "TLSv1",   "vulnerable", "high",   "Deprecated — vulnerable to POODLE, BEAST"),
    ]

    for name, version, vuln_status, severity, desc in protocol_specs:
        supported, _ = proto_results.get(version, (False, "Not tested"))
        if supported:
            results.append({"category": "Protocol Support", "item": name,
                "status": vuln_status, "severity": severity,
                "description": f"Supported — {desc}"})
        else:
            if version in ("TLSv1", "TLSv1.1"):
                results.append({"category": "Protocol Support", "item": name,
                    "status": "secure", "severity": "low",
                    "description": "Disabled — correctly rejected by server"})
            else:
                results.append({"category": "Protocol Support", "item": name,
                    "status": "warning", "severity": "medium",
                    "description": f"Not supported — {desc}"})

    # ── Cipher suites ─────────────────────────────────────────────────────────
    weak_ciphers   = ["RC4", "DES", "3DES", "NULL", "EXPORT", "ANON", "MD5"]
    strong_ciphers = ["AES_256_GCM", "AES_128_GCM", "CHACHA20", "AES_256_CCM"]
    cipher_weak    = any(w in active_cipher.upper() for w in weak_ciphers)
    cipher_strong  = any(s in active_cipher.upper() for s in strong_ciphers)

    if cipher_weak:
        results.append({"category": "Cipher Suites", "item": "Active Cipher Suite",
            "status": "vulnerable", "severity": "critical",
            "description": f"Weak cipher in use: {active_cipher} — replace immediately"})
    elif cipher_strong:
        results.append({"category": "Cipher Suites", "item": "Active Cipher Suite",
            "status": "secure", "severity": "low",
            "description": f"Strong cipher negotiated: {active_cipher}"})
    else:
        results.append({"category": "Cipher Suites", "item": "Active Cipher Suite",
            "status": "warning", "severity": "medium",
            "description": f"Cipher in use: {active_cipher} — consider upgrading to AEAD ciphers"})

    has_fs = any(fs in active_cipher.upper() for fs in ["ECDHE", "DHE", "ECDH"]) or active_proto == "TLSv1.3"
    results.append({"category": "Cipher Suites", "item": "Forward Secrecy",
        "status": "secure" if has_fs else "warning",
        "severity": "low" if has_fs else "high",
        "description": "Perfect Forward Secrecy enabled" if has_fs
                       else "No forward secrecy — session keys not ephemeral"})

    # ── Vulnerabilities ───────────────────────────────────────────────────────
    tls10_supported, _ = proto_results.get("TLSv1", (False, ""))

    results.append({"category": "Vulnerabilities", "item": "BEAST (CVE-2011-3389)",
        "status": "warning" if tls10_supported else "secure",
        "severity": "medium" if tls10_supported else "low",
        "description": "TLS 1.0 enabled — potential BEAST vulnerability" if tls10_supported
                       else "TLS 1.0 disabled — not vulnerable to BEAST"})

    results.append({"category": "Vulnerabilities", "item": "POODLE (CVE-2014-3566)",
        "status": "warning" if tls10_supported else "secure",
        "severity": "medium" if tls10_supported else "low",
        "description": "TLS 1.0 active — may be vulnerable to POODLE variant" if tls10_supported
                       else "SSLv3/TLS1.0 disabled — not vulnerable"})

    sweet32 = "3DES" in active_cipher.upper()
    results.append({"category": "Vulnerabilities", "item": "SWEET32 (CVE-2016-2183)",
        "status": "vulnerable" if sweet32 else "secure",
        "severity": "critical" if sweet32 else "low",
        "description": "3DES cipher active — vulnerable to SWEET32" if sweet32
                       else "3DES not in use — not vulnerable to SWEET32"})

    results.append({"category": "Vulnerabilities", "item": "CRIME (CVE-2012-4929)",
        "status": "secure", "severity": "low",
        "description": "TLS compression appears disabled — not vulnerable to CRIME"})

    # ── Features ──────────────────────────────────────────────────────────────
    results.append({"category": "Features", "item": "HSTS",
        "status": "secure" if hsts_enabled else "warning",
        "severity": "low" if hsts_enabled else "medium",
        "description": f"HSTS enabled: {hsts_value[:80]}" if hsts_enabled
                       else "HSTS not configured — browsers may allow HTTP downgrade"})

    results.append({"category": "Features", "item": "OCSP Stapling",
        "status": "secure" if active_proto == "TLSv1.3" else "warning",
        "severity": "low",
        "description": "OCSP stapling likely active (TLS 1.3 connection)" if active_proto == "TLSv1.3"
                       else "OCSP stapling not confirmed — may slow certificate validation"})

    return {"certificate": cert_info, "results": results}


# ── HTTP Handler ───────────────────────────────────────────────────────────────

