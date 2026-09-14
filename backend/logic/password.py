#!/usr/bin/env python3
"""
Password Auditor Backend — port 8778
Endpoints:
  GET  /health
  POST /password/analyze   {password}
  POST /password/bulk      {passwords: [...]}
  GET  /password/wordlist  ?query=...
"""
import json, re, math, hashlib, datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

import os
PORT = int(os.environ.get("PORT", 8778))

COMMON_PASSWORDS = {
    "password","123456","password123","admin","letmein","welcome","monkey",
    "dragon","master","123456789","qwerty","abc123","iloveyou","1234567",
    "sunshine","princess","football","shadow","superman","michael",
    "password1","123123","654321","pass","test","user","login","root",
    "toor","administrator","changeme","default","guest","secret",
    "passw0rd","p@ssw0rd","p@ssword","admin123","welcome1","hello",
}

KEYBOARD_PATTERNS = ["qwerty","asdf","zxcv","qazwsx","1qaz","2wsx",
                     "1234","abcd","aaaa","0000","1111","2222"]

def _cors(h):
    h.send_header("Access-Control-Allow-Origin", "*")
    h.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
    h.send_header("Access-Control-Allow-Headers", "Content-Type, Accept, Authorization")
    h.send_header("Access-Control-Max-Age", "86400")


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

def entropy(pwd):
    charset = 0
    if re.search(r"[a-z]", pwd): charset += 26
    if re.search(r"[A-Z]", pwd): charset += 26
    if re.search(r"[0-9]", pwd): charset += 10
    if re.search(r"[^a-zA-Z0-9]", pwd): charset += 32
    return round(len(pwd) * math.log2(charset), 1) if charset else 0

def crack_time(ent):
    guesses = 2 ** ent
    rate    = 1e10  # 10B guesses/sec (GPU)
    secs    = guesses / rate
    if secs < 1:       return "Instant"
    if secs < 60:      return f"{int(secs)} seconds"
    if secs < 3600:    return f"{int(secs/60)} minutes"
    if secs < 86400:   return f"{int(secs/3600)} hours"
    if secs < 2592000: return f"{int(secs/86400)} days"
    if secs < 31536000:return f"{int(secs/2592000)} months"
    if secs < 1e9:     return f"{int(secs/31536000)} years"
    return "Centuries"

def analyze_password(pwd):
    if not pwd:
        return {"error":"No password provided"}

    findings = []
    score = 0

    # Length
    ln = len(pwd)
    if ln < 8:
        findings.append({"check":"Length","status":"fail","severity":"critical","detail":f"Only {ln} chars — minimum 8 required"})
    elif ln < 12:
        findings.append({"check":"Length","status":"warn","severity":"medium","detail":f"{ln} chars — 12+ recommended"})
        score += 1
    elif ln < 16:
        findings.append({"check":"Length","status":"pass","severity":"low","detail":f"{ln} chars — good length"})
        score += 2
    else:
        findings.append({"check":"Length","status":"pass","severity":"low","detail":f"{ln} chars — excellent length"})
        score += 3

    # Character classes
    has_lower  = bool(re.search(r"[a-z]", pwd))
    has_upper  = bool(re.search(r"[A-Z]", pwd))
    has_digit  = bool(re.search(r"[0-9]", pwd))
    has_symbol = bool(re.search(r"[^a-zA-Z0-9]", pwd))
    classes = sum([has_lower, has_upper, has_digit, has_symbol])
    if classes < 2:
        findings.append({"check":"Character Variety","status":"fail","severity":"high","detail":"Uses only 1 character class — add uppercase, numbers, symbols"})
    elif classes == 2:
        findings.append({"check":"Character Variety","status":"warn","severity":"medium","detail":"2 character classes — add more variety"})
        score += 1
    elif classes == 3:
        findings.append({"check":"Character Variety","status":"pass","severity":"low","detail":"3 character classes — good"})
        score += 2
    else:
        findings.append({"check":"Character Variety","status":"pass","severity":"low","detail":"All 4 character classes — excellent"})
        score += 3

    # Common passwords
    if pwd.lower() in COMMON_PASSWORDS:
        findings.append({"check":"Common Password","status":"fail","severity":"critical","detail":"Found in common password lists — change immediately"})
        score = 0
    else:
        findings.append({"check":"Common Password","status":"pass","severity":"low","detail":"Not found in common password blacklist"})
        score += 1

    # Keyboard patterns
    lower_pwd = pwd.lower()
    pattern_found = next((p for p in KEYBOARD_PATTERNS if p in lower_pwd), None)
    if pattern_found:
        findings.append({"check":"Keyboard Pattern","status":"fail","severity":"high","detail":f"Contains keyboard pattern '{pattern_found}' — easily guessed"})
    else:
        findings.append({"check":"Keyboard Pattern","status":"pass","severity":"low","detail":"No keyboard walk patterns detected"})
        score += 1

    # Repeated chars
    if re.search(r"(.)\1{2,}", pwd):
        findings.append({"check":"Repeated Characters","status":"warn","severity":"medium","detail":"Contains 3+ repeated characters in a row"})
    else:
        findings.append({"check":"Repeated Characters","status":"pass","severity":"low","detail":"No excessive character repetition"})
        score += 1

    # Numbers only at end
    if re.search(r"^[a-zA-Z]+\d{1,3}$", pwd):
        findings.append({"check":"Predictable Structure","status":"warn","severity":"medium","detail":"Word + numbers at end — common substitution pattern"})
    else:
        findings.append({"check":"Predictable Structure","status":"pass","severity":"low","detail":"No predictable word+number structure"})
        score += 1

    ent = entropy(pwd)
    ct  = crack_time(ent)

    max_score = 12
    pct = round((score / max_score) * 100)
    if pct >= 85:   strength = "Very Strong"
    elif pct >= 65: strength = "Strong"
    elif pct >= 45: strength = "Moderate"
    elif pct >= 25: strength = "Weak"
    else:           strength = "Very Weak"

    sha1 = hashlib.sha1(pwd.encode()).hexdigest().upper()
    md5  = hashlib.md5(pwd.encode()).hexdigest()

    return {
        "length": ln,
        "entropy": ent,
        "crack_time": ct,
        "strength": strength,
        "score": score,
        "score_pct": pct,
        "char_classes": {"lower":has_lower,"upper":has_upper,"digit":has_digit,"symbol":has_symbol},
        "findings": findings,
        "hash_sha1_prefix": sha1[:5],
        "hash_md5": md5,
        "suggestions": _suggestions(findings, pwd),
    }

def _suggestions(findings, pwd):
    sug = []
    for f in findings:
        if f["status"] in ("fail","warn"):
            if f["check"] == "Length": sug.append(f"Increase length to at least {max(16, len(pwd)+4)} characters")
            elif f["check"] == "Character Variety": sug.append("Mix uppercase, lowercase, numbers and symbols")
            elif f["check"] == "Common Password": sug.append("Use a passphrase or password manager to generate unique passwords")
            elif f["check"] == "Keyboard Pattern": sug.append("Avoid sequences like 'qwerty', 'asdf', '1234'")
            elif f["check"] == "Repeated Characters": sug.append("Avoid repeating the same character consecutively")
            elif f["check"] == "Predictable Structure": sug.append("Don't just append numbers to words — intersperse them")
    if not sug: sug.append("Password looks strong — consider using a password manager to store it safely")
    return sug

