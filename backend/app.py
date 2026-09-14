from flask import Flask, request, jsonify
from flask_cors import CORS
import os

# Loads backend/.env for local development. On Render/Vercel, real
# environment variables set in the dashboard take precedence — this is a
# convenience for running `python3 app.py` on your own machine.
from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__)

CORS(
    app,
    origins=[
        "https://black-shield-icfy.vercel.app",
        "http://localhost:5173",
        "http://localhost:8080"
    ],
    supports_credentials=True
)

# ---------- Health ----------

@app.get("/")
def home():
    return {
        "service": "BlackShield Backend",
        "status": "running"
    }

@app.get("/health")
def health():
    return {"status": "ok"}

# ---------- Auth ----------

from auth_server import (
    signup,
    login,
    logout,
    get_me,
    init_db
)

init_db()

@app.post("/api/auth/signup")
def auth_signup():
    data = request.json or {}
    status, body = signup(
        data.get("username",""),
        data.get("email",""),
        data.get("password","")
    )
    return jsonify(body), status

@app.post("/api/auth/login")
def auth_login():
    data = request.json or {}
    status, body = login(
        data.get("email",""),
        data.get("password","")
    )
    return jsonify(body), status

@app.post("/api/auth/logout")
def auth_logout():
    token = request.headers.get("Authorization","").replace("Bearer ","")
    status, body = logout(token)
    return jsonify(body), status

@app.get("/api/auth/me")
def auth_me():
    token = request.headers.get("Authorization","").replace("Bearer ","")
    status, body = get_me(token)
    return jsonify(body), status

# ---------- Chat ----------
# Originally called a local Ollama instance (localhost:11434), which can't
# run on Render. Switched to Groq — hosted, free-tier, serves open-source
# models (Llama 3.3, Mixtral, Gemma). Needs GROQ_API_KEY set as an
# environment variable on Render (Dashboard -> your service -> Environment).
# Get a free key at https://console.groq.com/keys

from groq import Groq

GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
GROQ_MODEL   = "llama-3.3-70b-versatile"
groq_client  = Groq(api_key=GROQ_API_KEY) if GROQ_API_KEY else None

CHAT_SYSTEM_PROMPT = """You are CyberBot, an elite cybersecurity AI assistant for BlackShield — a professional cybersecurity analysis and penetration testing platform.

Your expertise covers:
- SSL/TLS certificate analysis and vulnerabilities
- Network scanning, port analysis, and service fingerprinting
- SQL injection detection and web application security
- Password cracking, hash analysis, and cryptography
- CVE vulnerabilities, CVSS scoring, and patch management
- DDoS attack types, detection, and mitigation
- Directory brute-forcing and web enumeration
- Subdomain discovery and DNS analysis
- Red team offensive techniques and Blue team defence
- CTF challenges and penetration testing methodology
- OWASP Top 10, MITRE ATT&CK framework

Rules:
- Be direct and technical — no filler phrases
- Use bullet points and code blocks for clarity
- Bold important terms and CVE IDs
- Answer cybersecurity questions thoroughly
- For BlackShield tool questions, explain how to use them effectively"""

@app.get("/api/health")
def api_health():
    return {"status": "ok", "ready": bool(GROQ_API_KEY)}

@app.route("/api/chat", methods=["POST"])
def chat():
    if not groq_client:
        return jsonify({
            "error": "Chat isn't configured. Set GROQ_API_KEY as an environment "
                     "variable on Render (free key at https://console.groq.com/keys), "
                     "then redeploy."
        }), 503

    data = request.json or {}
    messages = data.get("messages", [])
    if not messages:
        return jsonify({"error": "No messages provided"}), 400

    try:
        completion = groq_client.chat.completions.create(
            model=GROQ_MODEL,
            messages=[{"role": "system", "content": CHAT_SYSTEM_PROMPT}] + messages,
            temperature=0.7,
            max_tokens=800,
        )
        reply = completion.choices[0].message.content
        return jsonify({"reply": reply, "model": GROQ_MODEL, "provider": "groq"})
    except Exception as e:
        return jsonify({"error": f"Groq request failed: {e}"}), 502

# ---------- Tool logic (merged in-process — no more subprocess servers) ----------

import logic.ssl_analyzer as ssl_analyzer
import logic.subdomain    as subdomain
import logic.gobuster     as gobuster
import logic.sqlmap       as sqlmap
import logic.sniper       as sniper
import logic.cve          as cve
import logic.ddos         as ddos
import logic.firewall     as firewall
import logic.hashcat      as hashcat
import logic.ids          as ids
import logic.metasploit   as metasploit
import logic.network      as network
import logic.nmap         as nmap
import logic.password     as password
import logic.ssl_inspector as ssl_inspector


def _err(e: Exception, code: int = 500):
    return jsonify({"error": str(e)}), code


# ── SSL Analyzer ──────────────────────────────────────────────────────────────

@app.get("/api/sslanalyzer/analyze")
def sslanalyzer_analyze():
    url = request.args.get("url", "").strip()
    if not url:
        return jsonify({"error": "Missing required query parameter: url"}), 400
    try:
        return jsonify(ssl_analyzer.analyze_ssl(url))
    except Exception as e:
        return _err(e)


# ── Subdomain Finder ──────────────────────────────────────────────────────────

@app.get("/api/subdomain/find")
def subdomain_find():
    domain = request.args.get("domain", "").strip()
    if not domain:
        return jsonify({"error": "Missing required query parameter: domain"}), 400
    try:
        return jsonify(subdomain.find_subdomains(domain))
    except Exception as e:
        return _err(e)


# ── Gobuster ──────────────────────────────────────────────────────────────────

@app.get("/api/gobuster/scan")
def gobuster_scan():
    url     = request.args.get("url", "").strip()
    mode    = request.args.get("mode", "dir").strip().lower()
    ext_raw = request.args.get("ext", "php,html,txt,js,json").strip()
    threads = int(request.args.get("threads", "30"))

    if not url:
        return jsonify({"error": "Missing required parameter: url"}), 400
    if mode not in ("dir", "file", "both"):
        mode = "dir"
    extensions = [e.strip().lstrip(".") for e in ext_raw.split(",") if e.strip()]
    threads = max(1, min(threads, 50))

    try:
        return jsonify(gobuster.run_scan(url, mode=mode, extensions=extensions, max_workers=threads))
    except Exception as e:
        return _err(e)


# ── SQLMap ────────────────────────────────────────────────────────────────────

@app.get("/api/sqlmap/scan")
def sqlmap_scan():
    url       = request.args.get("url", "").strip()
    param_str = request.args.get("params", "").strip()
    level     = max(1, min(int(request.args.get("level", "2")), 3))

    if not url:
        return jsonify({"error": "Missing required parameter: url"}), 400
    param_names = [x.strip() for x in param_str.split(",") if x.strip()] or None

    try:
        return jsonify(sqlmap.run_scan(url, param_names=param_names, level=level))
    except Exception as e:
        return _err(e)


# ── Sniper ────────────────────────────────────────────────────────────────────

@app.get("/api/sniper/scan")
def sniper_scan():
    target    = request.args.get("target", "").strip()
    mode      = request.args.get("mode", "both").lower()
    intensity = max(1, min(int(request.args.get("intensity", "2")), 3))

    if not target:
        return jsonify({"error": "Missing parameter: target"}), 400
    if mode not in ("remote", "client", "both"):
        mode = "both"

    try:
        return jsonify(sniper.run_sniper(target, mode=mode, intensity=intensity))
    except Exception as e:
        return _err(e)


# ── CVE Scanner ───────────────────────────────────────────────────────────────

@app.post("/api/cve/scan")
def cve_scan():
    data = request.json or {}
    sw = data.get("software", "").strip()
    if not sw:
        return jsonify({"error": "Missing: software"}), 400
    return jsonify(cve.scan_software(sw, data.get("version", "").strip() or None))

@app.post("/api/cve/bulk")
def cve_bulk():
    data = request.json or {}
    targets = data.get("targets", [])[:20]
    results = [cve.scan_software(t.get("software", ""), t.get("version", "").strip() or None) for t in targets]
    return jsonify({
        "results": results,
        "total": len(results),
        "critical_count": sum(1 for r in results if r["risk"] == "critical"),
    })

@app.get("/api/cve/search")
def cve_search():
    q = request.args.get("q", "").strip()
    if not q:
        return jsonify({"error": "Missing query param: q"}), 400
    results = [e for e in cve.CVE_DB if q.lower() in e["software"] or q.upper() in e["cve"] or q.lower() in e["desc"].lower()]
    return jsonify({"query": q, "results": results, "count": len(results)})


# ── DDoS Simulator ────────────────────────────────────────────────────────────

@app.get("/api/ddos/live")
def ddos_live():
    return jsonify(ddos.get_live_snapshot())

@app.post("/api/ddos/simulate")
def ddos_simulate():
    attack_type = request.form.get("attack_type", "normal")
    try:
        duration = float(request.form.get("duration", 20))
        pps      = float(request.form.get("pps", 80))
    except ValueError:
        return jsonify({"error": "duration and pps must be numbers"}), 400
    duration = max(1, min(duration, 120))
    pps      = max(1, min(pps, 500))
    result = ddos.start_simulation(attack_type, duration, pps)
    if "error" in result:
        return jsonify(result), 409
    return jsonify(result)

@app.post("/api/ddos/stop")
def ddos_stop():
    return jsonify(ddos.stop_simulation())


# ── Firewall Tester ───────────────────────────────────────────────────────────

@app.post("/api/firewall/test")
def firewall_test():
    data = request.json or {}
    host = data.get("host", "").strip()
    if not host:
        return jsonify({"error": "Missing: host"}), 400
    raw_ports = data.get("ports", [])
    if isinstance(raw_ports, str):
        try:
            if "-" in raw_ports:
                lo, hi = map(int, raw_ports.split("-", 1))
                raw_ports = list(range(lo, min(hi + 1, lo + 200)))
            else:
                raw_ports = [int(p.strip()) for p in raw_ports.split(",") if p.strip()]
        except Exception:
            raw_ports = list(firewall.WELL_KNOWN.keys())
    if not raw_ports:
        raw_ports = list(firewall.WELL_KNOWN.keys())
    raw_ports = raw_ports[:200]
    return jsonify(firewall.test_firewall(host, raw_ports))

@app.post("/api/firewall/analyze")
def firewall_analyze():
    data = request.json or {}
    rules = data.get("rules", "")
    if not rules:
        return jsonify({"error": "Missing: rules"}), 400
    return jsonify(firewall.analyze_rules(rules))


# ── Hashcat ───────────────────────────────────────────────────────────────────

@app.post("/api/hashcat/crack")
def hashcat_crack():
    data = request.json or {}
    return jsonify(hashcat.crack_hash(
        hash_str=data.get("hash", ""),
        hash_type=data.get("hash_type", "auto"),
        mode=data.get("mode", "both"),
        custom_words=data.get("wordlist"),
    ))


# ── IDS / Malware Analyzer ────────────────────────────────────────────────────

@app.post("/api/ids/scan")
def ids_scan():
    data = request.json or {}
    target    = (data.get("target") or "").strip()
    scan_type = data.get("scan_type", "url")
    if not target:
        return jsonify({"error": "target is required"}), 400
    if scan_type == "url" and "://" not in target:
        target = "https://" + target
    try:
        if ids.VT_API_KEY and scan_type == "url":
            result = ids.vt_scan_url(target)
        else:
            result = ids.simulate_scan(target, scan_type)
        return jsonify(result)
    except Exception:
        try:
            return jsonify(ids.simulate_scan(target, scan_type))
        except Exception as e2:
            return _err(e2)


# ── Metasploit-style Vulnerability Scanner ────────────────────────────────────

@app.post("/api/metasploit/scan")
def metasploit_scan():
    data = request.json or {}
    target    = data.get("target", "").strip()
    scan_type = data.get("scan_type", "full")
    if not target:
        return jsonify({"error": "target is required"}), 400
    return jsonify(metasploit.scan_target(target, scan_type=scan_type))


# ── Network Analyzer + Port Scanner ───────────────────────────────────────────

@app.post("/api/network/analyze")
def network_analyze():
    data = request.json or {}
    host = data.get("host", "").strip()
    if not host:
        return jsonify({"error": "Missing required field: host"}), 400
    try:
        return jsonify(network.full_analyze(host))
    except Exception as e:
        return _err(e)

@app.post("/api/network/portscan")
def network_portscan():
    data = request.json or {}
    host = data.get("host", "").strip()
    if not host:
        return jsonify({"error": "Host required"}), 400
    ports_input = data.get("ports")
    try:
        if ports_input:
            if "-" in ports_input:
                start, end = map(int, ports_input.split("-"))
                ports = list(range(start, min(end + 1, start + 1000)))
            else:
                ports = [int(p.strip()) for p in ports_input.split(",") if p.strip()]
        else:
            ports = list(ddos.COMMON_PORTS.keys())
    except Exception:
        return jsonify({"error": "Invalid ports format"}), 400
    return jsonify({"host": host, "ports": ddos.scan_ports(host, ports)})


# ── Nmap-style Port Scanner ───────────────────────────────────────────────────

@app.post("/api/nmap/scan")
def nmap_scan():
    import socket as _socket
    data = request.json or {}
    target = data.get("target")
    ports  = data.get("ports", nmap.COMMON_PORTS)
    if not target:
        return jsonify({"error": "target is required"}), 400

    import time as _time
    start_time = _time.time()
    results = []
    open_ports = []
    for port in ports:
        res = nmap.scan_port(target, port)
        results.append(res)
        if res["state"] == "open":
            open_ports.append(port)
    scan_time = round(_time.time() - start_time, 2)

    try:
        ip = _socket.gethostbyname(target)
    except Exception as e:
        return jsonify({"error": f"Cannot resolve {target}: {e}"}), 400

    return jsonify({
        "target": target,
        "ip": ip,
        "rdns": "",
        "scan_type": "custom",
        "ports_scanned": len(ports),
        "open_ports": len(open_ports),
        "closed_ports": len([p for p in results if p["state"] == "closed"]),
        "filtered_ports": 0,
        "scan_time": scan_time,
        "avg_latency": int(sum(p["latency"] for p in results) / max(1, len(results))),
        "ports": results,
        "os_info": {
            "os": nmap.detect_os(open_ports),
            "confidence": 60,
            "candidates": {},
            "method": "heuristic port analysis",
        },
        "http_info": nmap.http_analysis(target),
        "host_up": True,
    })


# ── Password Auditor ──────────────────────────────────────────────────────────

@app.post("/api/password/analyze")
def password_analyze():
    data = request.json or {}
    return jsonify(password.analyze_password(data.get("password", "")))

@app.post("/api/password/bulk")
def password_bulk():
    data = request.json or {}
    pwds = data.get("passwords", [])[:50]
    results = [{"password": p, **password.analyze_password(p)} for p in pwds]
    return jsonify({
        "results": results,
        "total": len(results),
        "weak":   sum(1 for r in results if r.get("score_pct", 0) < 45),
        "strong": sum(1 for r in results if r.get("score_pct", 0) >= 65),
    })


# ── SSL Inspector ─────────────────────────────────────────────────────────────

@app.post("/api/ssl/inspect")
def ssl_inspect():
    data = request.json or {}
    host = data.get("host", "").strip()
    if not host:
        return jsonify({"error": "Missing field: host"}), 400
    port = int(data.get("port", 443))
    return jsonify(ssl_inspector.inspect_ssl(host, port))


if __name__=="__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.getenv("PORT",10000))
    )
