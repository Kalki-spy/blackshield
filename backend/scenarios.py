#!/usr/bin/env python3
"""
scenarios.py — guided multi-tool exercises whose progress is derived
entirely from real completed scans in activity_log's `scans` table.
No separate progress table, so there's nothing to fabricate: a step is
"done" only if that user has an actual completed scan logged for that
tool. As more tools get wired into activity_log (see nmap_server.py for
the pattern), more steps become completable for real.
"""

import os
import sqlite3

DB_PATH = os.path.join(os.path.dirname(__file__), "blackshield.db")

SCENARIOS = [
    {
        "id": "exposed-network-services",
        "title": "Exposed Network Services",
        "difficulty": "Beginner",
        "est_minutes": 45,
        "description": "Discover live hosts on a segment, identify misconfigured services, and confirm exposure with a targeted scan.",
        "steps": [
            {"label": "Map the network", "tool": "Network Analyzer", "route": "tools/network-analyzer"},
            {"label": "Identify open ports", "tool": "Port Scanner", "route": "tools/port-scanner"},
            {"label": "Fingerprint services", "tool": "Nmap", "route": "tools/nmap"},
        ],
    },
    {
        "id": "web-application-assessment",
        "title": "Web Application Assessment",
        "difficulty": "Intermediate",
        "est_minutes": 90,
        "description": "Enumerate a web application, identify an injectable endpoint, and confirm exploitability.",
        "steps": [
            {"label": "Enumerate directories", "tool": "Directory Scanner", "route": "tools/directory-scanner"},
            {"label": "Test for SQL injection", "tool": "SQL Injection Scanner", "route": "tools/sqli-scanner"},
        ],
    },
    {
        "id": "credential-compromise-chain",
        "title": "Credential Compromise Chain",
        "difficulty": "Advanced",
        "est_minutes": 180,
        "description": "Simulate a full attack chain from credential discovery through exploitation, using multiple tools in sequence.",
        "steps": [
            {"label": "Crack recovered hashes", "tool": "Hashcat", "route": "tools/hashcat"},
            {"label": "Exploit the target", "tool": "Metasploit", "route": "tools/metasploit"},
            {"label": "Audit password policy", "tool": "Password Auditor", "route": "tools/password-auditor"},
        ],
    },
]


def _connect():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute("PRAGMA busy_timeout=5000")
    conn.row_factory = sqlite3.Row
    return conn


def _has_completed_scan(conn, user_id, tool):
    row = conn.execute(
        "SELECT 1 FROM scans WHERE user_id = ? AND tool = ? AND status = 'completed' LIMIT 1",
        (user_id, tool),
    ).fetchone()
    return row is not None


def list_scenarios_with_progress(user_id):
    conn = _connect()
    try:
        # scans table may not exist yet if no tool has ever logged anything
        table_exists = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='scans'"
        ).fetchone()

        result = []
        for scenario in SCENARIOS:
            steps = []
            for step in scenario["steps"]:
                done = table_exists and _has_completed_scan(conn, user_id, step["tool"])
                steps.append({**step, "done": bool(done)})
            completed_count = sum(1 for s in steps if s["done"])
            total = len(steps)
            status = "completed" if completed_count == total else "in_progress" if completed_count > 0 else "not_started"
            next_step = next((s for s in steps if not s["done"]), steps[-1])
            result.append({
                **{k: v for k, v in scenario.items() if k != "steps"},
                "steps": steps,
                "completed_steps": completed_count,
                "total_steps": total,
                "status": status,
                "next_route": next_step["route"],
            })
        return result
    finally:
        conn.close()
