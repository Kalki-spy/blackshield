#!/usr/bin/env python3
"""
activity_log.py — shared scan/finding/activity history for the dashboard.

Every tool server (nmap_server.py, sqlmap_server.py, etc.) can import this
module to record real, persisted history instead of the dashboard showing
fabricated data. Uses the same SQLite file as auth_server.py
(blackshield.db) so the whole app has one source of truth.

Usage from a tool server:

    import activity_log as log

    scan_id = log.start_scan(user_id, "Nmap", target)
    ...
    log.add_finding(user_id, "Nmap", target, "Telnet exposed on port 23",
                     severity="high", scan_id=scan_id)
    log.finish_scan(scan_id, status="completed")

If user_id is None (caller didn't identify a user), rows are still stored
so the tool's own history isn't lost, but they won't show up in any
specific user's dashboard query.
"""

import os
import sqlite3
import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "blackshield.db")

VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
VALID_STATUSES = {"running", "completed", "failed"}


def _connect():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = _connect()
    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                tool TEXT NOT NULL,
                target TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'running',
                started_at TEXT NOT NULL,
                finished_at TEXT
            );

            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                user_id INTEGER,
                tool TEXT NOT NULL,
                target TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );

            CREATE TABLE IF NOT EXISTS activity_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                tool TEXT,
                message TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_scans_user ON scans(user_id, started_at);
            CREATE INDEX IF NOT EXISTS idx_findings_user ON findings(user_id, created_at);
            CREATE INDEX IF NOT EXISTS idx_activity_user ON activity_log(user_id, created_at);
            """
        )
        conn.commit()
    finally:
        conn.close()


def _now():
    return datetime.datetime.utcnow().isoformat() + "Z"


def start_scan(user_id, tool, target):
    init_db()
    conn = _connect()
    try:
        cur = conn.execute(
            "INSERT INTO scans (user_id, tool, target, status, started_at) VALUES (?, ?, ?, 'running', ?)",
            (user_id, tool, target, _now()),
        )
        conn.commit()
        scan_id = cur.lastrowid
        log(user_id, tool, f"Started {tool} scan on {target}")
        return scan_id
    finally:
        conn.close()


def finish_scan(scan_id, status="completed", tool=None, target=None, user_id=None):
    if status not in VALID_STATUSES:
        status = "completed"
    init_db()
    conn = _connect()
    try:
        conn.execute(
            "UPDATE scans SET status = ?, finished_at = ? WHERE id = ?",
            (status, _now(), scan_id),
        )
        conn.commit()
        if tool and target:
            log(user_id, tool, f"{tool} scan on {target} {status}")
    finally:
        conn.close()


def add_finding(user_id, tool, target, title, severity="info", scan_id=None):
    severity = severity.lower()
    if severity not in VALID_SEVERITIES:
        severity = "info"
    init_db()
    conn = _connect()
    try:
        conn.execute(
            "INSERT INTO findings (scan_id, user_id, tool, target, title, severity, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (scan_id, user_id, tool, target, title, severity, _now()),
        )
        conn.commit()
    finally:
        conn.close()


def log(user_id, tool, message):
    init_db()
    conn = _connect()
    try:
        conn.execute(
            "INSERT INTO activity_log (user_id, tool, message, created_at) VALUES (?, ?, ?, ?)",
            (user_id, tool, message, _now()),
        )
        conn.commit()
    finally:
        conn.close()


def get_active_scans(user_id, limit=10):
    init_db()
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT id, tool, target, status, started_at FROM scans "
            "WHERE user_id = ? AND status = 'running' ORDER BY started_at DESC LIMIT ?",
            (user_id, limit),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_recent_findings(user_id, limit=10):
    init_db()
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT id, tool, target, title, severity, created_at FROM findings "
            "WHERE user_id = ? ORDER BY created_at DESC LIMIT ?",
            (user_id, limit),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_recent_activity(user_id, limit=15):
    init_db()
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT id, tool, message, created_at FROM activity_log "
            "WHERE user_id = ? ORDER BY created_at DESC LIMIT ?",
            (user_id, limit),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_severity_counts(user_id):
    init_db()
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT severity, COUNT(*) as count FROM findings WHERE user_id = ? GROUP BY severity",
            (user_id,),
        ).fetchall()
        counts = {s: 0 for s in VALID_SEVERITIES}
        for r in rows:
            counts[r["severity"]] = r["count"]
        return counts
    finally:
        conn.close()
