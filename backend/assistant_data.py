#!/usr/bin/env python3
"""
assistant_data.py — real persistence backing the AI Assistant screen:
conversation history (so "Recent conversations" is real, not decorative)
and a minimal reports feature (so "Add to report" actually saves
something, and a report can be viewed later).
"""

import os
import sqlite3
import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "blackshield.db")


def _connect():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.row_factory = sqlite3.Row
    return conn


def _now():
    return datetime.datetime.utcnow().isoformat() + "Z"


def init_db():
    conn = _connect()
    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS conversations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                conversation_id INTEGER NOT NULL,
                role TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (conversation_id) REFERENCES conversations(id)
            );

            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS report_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_id INTEGER NOT NULL,
                content TEXT NOT NULL,
                source TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (report_id) REFERENCES reports(id)
            );

            CREATE INDEX IF NOT EXISTS idx_conv_user ON conversations(user_id, updated_at);
            CREATE INDEX IF NOT EXISTS idx_msg_conv ON messages(conversation_id, created_at);
            CREATE INDEX IF NOT EXISTS idx_reports_user ON reports(user_id, created_at);
            CREATE INDEX IF NOT EXISTS idx_report_items ON report_items(report_id, created_at);
            """
        )
        conn.commit()
    finally:
        conn.close()


# ---- Conversations ----

def create_conversation(user_id, title):
    init_db()
    conn = _connect()
    try:
        now = _now()
        cur = conn.execute(
            "INSERT INTO conversations (user_id, title, created_at, updated_at) VALUES (?, ?, ?, ?)",
            (user_id, title[:80], now, now),
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def add_message(conversation_id, role, content):
    init_db()
    conn = _connect()
    try:
        conn.execute(
            "INSERT INTO messages (conversation_id, role, content, created_at) VALUES (?, ?, ?, ?)",
            (conversation_id, role, content, _now()),
        )
        conn.execute(
            "UPDATE conversations SET updated_at = ? WHERE id = ?",
            (_now(), conversation_id),
        )
        conn.commit()
    finally:
        conn.close()


def list_conversations(user_id, limit=15):
    init_db()
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT id, title, updated_at FROM conversations WHERE user_id = ? ORDER BY updated_at DESC LIMIT ?",
            (user_id, limit),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_messages(conversation_id, user_id):
    init_db()
    conn = _connect()
    try:
        owner = conn.execute(
            "SELECT id FROM conversations WHERE id = ? AND user_id = ?", (conversation_id, user_id)
        ).fetchone()
        if not owner:
            return None
        rows = conn.execute(
            "SELECT role, content, created_at FROM messages WHERE conversation_id = ? ORDER BY created_at ASC",
            (conversation_id,),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


# ---- Reports ----

def list_reports(user_id):
    init_db()
    conn = _connect()
    try:
        rows = conn.execute(
            """
            SELECT r.id, r.title, r.created_at, COUNT(i.id) AS item_count
            FROM reports r LEFT JOIN report_items i ON i.report_id = r.id
            WHERE r.user_id = ? GROUP BY r.id ORDER BY r.created_at DESC
            """,
            (user_id,),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def create_report(user_id, title):
    init_db()
    conn = _connect()
    try:
        cur = conn.execute(
            "INSERT INTO reports (user_id, title, created_at) VALUES (?, ?, ?)",
            (user_id, title[:120], _now()),
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def add_report_item(report_id, content, source=None):
    init_db()
    conn = _connect()
    try:
        conn.execute(
            "INSERT INTO report_items (report_id, content, source, created_at) VALUES (?, ?, ?, ?)",
            (report_id, content, source, _now()),
        )
        conn.commit()
    finally:
        conn.close()


def get_report(report_id, user_id):
    init_db()
    conn = _connect()
    try:
        report = conn.execute(
            "SELECT id, title, created_at FROM reports WHERE id = ? AND user_id = ?",
            (report_id, user_id),
        ).fetchone()
        if not report:
            return None
        items = conn.execute(
            "SELECT id, content, source, created_at FROM report_items WHERE report_id = ? ORDER BY created_at ASC",
            (report_id,),
        ).fetchall()
        result = dict(report)
        result["items"] = [dict(i) for i in items]
        return result
    finally:
        conn.close()
