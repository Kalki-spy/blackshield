#!/usr/bin/env python3
"""
ctf.py — real CTF challenges with server-side flag verification.

Flags are never sent to the frontend or stored in plaintext — only a
SHA-256 hash is kept, and submissions are checked against that hash.
Each challenge here is genuinely solvable from its own asset (no
fabricated "solve counts" — solved_count is a real COUNT() over actual
recorded solves).
"""

import os
import sqlite3
import hashlib
import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "blackshield.db")


def _hash(flag: str) -> str:
    return hashlib.sha256(flag.strip().encode()).hexdigest()


# Real, solvable challenges — see backend/generate_ctf_assets.py for how
# the associated files under /public/ctf/ were produced and verified.
CHALLENGES = [
    {
        "slug": "view-source",
        "title": "View Source",
        "category": "Web Basics",
        "difficulty": "Easy",
        "points": 100,
        "description": "A staging page was left online by mistake. Sometimes the interesting part of a page isn't what's rendered.",
        "asset_url": "/ctf/portal.html",
        "hint": "Right-click → View Page Source (or Ctrl+U).",
        "flag_hash": _hash("blackshield{h1dd3n_1n_html}"),
    },
    {
        "slug": "signal-in-the-noise",
        "title": "Signal in the Noise",
        "category": "Cryptography",
        "difficulty": "Easy",
        "points": 100,
        "description": "Intercepted transmission: `oynpxfuvryq{p4rf4e_f4y4q}` — looks scrambled, but the scrambling is one of the oldest tricks in the book.",
        "asset_url": None,
        "hint": "It's a simple letter-substitution cipher with a shift of 13.",
        "flag_hash": _hash("blackshield{c4es4r_s4l4d}"),
    },
    {
        "slug": "hidden-in-plain-sight",
        "title": "Hidden in Plain Sight",
        "category": "Steganography",
        "difficulty": "Medium",
        "points": 250,
        "description": "This image looks like random noise, but it isn't. Something is encoded in the pixel data itself.",
        "asset_url": "/ctf/hidden-in-plain-sight.png",
        "hint": "The flag's ASCII bytes are stored one bit at a time in the least significant bit of each pixel's red channel, MSB-first, null-terminated.",
        "flag_hash": _hash("blackshield{pix3ls_d0nt_l13}"),
    },
    {
        "slug": "needle-in-the-log",
        "title": "Needle in the Log",
        "category": "Forensics",
        "difficulty": "Medium",
        "points": 200,
        "description": "180 lines of ordinary access logs from an internal test server. One request doesn't belong.",
        "asset_url": "/ctf/access.log",
        "hint": "Look for a request from an IP outside the usual 10.0.x.x range, and check what its query parameter decodes to.",
        "flag_hash": _hash("blackshield{gr3p_1s_y0ur_fr13nd}"),
    },
]


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
            CREATE TABLE IF NOT EXISTS ctf_challenges (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                slug TEXT UNIQUE NOT NULL,
                title TEXT NOT NULL,
                category TEXT NOT NULL,
                difficulty TEXT NOT NULL,
                points INTEGER NOT NULL,
                description TEXT NOT NULL,
                asset_url TEXT,
                hint TEXT,
                flag_hash TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS ctf_solves (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                challenge_id INTEGER NOT NULL,
                solved_at TEXT NOT NULL,
                UNIQUE(user_id, challenge_id),
                FOREIGN KEY (challenge_id) REFERENCES ctf_challenges(id)
            );
            """
        )
        conn.commit()

        for c in CHALLENGES:
            conn.execute(
                """
                INSERT INTO ctf_challenges (slug, title, category, difficulty, points, description, asset_url, hint, flag_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(slug) DO UPDATE SET
                    title=excluded.title, category=excluded.category, difficulty=excluded.difficulty,
                    points=excluded.points, description=excluded.description, asset_url=excluded.asset_url,
                    hint=excluded.hint, flag_hash=excluded.flag_hash
                """,
                (c["slug"], c["title"], c["category"], c["difficulty"], c["points"],
                 c["description"], c["asset_url"], c["hint"], c["flag_hash"]),
            )
        conn.commit()
    finally:
        conn.close()


def list_challenges(user_id):
    init_db()
    conn = _connect()
    try:
        rows = conn.execute(
            """
            SELECT c.id, c.slug, c.title, c.category, c.difficulty, c.points, c.description,
                   c.asset_url, c.hint,
                   EXISTS(SELECT 1 FROM ctf_solves s WHERE s.challenge_id = c.id AND s.user_id = ?) AS solved,
                   (SELECT COUNT(*) FROM ctf_solves s2 WHERE s2.challenge_id = c.id) AS solve_count
            FROM ctf_challenges c
            ORDER BY c.points ASC
            """,
            (user_id,),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def submit_flag(user_id, slug, flag):
    init_db()
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT id, points, flag_hash FROM ctf_challenges WHERE slug = ?", (slug,)
        ).fetchone()
        if row is None:
            return {"error": "unknown challenge"}, 404

        already = conn.execute(
            "SELECT 1 FROM ctf_solves WHERE user_id = ? AND challenge_id = ?",
            (user_id, row["id"]),
        ).fetchone()
        if already:
            return {"correct": True, "already_solved": True, "points": 0}, 200

        if _hash(flag) != row["flag_hash"]:
            return {"correct": False, "already_solved": False, "points": 0}, 200

        conn.execute(
            "INSERT INTO ctf_solves (user_id, challenge_id, solved_at) VALUES (?, ?, ?)",
            (user_id, row["id"], datetime.datetime.utcnow().isoformat() + "Z"),
        )
        conn.commit()
        return {"correct": True, "already_solved": False, "points": row["points"]}, 200
    finally:
        conn.close()
