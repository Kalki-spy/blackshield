#!/usr/bin/env python3
"""
BlackShield Auth Server — SQLite-backed login & signup
Endpoints:
    POST /auth/signup    { username, email, password }
    POST /auth/login     { email, password }
    POST /auth/logout
    GET  /auth/me        (requires Authorization: Bearer <token>)
    GET  /auth/health
"""

import sqlite3
import hashlib
import re
import secrets
import json
import os
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

PORT = int(os.environ.get("PORT",8766))
DB_PATH = os.path.join(os.path.dirname(__file__), "blackshield.db")


# ── Database ──────────────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                username  TEXT    NOT NULL,
                email     TEXT    NOT NULL UNIQUE,
                password  TEXT    NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                token      TEXT    PRIMARY KEY,
                user_id    INTEGER NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        # Safe migrations for columns added after initial release —
        # SQLite has no "ADD COLUMN IF NOT EXISTS", so ignore the
        # duplicate-column error on databases that already have them.
        for stmt in [
            "ALTER TABLE users ADD COLUMN display_name TEXT",
            "ALTER TABLE users ADD COLUMN bio TEXT",
            "ALTER TABLE users ADD COLUMN timezone TEXT DEFAULT 'UTC'",
            "ALTER TABLE users ADD COLUMN notify_critical_findings INTEGER DEFAULT 1",
            "ALTER TABLE users ADD COLUMN notify_scan_completion INTEGER DEFAULT 1",
            "ALTER TABLE users ADD COLUMN default_landing_route TEXT DEFAULT '/dashboard'",
            "ALTER TABLE users ADD COLUMN session_timeout_minutes INTEGER DEFAULT 0",
            "ALTER TABLE sessions ADD COLUMN user_agent TEXT",
            "ALTER TABLE sessions ADD COLUMN ip TEXT",
        ]:
            try:
                conn.execute(stmt)
            except sqlite3.OperationalError:
                pass
        conn.commit()
    print(f"[Auth] Database ready at {DB_PATH}")


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def create_token() -> str:
    return secrets.token_hex(32)


# ── Auth Logic ────────────────────────────────────────────────────────────────

def signup(username: str, email: str, password: str, user_agent: str = "", ip: str = ""):
    if not username or not email or not password:
        return 400, {"error": "username, email, and password are required"}
    if len(username.strip()) < 3:
        return 400, {"error": "Username must be at least 3 characters"}
    if not re.match(r'^[^\s@]+@[^\s@]+\.[^\s@]{2,}$', email.strip()):
        return 400, {"error": "Enter a valid email address"}
    if len(password) < 6:
        return 400, {"error": "Password must be at least 6 characters"}
    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                (username.strip(), email.strip().lower(), hash_password(password))
            )
            conn.commit()
            user = conn.execute(
                "SELECT id, username, email FROM users WHERE email = ?",
                (email.strip().lower(),)
            ).fetchone()
            token = create_token()
            conn.execute(
                "INSERT INTO sessions (token, user_id, user_agent, ip) VALUES (?, ?, ?, ?)",
                (token, user["id"], user_agent, ip)
            )
            conn.commit()
        return 200, {
            "token": token,
            "user": {"id": user["id"], "username": user["username"], "email": user["email"]}
        }
    except sqlite3.IntegrityError:
        return 409, {"error": "Email already registered"}
    except Exception as e:
        return 500, {"error": str(e)}


def login(email: str, password: str, user_agent: str = "", ip: str = ""):
    if not email or not password:
        return 400, {"error": "email and password are required"}
    if not re.match(r'^[^\s@]+@[^\s@]+\.[^\s@]{2,}$', email.strip()):
        return 400, {"error": "Enter a valid email address"}
    try:
        with get_db() as conn:
            user = conn.execute(
                "SELECT id, username, email, password FROM users WHERE email = ?",
                (email.strip().lower(),)
            ).fetchone()
            if not user or user["password"] != hash_password(password):
                return 401, {"error": "Invalid email or password"}
            token = create_token()
            conn.execute(
                "INSERT INTO sessions (token, user_id, user_agent, ip) VALUES (?, ?, ?, ?)",
                (token, user["id"], user_agent, ip)
            )
            conn.commit()
        return 200, {
            "token": token,
            "user": {"id": user["id"], "username": user["username"], "email": user["email"]}
        }
    except Exception as e:
        return 500, {"error": str(e)}


def logout(token: str):
    try:
        with get_db() as conn:
            conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
            conn.commit()
        return 200, {"message": "Logged out"}
    except Exception as e:
        return 500, {"error": str(e)}


def get_me(token: str):
    if not token:
        return 401, {"error": "Not authenticated"}
    try:
        with get_db() as conn:
            row = conn.execute("""
                SELECT u.id, u.username, u.email, u.display_name, u.bio, u.created_at,
                       u.timezone, u.notify_critical_findings, u.notify_scan_completion,
                       u.default_landing_route, u.session_timeout_minutes,
                       s.created_at AS session_created_at
                FROM sessions s
                JOIN users u ON s.user_id = u.id
                WHERE s.token = ?
            """, (token,)).fetchone()
            if not row:
                return 401, {"error": "Invalid or expired session"}

            timeout = row["session_timeout_minutes"] or 0
            if timeout > 0:
                import datetime as _dt
                session_age = _dt.datetime.now() - _dt.datetime.strptime(row["session_created_at"], "%Y-%m-%d %H:%M:%S")
                if session_age.total_seconds() > timeout * 60:
                    conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
                    conn.commit()
                    return 401, {"error": "Session expired due to inactivity"}

        return 200, {"user": {
            "id": row["id"], "username": row["username"], "email": row["email"],
            "display_name": row["display_name"], "bio": row["bio"], "created_at": row["created_at"],
            "timezone": row["timezone"], "notify_critical_findings": bool(row["notify_critical_findings"]),
            "notify_scan_completion": bool(row["notify_scan_completion"]),
            "default_landing_route": row["default_landing_route"],
            "session_timeout_minutes": row["session_timeout_minutes"],
        }}
    except Exception as e:
        return 500, {"error": str(e)}


def update_profile(token: str, display_name: str, bio: str):
    if not token:
        return 401, {"error": "Not authenticated"}
    try:
        with get_db() as conn:
            session = conn.execute("SELECT user_id FROM sessions WHERE token = ?", (token,)).fetchone()
            if not session:
                return 401, {"error": "Invalid or expired session"}
            conn.execute(
                "UPDATE users SET display_name = ?, bio = ? WHERE id = ?",
                (display_name.strip()[:80] or None, bio.strip()[:280] or None, session["user_id"]),
            )
            conn.commit()
        return 200, {"ok": True}
    except Exception as e:
        return 500, {"error": str(e)}


def update_settings(token: str, fields: dict):
    if not token:
        return 401, {"error": "Not authenticated"}
    allowed = {
        "timezone": str,
        "notify_critical_findings": bool,
        "notify_scan_completion": bool,
        "default_landing_route": str,
        "session_timeout_minutes": int,
    }
    updates = {}
    for key, cast in allowed.items():
        if key in fields:
            try:
                updates[key] = int(cast(fields[key])) if cast is bool else cast(fields[key])
            except (TypeError, ValueError):
                continue
    if not updates:
        return 400, {"error": "No valid settings provided"}
    try:
        with get_db() as conn:
            session = conn.execute("SELECT user_id FROM sessions WHERE token = ?", (token,)).fetchone()
            if not session:
                return 401, {"error": "Invalid or expired session"}
            set_clause = ", ".join(f"{k} = ?" for k in updates)
            conn.execute(f"UPDATE users SET {set_clause} WHERE id = ?", (*updates.values(), session["user_id"]))
            conn.commit()
        return 200, {"ok": True}
    except Exception as e:
        return 500, {"error": str(e)}


def export_user_data(token: str):
    """Aggregate everything BlackShield actually knows about this user into
    one JSON payload — real data pulled live from the shared database, not a
    canned template."""
    if not token:
        return 401, {"error": "Not authenticated"}
    try:
        with get_db() as conn:
            session = conn.execute("SELECT user_id FROM sessions WHERE token = ?", (token,)).fetchone()
            if not session:
                return 401, {"error": "Invalid or expired session"}
            uid = session["user_id"]

            def table_exists(name):
                return conn.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
                ).fetchone() is not None

            def rows_for(table, extra_where=""):
                if not table_exists(table):
                    return []
                cur = conn.execute(f"SELECT * FROM {table} WHERE user_id = ? {extra_where}", (uid,))
                return [dict(r) for r in cur.fetchall()]

            user = conn.execute(
                "SELECT id, username, email, display_name, bio, created_at FROM users WHERE id = ?", (uid,)
            ).fetchone()

            export = {
                "user": dict(user) if user else None,
                "scans": rows_for("scans"),
                "findings": rows_for("findings"),
                "activity_log": rows_for("activity_log"),
                "ctf_solves": rows_for("ctf_solves"),
                "conversations": rows_for("conversations"),
                "reports": rows_for("reports"),
            }
        return 200, export
    except Exception as e:
        return 500, {"error": str(e)}


def change_password(token: str, current_password: str, new_password: str):
    if not token:
        return 401, {"error": "Not authenticated"}
    if len(new_password) < 6:
        return 400, {"error": "New password must be at least 6 characters"}
    try:
        with get_db() as conn:
            row = conn.execute("""
                SELECT u.id, u.password FROM sessions s JOIN users u ON s.user_id = u.id
                WHERE s.token = ?
            """, (token,)).fetchone()
            if not row:
                return 401, {"error": "Invalid or expired session"}
            if row["password"] != hash_password(current_password):
                return 401, {"error": "Current password is incorrect"}
            conn.execute("UPDATE users SET password = ? WHERE id = ?", (hash_password(new_password), row["id"]))
            conn.commit()
        return 200, {"ok": True}
    except Exception as e:
        return 500, {"error": str(e)}


def list_sessions(token: str):
    if not token:
        return 401, {"error": "Not authenticated"}
    try:
        with get_db() as conn:
            session = conn.execute("SELECT user_id FROM sessions WHERE token = ?", (token,)).fetchone()
            if not session:
                return 401, {"error": "Invalid or expired session"}
            rows = conn.execute(
                "SELECT token, user_agent, ip, created_at FROM sessions WHERE user_id = ? ORDER BY created_at DESC",
                (session["user_id"],),
            ).fetchall()
        sessions = [{
            "token": r["token"][:8],  # never send the full token for another session
            "is_current": r["token"] == token,
            "user_agent": r["user_agent"],
            "ip": r["ip"],
            "created_at": r["created_at"],
        } for r in rows]
        return 200, {"sessions": sessions}
    except Exception as e:
        return 500, {"error": str(e)}


def revoke_session(token: str, target_token_prefix: str):
    if not token:
        return 401, {"error": "Not authenticated"}
    try:
        with get_db() as conn:
            session = conn.execute("SELECT user_id FROM sessions WHERE token = ?", (token,)).fetchone()
            if not session:
                return 401, {"error": "Invalid or expired session"}
            conn.execute(
                "DELETE FROM sessions WHERE user_id = ? AND token LIKE ? || '%' AND token != ?",
                (session["user_id"], target_token_prefix, token),
            )
            conn.commit()
        return 200, {"ok": True}
    except Exception as e:
        return 500, {"error": str(e)}


# ── HTTP Handler ──────────────────────────────────────────────────────────────

class AuthHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # suppress default logs

    def cors_headers(self):
        origin = self.headers.get("Origin", "")

        allowed = [
            "https://black-shield-icfy.vercel.app",
            "http://localhost:5173",
            "http://localhost:8080"
        ]

        self.send_header(
            "Access-Control-Allow-Origin",
            origin if origin in allowed else allowed[0]
        )
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Access-Control-Allow-Credentials", "true")
    def do_OPTIONS(self):
        self.send_response(200)
        self.cors_headers()
        self.send_header("Content-Length", "0")
        self.end_headers()

    def json_response(self, status: int, data: dict):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.cors_headers()
        self.end_headers()
        self.wfile.write(body)

    def read_body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        return json.loads(self.rfile.read(length))

    def get_token(self) -> str:
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return auth[7:]
        return ""

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/auth/health":
            self.json_response(200, {"status": "ok"})
        elif path == "/auth/me":
            status, data = get_me(self.get_token())
            self.json_response(status, data)
        elif path == "/auth/sessions":
            status, data = list_sessions(self.get_token())
            self.json_response(status, data)
        elif path == "/auth/export-data":
            status, data = export_user_data(self.get_token())
            self.json_response(status, data)
        else:
            self.json_response(404, {"error": "Not found"})

    def do_POST(self):
        path = urlparse(self.path).path
        body = self.read_body()
        user_agent = self.headers.get("User-Agent", "")
        ip = self.client_address[0] if self.client_address else ""

        if path == "/auth/signup":
            status, data = signup(
                body.get("username", ""),
                body.get("email", ""),
                body.get("password", ""),
                user_agent, ip,
            )
            self.json_response(status, data)
        elif path == "/auth/login":
            status, data = login(
                body.get("email", ""),
                body.get("password", ""),
                user_agent, ip,
            )
            self.json_response(status, data)
        elif path == "/auth/logout":
            status, data = logout(self.get_token())
            self.json_response(status, data)
        elif path == "/auth/update-profile":
            status, data = update_profile(self.get_token(), body.get("display_name", ""), body.get("bio", ""))
            self.json_response(status, data)
        elif path == "/auth/update-settings":
            status, data = update_settings(self.get_token(), body)
            self.json_response(status, data)
        elif path == "/auth/change-password":
            status, data = change_password(self.get_token(), body.get("current_password", ""), body.get("new_password", ""))
            self.json_response(status, data)
        elif path == "/auth/revoke-session":
            status, data = revoke_session(self.get_token(), body.get("token_prefix", ""))
            self.json_response(status, data)
        else:
            self.json_response(404, {"error": "Not found"})


# ── Entry ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    init_db()

    HTTPServer.allow_reuse_address = True
    server = HTTPServer(("0.0.0.0", PORT), AuthHandler)

    print(f"[Auth] Running on port {PORT}")
    print("POST /auth/signup")
    print("POST /auth/login")
    print("POST /auth/logout")
    print("GET  /auth/me")
    print("GET  /auth/health")

    server.serve_forever()
