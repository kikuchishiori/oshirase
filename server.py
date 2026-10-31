import hashlib
import json
import os
import re
import secrets
import sqlite3
import time
from datetime import date
from http.cookies import SimpleCookie
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("DATABASE_PATH", str(ROOT / "oshirase.sqlite3")))
COOKIE_NAME = "oshirase_session"
SESSION_SECONDS = 60 * 60 * 24 * 14
MAX_BODY = 2_000_000


def connect():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_database():
    with connect() as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_salt BLOB NOT NULL,
                password_hash BLOB NOT NULL,
                reminders_json TEXT NOT NULL DEFAULT '[]',
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                expires_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS friends (
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                friend_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                created_at INTEGER NOT NULL,
                PRIMARY KEY (user_id, friend_id),
                CHECK (user_id != friend_id)
            );
            CREATE TABLE IF NOT EXISTS rooms (
                id TEXT PRIMARY KEY,
                owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                name TEXT NOT NULL,
                start_date TEXT NOT NULL,
                end_date TEXT NOT NULL,
                password_salt BLOB NOT NULL,
                password_hash BLOB NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS room_members (
                room_id TEXT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                PRIMARY KEY (room_id, user_id)
            );
            CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);
            CREATE INDEX IF NOT EXISTS idx_room_members_user ON room_members(user_id);
            """
        )
        db.execute("DELETE FROM sessions WHERE expires_at <= ?", (int(time.time()),))


def password_hash(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 310_000)


class AppHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def log_message(self, fmt, *args):
        print("%s - %s" % (self.address_string(), fmt % args))

    def send_json(self, status, payload, headers=None):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if headers:
            for name, value in headers.items():
                self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def read_json(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length > MAX_BODY:
            raise ValueError("request_too_large")
        raw = self.rfile.read(length) if length else b"{}"
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("invalid_json")
        return value

    def current_user(self, db):
        cookie = SimpleCookie()
        cookie.load(self.headers.get("Cookie", ""))
        morsel = cookie.get(COOKIE_NAME)
        if not morsel:
            return None
        token_hash = hashlib.sha256(morsel.value.encode("ascii", errors="ignore")).hexdigest()
        row = db.execute(
            "SELECT users.id, users.username FROM sessions JOIN users ON users.id = sessions.user_id "
            "WHERE sessions.token_hash = ? AND sessions.expires_at > ?",
            (token_hash, int(time.time())),
        ).fetchone()
        return row

    def require_user(self, db):
        user = self.current_user(db)
        if user is None:
            self.send_json(401, {"error": "login_required"})
        return user

    def do_GET(self):
        path = urlparse(self.path)
        if not path.path.startswith("/api/"):
            if path.path not in ("/", "/index.html"):
                return self.send_json(404, {"error": "not_found"})
            return super().do_GET()
        with connect() as db:
            if path.path == "/api/health":
                return self.send_json(200, {"ok": True})
            if path.path == "/api/session":
                user = self.current_user(db)
                return self.send_json(200, {"user": dict(user) if user else None})
            user = self.require_user(db)
            if user is None:
                return
            if path.path == "/api/me":
                return self.send_json(200, {"id": user["id"], "username": user["username"]})
            if path.path == "/api/reminders":
                row = db.execute("SELECT reminders_json FROM users WHERE id = ?", (user["id"],)).fetchone()
                return self.send_json(200, {"reminders": json.loads(row["reminders_json"])})
            if path.path == "/api/users":
                query = parse_qs(path.query).get("q", [""])[0].strip()
                if len(query) < 2 or not re.fullmatch(r"[a-zA-Z0-9_]{2,24}", query):
                    return self.send_json(200, {"users": []})
                pattern = "%" + query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
                matches = db.execute(
                    "SELECT id, username FROM users WHERE id != ? AND username LIKE ? ESCAPE '\\' COLLATE NOCASE "
                    "ORDER BY username LIMIT 20",
                    (user["id"], pattern),
                ).fetchall()
                return self.send_json(200, {"users": [dict(row) for row in matches]})
            if path.path == "/api/friends":
                rows = db.execute(
                    "SELECT users.id, users.username FROM friends JOIN users ON users.id = friends.friend_id "
                    "WHERE friends.user_id = ? ORDER BY users.username",
                    (user["id"],),
                ).fetchall()
                return self.send_json(200, {"friends": [dict(row) for row in rows]})
            if path.path == "/api/rooms":
                room_rows = db.execute(
                    "SELECT DISTINCT rooms.id, rooms.name, rooms.start_date, rooms.end_date, users.username AS owner "
                    "FROM rooms JOIN users ON users.id = rooms.owner_id "
                    "LEFT JOIN room_members ON room_members.room_id = rooms.id "
                    "WHERE rooms.owner_id = ? OR room_members.user_id = ? ORDER BY rooms.created_at DESC",
                    (user["id"], user["id"]),
                ).fetchall()
                result = []
                for room in room_rows:
                    member_rows = db.execute(
                        "SELECT users.username FROM room_members JOIN users ON users.id = room_members.user_id "
                        "WHERE room_members.room_id = ? ORDER BY users.username",
                        (room["id"],),
                    ).fetchall()
                    result.append({**dict(room), "start": room["start_date"], "end": room["end_date"], "members": [row["username"] for row in member_rows]})
                return self.send_json(200, {"rooms": result})
        self.send_json(404, {"error": "not_found"})

    def do_POST(self):
        path = urlparse(self.path).path
        if not path.startswith("/api/"):
            return self.send_json(404, {"error": "not_found"})
        try:
            payload = self.read_json()
        except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
            return self.send_json(400, {"error": "invalid_request"})

        if path in ("/api/register", "/api/login"):
            username = str(payload.get("username", "")).strip().lower()
            password = payload.get("password", "")
            if not re.fullmatch(r"[a-zA-Z0-9_]{3,24}", username) or not isinstance(password, str) or len(password) < 8 or len(password) > 256:
                return self.send_json(400, {"error": "invalid_credentials"})
            with connect() as db:
                if path == "/api/register":
                    salt = secrets.token_bytes(16)
                    try:
                        cursor = db.execute(
                            "INSERT INTO users (username, password_salt, password_hash, created_at) VALUES (?, ?, ?, ?)",
                            (username, salt, password_hash(password, salt), int(time.time())),
                        )
                    except sqlite3.IntegrityError:
                        return self.send_json(409, {"error": "username_taken"})
                    user_id = cursor.lastrowid
                else:
                    user = db.execute("SELECT * FROM users WHERE username = ? COLLATE NOCASE", (username,)).fetchone()
                    if not user or not secrets.compare_digest(password_hash(password, user["password_salt"]), user["password_hash"]):
                        return self.send_json(401, {"error": "invalid_login"})
                    user_id = user["id"]
                token = secrets.token_urlsafe(32)
                token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
                expires = int(time.time()) + SESSION_SECONDS
                db.execute("INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)", (token_hash, user_id, expires))
                user = db.execute("SELECT id, username FROM users WHERE id = ?", (user_id,)).fetchone()
            secure = "; Secure" if self.headers.get("X-Forwarded-Proto", "").lower() == "https" else ""
            cookie = f"{COOKIE_NAME}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_SECONDS}{secure}"
            return self.send_json(200, dict(user), {"Set-Cookie": cookie})

        with connect() as db:
            user = self.require_user(db)
            if user is None:
                return
            if path == "/api/logout":
                cookie = SimpleCookie()
                cookie.load(self.headers.get("Cookie", ""))
                morsel = cookie.get(COOKIE_NAME)
                if morsel:
                    token_hash = hashlib.sha256(morsel.value.encode("ascii", errors="ignore")).hexdigest()
                    db.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
                expired = f"{COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"
                return self.send_json(200, {"ok": True}, {"Set-Cookie": expired})
            if path == "/api/friends":
                username = str(payload.get("username", "")).strip()
                friend = db.execute("SELECT id, username FROM users WHERE username = ? COLLATE NOCASE", (username,)).fetchone()
                if not friend:
                    return self.send_json(404, {"error": "user_not_found"})
                if friend["id"] == user["id"]:
                    return self.send_json(400, {"error": "cannot_add_self"})
                db.execute("INSERT OR IGNORE INTO friends (user_id, friend_id, created_at) VALUES (?, ?, ?)", (user["id"], friend["id"], int(time.time())))
                return self.send_json(200, dict(friend))
            if path == "/api/rooms":
                room_id = str(payload.get("id", ""))
                name = str(payload.get("name", "")).strip()
                start = str(payload.get("start", ""))
                end = str(payload.get("end", ""))
                room_password = payload.get("password", "")
                usernames = payload.get("members", [])
                if not room_id or len(room_id) > 80 or not name or len(name) > 40 or not isinstance(room_password, str) or len(room_password) < 4 or len(room_password) > 128 or not isinstance(usernames, list) or len(usernames) > 50:
                    return self.send_json(400, {"error": "invalid_room"})
                try:
                    start_day = date.fromisoformat(start)
                    end_day = date.fromisoformat(end)
                except ValueError:
                    return self.send_json(400, {"error": "invalid_room_dates"})
                if end_day < start_day or (end_day - start_day).days > 366:
                    return self.send_json(400, {"error": "invalid_room_dates"})
                member_ids = [user["id"]]
                for username in usernames:
                    friend = db.execute(
                        "SELECT users.id FROM users JOIN friends ON friends.friend_id = users.id "
                        "WHERE friends.user_id = ? AND users.username = ? COLLATE NOCASE",
                        (user["id"], str(username)),
                    ).fetchone()
                    if not friend:
                        return self.send_json(400, {"error": "room_member_must_be_friend"})
                    member_ids.append(friend["id"])
                salt = secrets.token_bytes(16)
                try:
                    db.execute(
                        "INSERT INTO rooms (id, owner_id, name, start_date, end_date, password_salt, password_hash, created_at) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                        (room_id, user["id"], name, start, end, salt, password_hash(room_password, salt), int(time.time())),
                    )
                except sqlite3.IntegrityError:
                    return self.send_json(409, {"error": "room_id_exists"})
                db.executemany("INSERT INTO room_members (room_id, user_id) VALUES (?, ?)", [(room_id, member_id) for member_id in set(member_ids)])
                return self.send_json(201, {"id": room_id, "name": name, "start": start, "end": end, "members": usernames + [user["username"]], "owner": user["username"]})
        self.send_json(404, {"error": "not_found"})

    def do_PUT(self):
        if urlparse(self.path).path != "/api/reminders":
            return self.send_json(404, {"error": "not_found"})
        try:
            payload = self.read_json()
        except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
            return self.send_json(400, {"error": "invalid_request"})
        reminders = payload.get("reminders")
        if not isinstance(reminders, list) or len(reminders) > 10000:
            return self.send_json(400, {"error": "invalid_reminders"})
        try:
            encoded = json.dumps(reminders, ensure_ascii=False, allow_nan=False)
        except (TypeError, ValueError):
            return self.send_json(400, {"error": "invalid_reminders"})
        with connect() as db:
            user = self.require_user(db)
            if user is None:
                return
            db.execute("UPDATE users SET reminders_json = ? WHERE id = ?", (encoded, user["id"]))
        self.send_json(200, {"ok": True})

    def do_DELETE(self):
        path = urlparse(self.path).path
        if path != "/api/friends":
            return self.send_json(404, {"error": "not_found"})
        try:
            payload = self.read_json()
        except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
            return self.send_json(400, {"error": "invalid_request"})
        with connect() as db:
            user = self.require_user(db)
            if user is None:
                return
            friend = db.execute("SELECT id FROM users WHERE username = ? COLLATE NOCASE", (str(payload.get("username", "")),)).fetchone()
            if friend:
                db.execute("DELETE FROM friends WHERE user_id = ? AND friend_id = ?", (user["id"], friend["id"]))
        self.send_json(200, {"ok": True})

    def do_PATCH(self):
        path = urlparse(self.path).path
        match = re.fullmatch(r"/api/rooms/([A-Za-z0-9_-]+)/unlock", path)
        if not match:
            return self.send_json(404, {"error": "not_found"})
        try:
            payload = self.read_json()
        except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
            return self.send_json(400, {"error": "invalid_request"})
        room_id = match.group(1)
        room_password = payload.get("password", "")
        with connect() as db:
            user = self.require_user(db)
            if user is None:
                return
            room = db.execute(
                "SELECT rooms.* FROM rooms JOIN room_members ON room_members.room_id = rooms.id "
                "WHERE rooms.id = ? AND room_members.user_id = ?",
                (room_id, user["id"]),
            ).fetchone()
            if not room:
                return self.send_json(404, {"error": "room_not_found"})
            if not isinstance(room_password, str) or not secrets.compare_digest(password_hash(room_password, room["password_salt"]), room["password_hash"]):
                return self.send_json(403, {"error": "wrong_room_password"})
            members = db.execute(
                "SELECT users.id, users.username, users.reminders_json FROM room_members "
                "JOIN users ON users.id = room_members.user_id WHERE room_members.room_id = ? ORDER BY users.username",
                (room_id,),
            ).fetchall()
            schedules = []
            for member in members:
                member_reminders = json.loads(member["reminders_json"])
                visible = []
                for item in member_reminders:
                    if item.get("kind") == "entry":
                        continue
                    start_day = item.get("startDay") or item.get("startAt", item.get("at", ""))[:10]
                    end_day = item.get("endDay") or item.get("endAt", item.get("at", ""))[:10]
                    if start_day <= room["end_date"] and end_day >= room["start_date"]:
                        visible.append(item)
                schedules.append({"username": member["username"], "reminders": visible})
            room_data = {"id": room["id"], "name": room["name"], "start": room["start_date"], "end": room["end_date"]}
        self.send_json(200, {"room": room_data, "schedules": schedules})


def main():
    initialize_database()
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8000"))
    server = ThreadingHTTPServer((host, port), AppHandler)
    print(f"Oshirase server listening on http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
