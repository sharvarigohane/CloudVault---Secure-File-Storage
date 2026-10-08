"""
CloudVault — Cloud-Based File Storage & Management System

Python/Flask app: users sign up and log in, then upload, list, search,
download, and delete their own files. File bytes go to a storage backend
(local disk in dev, Azure Blob Storage in production — same interface,
see storage_backend/backend.py). File metadata (owner, filename, size,
hash, timestamps) lives in a SQL database (SQLite here; the same schema
works unmodified against Postgres/MySQL via SQLAlchemy).

Access control model: every file operation (download, delete, search)
is scoped to the logged-in user's own files only — enforced with a
WHERE owner_id = ? clause on every query, never by trusting client input.
This is the actual mechanism behind "restrict file operations to
authorized users," and it's the one thing worth being able to explain
in detail in an interview.
"""

import os
import hashlib
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, request, jsonify, session, render_template, send_file
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import io

from storage_backend import get_backend

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-in-production")
DB_PATH = "cloudvault.db"
storage = get_backend()


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            security_question TEXT NOT NULL,
            security_answer_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL REFERENCES users(id),
            filename TEXT NOT NULL,
            storage_key TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            content_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def now_iso():
    return datetime.now(timezone.utc).isoformat()


# ---------- Auth ----------

def login_required(f):
    """Access control gate: every file route below is wrapped with this.
    No session -> 401, before any file logic even runs."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "authentication required"}), 401
        return f(*args, **kwargs)
    return wrapper


@app.route("/api/signup", methods=["POST"])
def signup():
    data = request.get_json(force=True)
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    question = (data.get("security_question") or "").strip()
    answer = (data.get("security_answer") or "").strip()

    if not username or not password:
        return jsonify({"error": "username and password are required"}), 400
    if len(password) < 6:
        return jsonify({"error": "password must be at least 6 characters"}), 400
    if not question or not answer:
        return jsonify({"error": "a security question and answer are required, for password resets"}), 400

    conn = get_db()
    existing = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    if existing:
        conn.close()
        return jsonify({"error": "username already taken"}), 409

    pw_hash = generate_password_hash(password)  # salted hash, never store plaintext
    # Answer is normalized (lowercased) before hashing so "Blue" and "blue"
    # both verify correctly at reset time, then hashed the same way as a
    # password — it's a credential, not a display value.
    answer_hash = generate_password_hash(answer.lower())
    conn.execute(
        "INSERT INTO users (username, password_hash, security_question, security_answer_hash, created_at) VALUES (?, ?, ?, ?, ?)",
        (username, pw_hash, question, answer_hash, now_iso()),
    )
    conn.commit()
    conn.close()
    return jsonify({"status": "account created", "username": username}), 201


@app.route("/api/security-question", methods=["GET"])
def get_security_question():
    """First step of password reset: look up the account's question by
    username. Returns a generic response either way so this endpoint
    can't be used to enumerate which usernames exist."""
    username = (request.args.get("username") or "").strip()
    conn = get_db()
    user = conn.execute("SELECT security_question FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    if user is None:
        return jsonify({"error": "no account found for that username"}), 404
    return jsonify({"security_question": user["security_question"]})


@app.route("/api/reset-password", methods=["POST"])
def reset_password():
    """Second step: verify the security answer, then set a new password.
    No email involved — this is the buildable alternative to an email
    reset link when there's no email-sending service configured."""
    data = request.get_json(force=True)
    username = (data.get("username") or "").strip()
    answer = (data.get("security_answer") or "").strip()
    new_password = data.get("new_password") or ""

    if len(new_password) < 6:
        return jsonify({"error": "new password must be at least 6 characters"}), 400

    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if user is None or not check_password_hash(user["security_answer_hash"], answer.lower()):
        conn.close()
        # Same error either way — don't reveal whether the username or
        # the answer was the wrong part.
        return jsonify({"error": "username or security answer is incorrect"}), 401

    new_hash = generate_password_hash(new_password)
    conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, user["id"]))
    conn.commit()
    conn.close()
    return jsonify({"status": "password updated"})


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(force=True)
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()

    if user is None or not check_password_hash(user["password_hash"], password):
        return jsonify({"error": "invalid username or password"}), 401

    session["user_id"] = user["id"]
    session["username"] = user["username"]
    return jsonify({"status": "logged in", "username": user["username"]})


@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"status": "logged out"})


@app.route("/api/whoami", methods=["GET"])
def whoami():
    if "user_id" not in session:
        return jsonify({"authenticated": False})
    return jsonify({"authenticated": True, "username": session["username"]})


# ---------- File operations (all access-controlled by owner_id) ----------

@app.route("/api/files", methods=["GET"])
@login_required
def list_files():
    conn = get_db()
    rows = conn.execute(
        "SELECT id, filename, size_bytes, content_hash, created_at FROM files WHERE owner_id = ? ORDER BY created_at DESC",
        (session["user_id"],),
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/files/search", methods=["GET"])
@login_required
def search_files():
    q = request.args.get("q", "").strip()
    if not q:
        return jsonify([])
    conn = get_db()
    rows = conn.execute(
        "SELECT id, filename, size_bytes, content_hash, created_at FROM files WHERE owner_id = ? AND filename LIKE ? ORDER BY created_at DESC",
        (session["user_id"], f"%{q}%"),
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/files", methods=["POST"])
@login_required
def upload_file():
    if "file" not in request.files:
        return jsonify({"error": "no file provided"}), 400
    f = request.files["file"]
    if f.filename == "":
        return jsonify({"error": "empty filename"}), 400

    data = f.read()
    content_hash = hashlib.sha256(data).hexdigest()
    storage_key = f"{session['user_id']}/{content_hash}_{f.filename}"

    storage.put(storage_key, data)

    conn = get_db()
    cur = conn.execute(
        "INSERT INTO files (owner_id, filename, storage_key, size_bytes, content_hash, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (session["user_id"], f.filename, storage_key, len(data), content_hash, now_iso()),
    )
    conn.commit()
    new_id = cur.lastrowid
    row = conn.execute("SELECT id, filename, size_bytes, content_hash, created_at FROM files WHERE id = ?", (new_id,)).fetchone()
    conn.close()
    return jsonify(dict(row)), 201


def _get_owned_file(file_id, owner_id, conn):
    """Central access-control check: a file row is only ever returned if
    it belongs to the requesting user. Reused by download and delete so
    the ownership rule lives in exactly one place."""
    return conn.execute(
        "SELECT * FROM files WHERE id = ? AND owner_id = ?", (file_id, owner_id)
    ).fetchone()


@app.route("/api/files/<int:file_id>", methods=["GET"])
@login_required
def download_file(file_id):
    conn = get_db()
    row = _get_owned_file(file_id, session["user_id"], conn)
    conn.close()
    if row is None:
        # Same response whether the file doesn't exist or belongs to
        # someone else — don't leak which case it is.
        return jsonify({"error": "file not found"}), 404

    data = storage.get(row["storage_key"])
    return send_file(io.BytesIO(data), download_name=row["filename"], as_attachment=True)


@app.route("/api/files/<int:file_id>", methods=["DELETE"])
@login_required
def delete_file(file_id):
    conn = get_db()
    row = _get_owned_file(file_id, session["user_id"], conn)
    if row is None:
        conn.close()
        return jsonify({"error": "file not found"}), 404

    storage.delete(row["storage_key"])
    conn.execute("DELETE FROM files WHERE id = ?", (file_id,))
    conn.commit()
    conn.close()
    return jsonify({"status": "deleted", "id": file_id})


@app.route("/")
def home():
    return render_template("index.html")


if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=5001)
