import os
import sqlite3
from datetime import datetime, timezone
from flask import Flask, request, jsonify, session, g, render_template
from cryptography.hazmat.primitives import serialization
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_PATH = os.path.join(BASE_DIR, "secure_messages.db")

app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = os.environ.get("APP_SECRET_KEY", "dev-secret-change-me")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_error):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DATABASE_PATH)
    db.executescript(
        """
        PRAGMA foreign_keys = ON;

        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            public_key TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS conversations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user1_id INTEGER NOT NULL,
            user2_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(user1_id, user2_id),
            FOREIGN KEY(user1_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(user2_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS conversation_keys (
            conversation_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            encrypted_aes_key TEXT NOT NULL,
            PRIMARY KEY(conversation_id, user_id),
            FOREIGN KEY(conversation_id) REFERENCES conversations(id) ON DELETE CASCADE,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            conversation_id INTEGER NOT NULL,
            sender_id INTEGER NOT NULL,
            ciphertext TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(conversation_id) REFERENCES conversations(id) ON DELETE CASCADE,
            FOREIGN KEY(sender_id) REFERENCES users(id) ON DELETE CASCADE
        );
        """
    )
    db.commit()
    db.close()


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def get_user_by_username(username):
    db = get_db()
    return db.execute(
        "SELECT id, username, password_hash, public_key FROM users WHERE username = ?",
        (username,),
    ).fetchone()


def get_user_by_id(user_id):
    db = get_db()
    return db.execute(
        "SELECT id, username, public_key FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()


def get_or_fail_logged_in_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    return get_user_by_id(user_id)


def conversation_for_users(user_a, user_b):
    user1, user2 = sorted([user_a, user_b])
    db = get_db()
    return db.execute(
        "SELECT id, user1_id, user2_id FROM conversations WHERE user1_id = ? AND user2_id = ?",
        (user1, user2),
    ).fetchone()


@app.route("/")
def index():
    return render_template("index.html")


@app.route('/signup', methods=['POST'])
def signup():
    data = request.json or {}
    username = (data.get('username') or "").strip()
    password = data.get('password')
    public_key = data.get('public_key')

    if not username or not password or not public_key:
        return jsonify({"status": "fail", "message": "username, password, and public_key are required"}), 400

    try:
        serialization.load_pem_public_key(public_key.encode())
    except ValueError:
        return jsonify({"status": "fail", "message": "Invalid public key format"}), 400

    db = get_db()
    if get_user_by_username(username):
        return jsonify({"status": "fail", "message": "Username already taken"}), 409

    db.execute(
        "INSERT INTO users (username, password_hash, public_key, created_at) VALUES (?, ?, ?, ?)",
        (username, generate_password_hash(password), public_key, utc_now()),
    )
    db.commit()
    return jsonify({"status": "success", "message": "Account created successfully"})


@app.route('/login', methods=['POST'])
def login():
    data = request.json or {}
    username = (data.get('username') or "").strip()
    password = data.get('password')

    user = get_user_by_username(username)
    if user and check_password_hash(user["password_hash"], password):
        session['user_id'] = user["id"]
        session['username'] = user["username"]
        return jsonify({"status": "success", "message": f"Access granted. Welcome {username}"})

    return jsonify({"status": "fail", "message": "Access denied"}), 401


@app.route('/conversations')
def get_conversations():
    user = get_or_fail_logged_in_user()
    if not user:
        return jsonify({"status": "fail", "message": "Not logged in"}), 401

    db = get_db()
    rows = db.execute(
        """
        SELECT u.username
        FROM conversations c
        JOIN users u
          ON u.id = CASE WHEN c.user1_id = ? THEN c.user2_id ELSE c.user1_id END
        WHERE c.user1_id = ? OR c.user2_id = ?
        ORDER BY u.username ASC
        """,
        (user["id"], user["id"], user["id"]),
    ).fetchall()

    return jsonify({"status": "success", "conversations": [row["username"] for row in rows]})


@app.route('/start_chat', methods=['POST'])
def start_chat():
    me = get_or_fail_logged_in_user()
    if not me:
        return jsonify({"status": "fail", "message": "Not logged in"}), 401

    data = request.json or {}
    other_username = (data.get('username') or "").strip()
    aes_key_user1 = data.get("aes_key_user1")
    aes_key_user2 = data.get("aes_key_user2")

    if not other_username or not aes_key_user1 or not aes_key_user2:
        return jsonify({"status": "fail", "message": "username, aes keys are required"}), 400

    other = get_user_by_username(other_username)
    if not other:
        return jsonify({"status": "fail", "message": "User does not exist"}), 404

    if other["id"] == me["id"]:
        return jsonify({"status": "fail", "message": "Cannot chat with yourself"}), 400

    db = get_db()
    existing = conversation_for_users(me["id"], other["id"])
    if existing:
        return jsonify({"status": "fail", "message": "Chat already exists"}), 409

    user1, user2 = sorted([me["id"], other["id"]])
    cur = db.execute(
        "INSERT INTO conversations (user1_id, user2_id, created_at) VALUES (?, ?, ?)",
        (user1, user2, utc_now()),
    )
    conversation_id = cur.lastrowid

    key_for_me = aes_key_user1
    key_for_other = aes_key_user2

    db.execute(
        "INSERT INTO conversation_keys (conversation_id, user_id, encrypted_aes_key) VALUES (?, ?, ?)",
        (conversation_id, me["id"], key_for_me),
    )
    db.execute(
        "INSERT INTO conversation_keys (conversation_id, user_id, encrypted_aes_key) VALUES (?, ?, ?)",
        (conversation_id, other["id"], key_for_other),
    )

    db.commit()
    return jsonify({"status": "success", "message": "Chat created"})


@app.route('/get_public_keys', methods=['POST'])
def get_keys():
    me = get_or_fail_logged_in_user()
    if not me:
        return jsonify({"status": "fail", "message": "Not logged in"}), 401

    data = request.json or {}
    other_username = (data.get('username') or "").strip()
    other = get_user_by_username(other_username)

    if not other:
        return jsonify({"status": "fail", "message": "User does not exist"}), 404

    return jsonify(
        {
            "status": "success",
            "my_public_key": me["public_key"],
            "their_public_key": other["public_key"],
        }
    )


@app.route('/get_messages', methods=['POST'])
def get_messages():
    me = get_or_fail_logged_in_user()
    if not me:
        return jsonify({"status": "fail", "message": "Not logged in"}), 401

    data = request.json or {}
    other_username = (data.get('username') or "").strip()
    other = get_user_by_username(other_username)

    if not other:
        return jsonify({"status": "fail", "message": "User does not exist"}), 404

    conversation = conversation_for_users(me["id"], other["id"])
    if not conversation:
        return jsonify({"status": "fail", "message": "No conversation"}), 404

    db = get_db()
    rows = db.execute(
        """
        SELECT m.ciphertext AS message, u.username AS sender
        FROM messages m
        JOIN users u ON u.id = m.sender_id
        WHERE m.conversation_id = ?
        ORDER BY m.id ASC
        """,
        (conversation["id"],),
    ).fetchall()

    return jsonify({"status": "success", "messages": [dict(row) for row in rows]})


@app.route('/get_aes_key', methods=['POST'])
def get_aes_key():
    me = get_or_fail_logged_in_user()
    if not me:
        return jsonify({"status": "fail", "message": "Not logged in"}), 401

    data = request.json or {}
    other_username = (data.get('username') or "").strip()
    other = get_user_by_username(other_username)

    if not other:
        return jsonify({"status": "fail", "message": "User does not exist"}), 404

    conversation = conversation_for_users(me["id"], other["id"])
    if not conversation:
        return jsonify({"status": "fail", "message": "No conversation"}), 404

    db = get_db()
    row = db.execute(
        "SELECT encrypted_aes_key FROM conversation_keys WHERE conversation_id = ? AND user_id = ?",
        (conversation["id"], me["id"]),
    ).fetchone()
    if not row:
        return jsonify({"status": "fail", "message": "No key found"}), 404

    return jsonify({"status": "success", "aes_key": row["encrypted_aes_key"]})


@app.route('/send_message', methods=['POST'])
def send_message():
    me = get_or_fail_logged_in_user()
    if not me:
        return jsonify({"status": "fail", "message": "Not logged in"}), 401

    data = request.json or {}
    other_username = (data.get('username') or "").strip()
    encrypted_msg = data.get('message')

    if not other_username or not encrypted_msg:
        return jsonify({"status": "fail", "message": "username and message are required"}), 400

    other = get_user_by_username(other_username)
    if not other:
        return jsonify({"status": "fail", "message": "User does not exist"}), 404

    conversation = conversation_for_users(me["id"], other["id"])
    if not conversation:
        return jsonify({"status": "fail", "message": "No conversation"}), 404

    db = get_db()
    db.execute(
        "INSERT INTO messages (conversation_id, sender_id, ciphertext, created_at) VALUES (?, ?, ?, ?)",
        (conversation["id"], me["id"], encrypted_msg, utc_now()),
    )
    db.commit()

    return jsonify({"status": "success"})


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    return jsonify({"message": "Logged out"})


if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000)
