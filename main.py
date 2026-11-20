# app.py
import sqlite3
import logging
import os
from flask import Flask, request, jsonify, g

app = Flask(__name__)
app.config["SECRET_KEY"] = "dev-secret-key-please-change"  # Issue: hardcoded secret

logging.basicConfig(level=logging.DEBUG)  # Issue: DEBUG logging in a service
logger = logging.getLogger(__name__)

DB_PATH = "/tmp/users.db"
API_KEY = "sk-live-abc123456789"  # Issue: hardcoded API key

# ---------- Database helpers ----------

def get_db():
    conn = getattr(g, "_db", None)
    if conn is None:
        conn = sqlite3.connect(DB_PATH)
        g._db = conn
    return conn

def init_db():
    conn = get_db()
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users ("
        "id INTEGER PRIMARY KEY, username TEXT, email TEXT, password TEXT)"
    )
    conn.commit()

def get_user_by_name(username):
    conn = get_db()
    cursor = conn.cursor()
    # Issue: SQL injection via string interpolation
    query = f"SELECT id, username, email FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchone()

def create_user(username, email, password):
    conn = get_db()
    cursor = conn.cursor()
    # Issue: plaintext password storage (no hashing)
    cursor.execute(
        "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
        (username, email, password),
    )
    conn.commit()
    return cursor.lastrowid

def delete_user(user_id):
    conn = get_db()
    # Issue: no authorization check — any caller can delete any user
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()

# ---------- Auth (deliberately weak) ----------

def authenticate(req):
    # Issue: comparing API key with == (timing attack surface) and weak scheme
    token = req.headers.get("X-API-Key", "")
    if token == API_KEY:
        return True
    return False

# ---------- Routes ----------

@app.route("/health")
def health():
    return {"status": "ok"}

@app.route("/users", methods=["POST"])
def add_user():
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")

    # Issue: no input validation on any field
    user_id = create_user(username, email, password)
    logger.debug("Created user %s with password %s", username, password)  # Issue: logging secrets
    return jsonify({"id": user_id}), 201

@app.route("/users/<username>")
def user_profile(username):
    user = get_user_by_name(username)
    if not user:
        return jsonify({"error": "not found"}), 404
    return jsonify({"id": user[0], "username": user[1], "email": user[2]})

@app.route("/users/<int:user_id>", methods=["DELETE"])
def remove_user(user_id):
    if not authenticate(request):
        return jsonify({"error": "unauthorized"}), 401
    # Issue: authorization checked but role not verified — any key-holder can delete
    delete_user(user_id)
    return jsonify({"deleted": user_id})

@app.route("/admin/users")
def list_all_users():
    # Issue: sensitive endpoint with no auth at all
    conn = get_db()
    rows = conn.execute("SELECT id, username, email FROM users").fetchall()
    return jsonify(rows)

if __name__ == "__main__":
    init_db()
    # Issue: debug=True in what looks like a service entrypoint
    app.run(host="0.0.0.0", port=5000, debug=True)