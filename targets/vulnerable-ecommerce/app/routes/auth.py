"""认证路由 — 含弱密码哈希。"""

import hashlib

from flask import Blueprint, jsonify, request

from app.database import get_connection


auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/api/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    username = data.get("username")
    password = data.get("password")
    password_hash = hashlib.md5(password.encode("utf-8")).hexdigest()

    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM users WHERE username=? AND password=?",
        (username, password_hash),
    ).fetchone()
    conn.close()

    if row is None:
        return jsonify({"error": "invalid credentials"}), 401
    return jsonify({"role": row["role"], "username": row["username"]})
