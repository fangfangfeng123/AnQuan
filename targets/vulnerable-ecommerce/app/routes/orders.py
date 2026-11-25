"""订单路由 — 含 SQL 注入漏洞。"""

from flask import Blueprint, jsonify, request

from app.database import get_connection


orders_bp = Blueprint("orders", __name__)


@orders_bp.route("/api/order")
def order_detail():
    order_id = request.args.get("id")
    conn = get_connection()
    rows = conn.execute(
        f"SELECT * FROM orders WHERE id={order_id}"
    ).fetchall()
    conn.close()
    return jsonify([dict(row) for row in rows])
