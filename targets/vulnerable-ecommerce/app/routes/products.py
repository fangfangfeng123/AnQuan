"""商品路由 — 正常路由。"""

from flask import Blueprint, jsonify

from app.database import get_connection


products_bp = Blueprint("products", __name__)


@products_bp.route("/api/products")
def product_list():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM products").fetchall()
    conn.close()
    return jsonify([dict(row) for row in rows])
