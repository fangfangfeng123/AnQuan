"""文件上传路由 — 含任意文件上传漏洞。"""

import os

from flask import Blueprint, jsonify, request


upload_bp = Blueprint("upload", __name__)
UPLOAD_DIR = os.environ.get(
    "ECOM_UPLOAD_DIR",
    os.path.join(os.path.dirname(os.path.dirname(__file__)), "uploads"),
)


@upload_bp.route("/api/upload", methods=["POST"])
def upload_file():
    file = request.files.get("file")
    if file is None:
        return jsonify({"error": "file required"}), 400

    os.makedirs(UPLOAD_DIR, exist_ok=True)
    file.save(os.path.join(UPLOAD_DIR, file.filename))
    return jsonify({"message": "uploaded", "filename": file.filename})
