#!/usr/bin/env python
"""E2E verification for Recon Agent - 3 scenarios."""

import sys
import os

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from app.scanners.manifest_parser import parse_manifest, detect_manifest_files
from app.scanners.tech_detector import (
    detect_language,
    detect_framework,
    detect_entry_points,
    detect_ports,
    detect_db_type,
    detect_run_command,
)
from app.scanners.route_scanner import scan_routes, summarize_routes

print("=== E2E VERIFICATION: 3 SCENARIOS ===")
print()

# ================================================================
# Scenario 1: Flask e-commerce target
# ================================================================
print("--- Scenario 1: Flask E-commerce Target ---")
flask_manifest = "requirements.txt"
flask_file_listing = "app.py\nrequirements.txt\ntemplates\nstatic\ntests.py"
flask_file_type_dist = "  8 py\n  4 html\n  2 css\n  1 js"
flask_req_content = (
    "flask==2.3.0\n"
    "flask-sqlalchemy>=3.0\n"
    "psycopg2-binary==2.9.9\n"
    "werkzeug==2.3.6\n"
    "jinja2==3.1.2"
)
flask_entry_code = """
from flask import Flask, request, render_template
from flask_sqlalchemy import SQLAlchemy
import os

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "postgresql://user:pass@localhost/shop")
db = SQLAlchemy(app)

@app.route("/api/products", methods=["GET"])
def list_products():
    sql = "SELECT * FROM products WHERE name LIKE '%" + request.args.get("q", "") + "%'"
    return db.session.execute(sql).fetchall()

@app.route("/api/orders/<int:order_id>", methods=["GET"])
def get_order(order_id):
    return db.session.execute(f"SELECT * FROM orders WHERE id = {order_id}").fetchone()

@app.route("/api/admin/upload", methods=["POST"])
def upload_file():
    f = request.files["file"]
    f.save("/var/www/uploads/" + f.filename)
    return "uploaded"

@app.post("/api/login")
def login():
    return "ok"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
"""

# 1.1 detect manifest files
manifests = detect_manifest_files(flask_file_listing)
assert "requirements.txt" in manifests, f"Expected requirements.txt in {manifests}"

# 1.2 detect language
lang = detect_language(manifests, flask_file_type_dist)
assert lang == "python", f"Expected python, got {lang}"

# 1.3 parse dependencies
deps = parse_manifest("requirements.txt", flask_req_content)
assert deps.get("flask") == "2.3.0", f"flask version: {deps.get('flask')}"
assert deps.get("flask-sqlalchemy") is not None
assert deps.get("psycopg2-binary") == "2.9.9", (
    f"psycopg2 version: {deps.get('psycopg2-binary')}"
)
assert len(deps) == 5, f"Expected 5 deps, got {len(deps)}"

# 1.4 detect framework
fw = detect_framework(lang, deps)
assert fw == "flask", f"Expected flask, got {fw}"

# 1.5 detect entry points
entries = detect_entry_points(lang, fw, flask_file_listing)
assert len(entries) > 0, "Expected at least 1 entry point"
assert entries[0]["file"] == "app.py", f"Expected app.py, got {entries[0]['file']}"

# 1.6 detect ports
ports = detect_ports(fw, flask_entry_code, "")
assert any(p["port"] == 5000 for p in ports), f"Expected port 5000 in {ports}"

# 1.7 detect db type
db = detect_db_type(flask_entry_code, "", deps)
assert db == "postgresql", f"Expected postgresql, got {db}"

# 1.8 detect run command
cmd = detect_run_command(lang, fw, entries)
assert cmd == "python app.py", f"Expected python app.py, got {cmd}"

# 1.9 scan routes
routes = scan_routes(lang, flask_entry_code, "app.py")
assert len(routes) >= 4, f"Expected >=4 routes, got {len(routes)}"
mp = {(r["method"], r["path"]) for r in routes}
assert ("GET", "/api/products") in mp, f"Missing GET /api/products in {mp}"
assert ("GET", "/api/orders/<int:order_id>") in mp, (
    f"Missing GET /api/orders/<int:order_id> in {mp}"
)
assert ("POST", "/api/admin/upload") in mp, f"Missing POST /api/admin/upload in {mp}"
assert ("POST", "/api/login") in mp, f"Missing POST /api/login in {mp}"

# 1.10 handlers
handlers = {r["handler"] for r in routes if r["handler"]}
assert "list_products" in handlers, f"Missing list_products in {handlers}"
assert "get_order" in handlers, f"Missing get_order in {handlers}"
assert "upload_file" in handlers, f"Missing upload_file in {handlers}"

# 1.11 summarize
summary = summarize_routes(routes)
assert summary["total"] == len(routes), (
    f"Summary total mismatch: {summary['total']} vs {len(routes)}"
)
assert "GET" in summary["by_method"], (
    f"Missing GET in by_method: {summary['by_method']}"
)
assert "POST" in summary["by_method"], (
    f"Missing POST in by_method: {summary['by_method']}"
)

print(f"  language={lang}")
print(f"  framework={fw}")
print(
    f"  dependencies={len(deps)} (flask, flask-sqlalchemy, psycopg2-binary, werkzeug, jinja2)"
)
print(f"  entry_points={[e['file'] for e in entries]}")
print(f"  ports={[p['port'] for p in ports]}")
print(f"  db_type={db}")
print(f"  run_command={cmd}")
print(
    f"  routes={summary['total']} (GET /api/products, GET /api/orders/<int:id>, POST /api/admin/upload, POST /api/login)"
)
print(f"  handlers={handlers}")
print("  RESULT: PASS")
print()

# ================================================================
# Scenario 2: Node.js/Express microservice
# ================================================================
print("--- Scenario 2: Node.js Express Microservice ---")
node_manifest = "package.json"
node_file_listing = "app.js\npackage.json\nroutes\nmiddleware\npublic"
node_file_type_dist = "  10 js\n  3 json\n  2 css"
node_pkg_content = '{"dependencies":{"express":"^4.18.0","mongoose":"^7.5.0","jsonwebtoken":"^9.0.0","bcryptjs":"^2.4.3"},"devDependencies":{"nodemon":"^3.0.0"}}'
node_entry_code = """
const express = require("express");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI || "mongodb://localhost:27017/userservice";

mongoose.connect(MONGODB_URI);

app.get("/api/users", async (req, res) => {
    const users = await User.find({});
    res.json(users);
});

app.get("/api/users/:id", async (req, res) => {
    const user = await User.findById(req.params.id);
    res.json(user);
});

app.post("/api/auth/login", async (req, res) => {
    const token = jwt.sign({ userId: 1 }, "secret");
    res.json({ token });
});

app.delete("/api/users/:id", async (req, res) => {
    await User.findByIdAndDelete(req.params.id);
    res.json({ ok: true });
});

app.listen(PORT, () => console.log("Server running on port " + PORT));
"""

# 2.1 detect manifest
manifests2 = detect_manifest_files(node_file_listing)
assert "package.json" in manifests2, f"Expected package.json in {manifests2}"

# 2.2 detect language
lang2 = detect_language(manifests2, node_file_type_dist)
assert lang2 == "javascript", f"Expected javascript, got {lang2}"

# 2.3 parse deps
deps2 = parse_manifest("package.json", node_pkg_content)
assert deps2.get("express") == "4.18.0", f"express: {deps2.get('express')}"
assert deps2.get("mongoose") == "7.5.0", f"mongoose: {deps2.get('mongoose')}"
assert deps2.get("jsonwebtoken") == "9.0.0", (
    f"jsonwebtoken: {deps2.get('jsonwebtoken')}"
)
assert deps2.get("bcryptjs") == "2.4.3", f"bcryptjs: {deps2.get('bcryptjs')}"
assert deps2.get("nodemon") == "3.0.0", f"nodemon: {deps2.get('nodemon')}"

# 2.4 detect framework
fw2 = detect_framework(lang2, deps2)
assert fw2 == "express", f"Expected express, got {fw2}"

# 2.5 detect entry points
entries2 = detect_entry_points(lang2, fw2, node_file_listing)
assert len(entries2) > 0, "Expected at least 1 entry point"
assert entries2[0]["file"] == "app.js", f"Expected app.js, got {entries2[0]['file']}"

# 2.6 detect ports
ports2 = detect_ports(fw2, node_entry_code, "")
assert any(p["port"] == 3000 for p in ports2), f"Expected port 3000 in {ports2}"

# 2.7 detect db type
db2 = detect_db_type(node_entry_code, "", deps2)
assert db2 == "mongodb", f"Expected mongodb, got {db2}"

# 2.8 detect run command
cmd2 = detect_run_command(lang2, fw2, entries2)
assert cmd2 == "npm start", f"Expected npm start, got {cmd2}"

# 2.9 scan routes
routes2 = scan_routes(lang2, node_entry_code, "app.js")
assert len(routes2) >= 4, f"Expected >=4 routes, got {len(routes2)}"
mp2 = {(r["method"], r["path"]) for r in routes2}
assert ("GET", "/api/users") in mp2, f"Missing GET /api/users in {mp2}"
assert ("GET", "/api/users/:id") in mp2, f"Missing GET /api/users/:id in {mp2}"
assert ("POST", "/api/auth/login") in mp2, f"Missing POST /api/auth/login in {mp2}"
assert ("DELETE", "/api/users/:id") in mp2, f"Missing DELETE /api/users/:id in {mp2}"

# 2.10 summarize
summary2 = summarize_routes(routes2)
assert summary2["total"] == len(routes2), (
    f"Summary total mismatch: {summary2['total']} vs {len(routes2)}"
)

print(f"  language={lang2}")
print(f"  framework={fw2}")
print(
    f"  dependencies={len(deps2)} (express, mongoose, jsonwebtoken, bcryptjs, nodemon)"
)
print(f"  entry_points={[e['file'] for e in entries2]}")
print(f"  ports={[p['port'] for p in ports2]}")
print(f"  db_type={db2}")
print(f"  run_command={cmd2}")
print(
    f"  routes={summary2['total']} (GET /api/users, GET /api/users/:id, POST /api/auth/login, DELETE /api/users/:id)"
)
print("  RESULT: PASS")
print()

# ================================================================
# Scenario 3: Unknown project (no manifests)
# ================================================================
print("--- Scenario 3: Unknown Project (No Manifest Files) ---")
unknown_listing = "README.md\ndata.csv\nnotes.txt\nconfig.ini"
unknown_file_type_dist = "  2 txt\n  1 md\n  1 csv\n  1 ini"

# 3.1 detect manifest files
manifests3 = detect_manifest_files(unknown_listing)
assert len(manifests3) == 0, f"Expected 0 manifests, got {manifests3}"

# 3.2 detect language
lang3 = detect_language(manifests3, unknown_file_type_dist)
assert lang3 == "unknown", f"Expected unknown, got {lang3}"

# 3.3 detect framework
fw3 = detect_framework(lang3, {})
assert fw3 == "unknown", f"Expected unknown, got {fw3}"

# 3.4 detect entry points
entries3 = detect_entry_points(lang3, fw3, unknown_listing)
assert len(entries3) == 0, f"Expected 0 entries, got {entries3}"

# 3.5 detect ports
ports3 = detect_ports(fw3, "", "")
assert len(ports3) == 0, f"Expected 0 ports, got {ports3}"

# 3.6 detect db type
db3 = detect_db_type("", "", {})
assert db3 == "not_detected", f"Expected not_detected, got {db3}"

# 3.7 detect run command
cmd3 = detect_run_command(lang3, fw3, entries3)
assert cmd3 is None, f"Expected None, got {cmd3}"

# 3.8 scan routes
routes3 = scan_routes(lang3, "some content", "README.md")
assert len(routes3) == 0, f"Expected 0 routes, got {routes3}"

# 3.9 summarize
summary3 = summarize_routes(routes3)
assert summary3["total"] == 0, f"Expected 0 total, got {summary3['total']}"

print(f"  language={lang3}")
print(f"  framework={fw3}")
print(f"  dependencies=0")
print(f"  entry_points=0")
print(f"  ports=0")
print(f"  db_type={db3}")
print(f"  run_command={cmd3}")
print(f"  routes=0")
print("  RESULT: PASS (no crash, all fields default to unknown/not_detected)")
print()

# ================================================================
# Final summary
# ================================================================
print("=== SUMMARY ===")
print("  Scenario 1 (Flask e-commerce):     PASS")
print("  Scenario 2 (Express microservice): PASS")
print("  Scenario 3 (Unknown project):       PASS (graceful, no crash)")
print()
print("ALL E2E SCENARIO TESTS PASSED (3/3)")
