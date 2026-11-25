#!/usr/bin/env python
"""E2E verification for taint engine - Flask e-commerce target."""

import sys

sys.path.insert(0, "E:/xuexi/AnQuan/AnQuanPingGu/backend")

from app.taint.facade import TaintFacade
from app.taint.engine import analyze_file
from app.taint.result import TaintResult
from app.taint.sanitizer import find_sanitizers_in_line, get_sanitizer_rules

print("=== Taint Engine E2E Verification ===")
print()

# ──────────────────────────────────────────────────────
# Flask e-commerce target code (same as Recon E2E)
# ──────────────────────────────────────────────────────
flask_code = """from flask import Flask, request, render_template
from flask_sqlalchemy import SQLAlchemy
import os

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "postgresql://user:pass@localhost/shop")
db = SQLAlchemy(app)

@app.route("/api/products", methods=["GET"])
def list_products():
    q = request.args.get("q", "")
    sql = "SELECT * FROM products WHERE name LIKE '%" + q + "%'"
    return db.session.execute(sql).fetchall()

@app.route("/api/orders/<int:order_id>", methods=["GET"])
def get_order(order_id):
    return db.session.execute(f"SELECT * FROM orders WHERE id = {order_id}").fetchone()

@app.route("/api/admin/upload", methods=["POST"])
def upload_file():
    f = request.files.get("file")
    f.save("/var/www/uploads/" + f.filename)
    return "uploaded"

@app.post("/api/login")
def login():
    return "ok"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
"""

# ──────────────────────────────────────────────────────
# Test 1: Basic analysis - should find vulnerabilities
# ──────────────────────────────────────────────────────
print("--- Test 1: Flask e-commerce taint analysis ---")
results = analyze_file(flask_code, "app.py", "python", "flask")
assert len(results) > 0, f"Expected >0 results, got {len(results)}"
print(f"  Total TaintResults: {len(results)}")

# Check we found SQL injection
sql_results = [r for r in results if r.sink_info.vuln_type == "sql_injection"]
assert len(sql_results) > 0, (
    f"Expected SQL injection results, got {[r.sink_info.vuln_type for r in results]}"
)
print(f"  SQL injection findings: {len(sql_results)}")

# Check we found file upload
file_results = [r for r in results if r.sink_info.vuln_type == "file_upload"]
assert len(file_results) > 0, (
    f"Expected file_upload results, got {[r.sink_info.vuln_type for r in results]}"
)
print(f"  File upload findings: {len(file_results)}")
print("  Test 1: PASS")
print()

# ──────────────────────────────────────────────────────
# Test 2: SQL injection - Source -> Sink path
# ──────────────────────────────────────────────────────
print("--- Test 2: SQL injection Source -> Sink path ---")
sql_result = sql_results[0]
assert sql_result.source_info.file == "app.py"
assert sql_result.sink_info.file == "app.py"
assert sql_result.sink_info.cwe_id == "CWE-89"
assert sql_result.sink_info.owasp == "A03:2021"
assert sql_result.is_vulnerable == True
assert sql_result.has_sanitizer == False
assert sql_result.confidence > 0.3, (
    f"Expected confidence > 0.3, got {sql_result.confidence}"
)

# Check taint path structure
assert len(sql_result.taint_path) >= 2, (
    f"Expected >=2 steps, got {len(sql_result.taint_path)}"
)
assert sql_result.taint_path[0].type == "source"
assert sql_result.taint_path[-1].type == "sink"

# Check source code contains request.args
assert (
    "request.args" in sql_result.source_info.code
    or "request" in sql_result.source_info.code
)

# Check sink code contains execute or SQL
sink_code = sql_result.sink_info.code
assert "execute" in sink_code.lower() or "select" in sink_code.lower(), (
    f"Sink code: {sink_code}"
)

print(f"  Source: {sql_result.source_info.code}")
print(f"  Sink:   {sql_result.sink_info.code}")
print(f"  CWE:    {sql_result.sink_info.cwe_id}")
print(f"  OWASP:  {sql_result.sink_info.owasp}")
print(f"  Path steps: {len(sql_result.taint_path)}")
for step in sql_result.taint_path:
    print(f"    [{step.step}] {step.type}: L{step.line} {step.code[:60]}")
print(f"  Confidence: {sql_result.confidence}")
print("  Test 2: PASS")
print()

# ──────────────────────────────────────────────────────
# Test 3: File upload - Source -> Sink path
# ──────────────────────────────────────────────────────
print("--- Test 3: File upload Source -> Sink path ---")
file_result = file_results[0]
assert file_result.sink_info.cwe_id == "CWE-434"
assert file_result.sink_info.owasp == "A04:2021"
assert file_result.is_vulnerable == True

# Check source contains request.files
assert "request.files" in file_result.source_info.code, (
    f"Source: {file_result.source_info.code}"
)

# Check sink contains .save
assert ".save" in file_result.sink_info.code, f"Sink: {file_result.sink_info.code}"

print(f"  Source: {file_result.source_info.code}")
print(f"  Sink:   {file_result.sink_info.code}")
print(f"  CWE:    {file_result.sink_info.cwe_id}")
print(f"  Path steps: {len(file_result.taint_path)}")
print("  Test 3: PASS")
print()

# ──────────────────────────────────────────────────────
# Test 4: TaintResult.to_finding_dict
# ──────────────────────────────────────────────────────
print("--- Test 4: TaintResult.to_finding_dict ---")
finding_dict = sql_result.to_finding_dict()
assert finding_dict["vuln_type"] == "sql_injection"
assert finding_dict["cwe_id"] == "CWE-89"
assert finding_dict["owasp"] == "A03:2021"
assert finding_dict["status"] == "unverified"
assert finding_dict["severity"] == "info"  # to be set by cvss
assert finding_dict["file_path"] == "app.py"
assert finding_dict["source_file"] == "app.py"
assert finding_dict["sink_file"] == "app.py"
assert finding_dict["detected_by"] == "taint_engine"
assert finding_dict["confidence"] > 0.3
assert len(finding_dict["taint_path"]) >= 2
assert finding_dict["taint_path"][0]["type"] == "source"
assert finding_dict["taint_path"][-1]["type"] == "sink"
print(f"  vuln_type: {finding_dict['vuln_type']}")
print(f"  cwe_id: {finding_dict['cwe_id']}")
print(f"  owasp: {finding_dict['owasp']}")
print(f"  status: {finding_dict['status']}")
print(f"  file_path: {finding_dict['file_path']}")
print(f"  taint_path steps: {len(finding_dict['taint_path'])}")
print("  Test 4: PASS")
print()

# ──────────────────────────────────────────────────────
# Test 5: Sanitizer detection - parameterized query
# ──────────────────────────────────────────────────────
print("--- Test 5: Sanitizer detection (parameterized query) ---")
safe_sql_code = """from flask import Flask, request
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
db = SQLAlchemy(app)

@app.route("/api/users")
def get_user():
    user_id = request.args.get("id")
    result = db.session.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    return result
"""
safe_results = analyze_file(safe_sql_code, "safe.py", "python", "flask")
# Should NOT find SQL injection (parameterized query)
sql_safe = [r for r in safe_results if r.sink_info.vuln_type == "sql_injection"]
assert len(sql_safe) == 0, f"Expected 0 SQL injection in safe code, got {len(sql_safe)}"
print(f"  parameterized query -> 0 SQL injection findings")
print("  Test 5: PASS")
print()

# ──────────────────────────────────────────────────────
# Test 6: Sanitizer detection - file type validation
# ──────────────────────────────────────────────────────
print("--- Test 6: Sanitizer detection (file type validation) ---")
safe_upload_code = """from flask import Flask, request
import os

app = Flask(__name__)
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}

def allowed_file(filename):
    return os.path.splitext(filename)[1].lower().lstrip(".") in ALLOWED_EXTENSIONS

@app.route("/upload", methods=["POST"])
def upload():
    f = request.files.get("file")
    if not allowed_file(f.filename):
        return "invalid file type"
    f.save("/var/www/uploads/" + f.filename)
    return "uploaded"
"""
upload_results = analyze_file(safe_upload_code, "safe_upload.py", "python", "flask")
# Should NOT find file upload vulnerability (has allowed_file check)
file_safe = [r for r in upload_results if r.sink_info.vuln_type == "file_upload"]
# Note: the sanitizer should be detected on the path
if len(file_safe) > 0:
    # If found, it should have sanitizer
    for r in file_safe:
        assert r.has_sanitizer, (
            "Expected sanitizer for file upload with allowed_file check"
        )
    print(
        f"  file upload with allowed_file -> {len(file_safe)} findings (all sanitized)"
    )
else:
    print(f"  file upload with allowed_file -> 0 findings (sanitizer blocked)")
print("  Test 6: PASS")
print()

# ──────────────────────────────────────────────────────
# Test 7: Facade analyze_code (one-step)
# ──────────────────────────────────────────────────────
print("--- Test 7: TaintFacade.analyze_code (one-step) ---")
findings = TaintFacade.analyze_code(flask_code, "app.py", "python", "flask")
assert len(findings) > 0, f"Expected >0 findings, got {len(findings)}"

# Check all findings have correct status
for f in findings:
    assert f["status"] == "unverified", f"Expected unverified, got {f['status']}"
    assert f["detected_by"] == "taint_engine"

# Check we have SQL injection and file upload
finding_types = set(f["vuln_type"] for f in findings)
assert "sql_injection" in finding_types, f"Missing sql_injection in {finding_types}"
assert "file_upload" in finding_types, f"Missing file_upload in {finding_types}"

print(f"  Total findings: {len(findings)}")
print(f"  Types: {finding_types}")
print(f"  All status=unverified: True")
print("  Test 7: PASS")
print()

# ──────────────────────────────────────────────────────
# Test 8: No vulnerabilities in safe code
# ──────────────────────────────────────────────────────
print("--- Test 8: No vulnerabilities in safe code ---")
safe_code = """from flask import Flask
app = Flask(__name__)

@app.route("/")
def index():
    return "Hello World"

if __name__ == "__main__":
    app.run(port=5000)
"""
safe_findings = TaintFacade.analyze_code(safe_code, "safe.py", "python", "flask")
assert len(safe_findings) == 0, (
    f"Expected 0 findings in safe code, got {len(safe_findings)}"
)
print(f"  safe code -> 0 findings")
print("  Test 8: PASS")
print()

# ──────────────────────────────────────────────────────
# Test 9: Unknown language -> empty results
# ──────────────────────────────────────────────────────
print("--- Test 9: Unknown language ---")
unknown_findings = TaintFacade.analyze_code(flask_code, "app.rs", "rust", "generic")
assert len(unknown_findings) == 0
print(f"  rust code -> 0 findings (no rules)")
print("  Test 9: PASS")
print()

# ──────────────────────────────────────────────────────
# Test 10: Sanitizer rules verification
# ──────────────────────────────────────────────────────
print("--- Test 10: Sanitizer rules ---")
# Parameterized query
matched = find_sanitizers_in_line(
    'db.session.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
    "python",
    "sql_injection",
)
assert len(matched) > 0, "Expected sanitizer match for parameterized query"
print(f"  parameterized query -> matched: {matched[0].name}")

# shlex.quote
matched = find_sanitizers_in_line(
    "cmd = shlex.quote(user_input)", "python", "command_injection"
)
assert len(matched) > 0
print(f"  shlex.quote -> matched: {matched[0].name}")

# allowed_file
matched = find_sanitizers_in_line(
    "if not allowed_file(f.filename):", "python", "file_upload"
)
assert len(matched) > 0
print(f"  allowed_file -> matched: {matched[0].name}")

# secure_filename
matched = find_sanitizers_in_line(
    "filename = secure_filename(f.filename)", "python", "file_upload"
)
assert len(matched) > 0
print(f"  secure_filename -> matched: {matched[0].name}")

# No false positive
matched = find_sanitizers_in_line(
    "result = db.session.execute(sql)", "python", "sql_injection"
)
# execute(sql) without params should NOT match sanitizer
# But the sanitizer pattern r"\.execute\s*\(\s*[^,]+\s*,\s*" requires a comma after first arg
# So execute(sql) alone should NOT match
print(
    f"  execute(sql) without params -> {len(matched)} sanitizer matches (should be 0)"
)
assert len(matched) == 0, (
    f"Expected 0 sanitizer matches for execute(sql), got {matched}"
)

print("  Test 10: PASS")
print()

# ──────────────────────────────────────────────────────
# Test 11: Multiple files batch analysis
# ──────────────────────────────────────────────────────
print("--- Test 11: Batch analysis (multiple files) ---")
files = [
    {"path": "app.py", "content": flask_code},
    {"path": "utils.py", "content": "import os\ndef helper():\n    pass\n"},
    {
        "path": "admin.py",
        "content": 'from flask import request\nimport os\n\n@app.route("/exec")\ndef exec_cmd():\n    cmd = request.args.get("cmd")\n    os.system(cmd)\n    return "done"\n',
    },
]
batch_results = TaintFacade.analyze_files(files, "python", "flask")
assert len(batch_results) > 0
# Should find findings from app.py and admin.py
finding_files = set(r.source_info.file for r in batch_results)
assert "app.py" in finding_files
assert "admin.py" in finding_files
# Should have command injection from admin.py
cmd_results = [r for r in batch_results if r.sink_info.vuln_type == "command_injection"]
assert len(cmd_results) > 0, (
    f"Expected command_injection, got {set(r.sink_info.vuln_type for r in batch_results)}"
)
print(f"  Batch results: {len(batch_results)} findings from {len(finding_files)} files")
print(f"  Files with findings: {finding_files}")
print(f"  Finding types: {set(r.sink_info.vuln_type for r in batch_results)}")
print("  Test 11: PASS")
print()

# ──────────────────────────────────────────────────────
# Test 12: results_to_findings
# ──────────────────────────────────────────────────────
print("--- Test 12: TaintFacade.results_to_findings ---")
findings_list = TaintFacade.results_to_findings(results)
assert len(findings_list) > 0
for f in findings_list:
    assert f["status"] == "unverified"
    assert f["vuln_type"] in ("sql_injection", "file_upload", "command_injection")
    assert f["cwe_id"] is not None
    assert f["owasp"] is not None
    assert f["source_code"] is not None
    assert f["sink_code"] is not None
    assert f["taint_path"] is not None and len(f["taint_path"]) >= 2
    assert f["file_path"] is not None
    assert f["detected_by"] == "taint_engine"
print(f"  {len(findings_list)} findings, all with required fields")
print("  Test 12: PASS")
print()

print("=== ALL TAINT ENGINE TESTS PASSED (12/12) ===")
