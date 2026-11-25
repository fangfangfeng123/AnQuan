#!/usr/bin/env python
"""Verify scoring/cvss.py - CVSS calculation and heuristic scoring.

Test vectors verified against official FIRST.org CVSS 3.1 Examples document
(https://www.first.org/cvss/v3.1/examples) and the NVD calculator.
"""

import sys

sys.path.insert(0, "E:/xuexi/AnQuan/AnQuanPingGu/backend")

from app.scoring.cvss import (
    ScoringContext,
    score_finding,
    score_findings_batch,
    calculate_base_score,
    severity_from_score,
)

print("=== CVSS Scoring Verification ===")
print()

# ──────────────────────────────────────────────────────
# Test 1: CVSS 3.1 Base Score calculation (verified against NVD)
# ──────────────────────────────────────────────────────
print("--- Test 1: CVSS 3.1 Base Score (official NVD values) ---")

verified_vectors = [
    ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "Shellshock"),
    ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5, "Heartbleed"),
    ("AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N", 7.1, "IDOR pattern"),
    ("AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", 5.4, "XSS pattern"),
    ("AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N", 6.5, "XSS stored pattern"),
    ("AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, "No impact"),
]

for vector, expected, desc in verified_vectors:
    score = calculate_base_score(vector)
    assert score == expected, f"{desc}: expected {expected}, got {score}"
    print(f"  {desc:20s} {vector} = {score}")

print("  Test 1: PASS")
print()

# ──────────────────────────────────────────────────────
# Test 2: FIRST.org official examples (18 CVEs)
# ──────────────────────────────────────────────────────
print("--- Test 2: FIRST.org official CVSS 3.1 examples ---")

official_vectors = [
    ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "Shellshock CVE-2014-6271"),
    ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5, "Heartbleed CVE-2014-0160"),
    ("AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", 7.2, "Cisco IOS CVE-2012-0384"),
    ("AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 7.8, "Apple iWork CVE-2015-1098"),
    ("AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:L", 4.2, "Tomcat CVE-2009-0783"),
    ("AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N", 4.6, "Apple iOS CVE-2014-2019"),
    ("AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 8.8, "SearchBlox CSRF CVE-2015-0970"),
    ("AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.8, "Bluetooth CVE-2011-1265"),
    ("AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", 6.4, "MySQL SQLi CVE-2013-0375"),
    ("AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1, "POODLE CVE-2014-3566"),
    ("AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9, "VMware Escape CVE-2012-1516"),
    ("AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N", 6.8, "DNS Kaminsky CVE-2008-1447"),
    ("AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 6.8, "Sophos CVE-2014-2005"),
    ("AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N", 5.8, "Joomla CVE-2010-0467"),
    ("AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N", 5.8, "Cisco ACL CVE-2012-1342"),
    ("AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:H", 9.3, "Juniper ARP CVE-2013-6014"),
    ("AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H", 9.0, "Cantemo XSS CVE-2019-7551"),
    ("AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 7.8, "Adobe Acrobat CVE-2009-0658"),
]

for vector, expected, desc in official_vectors:
    score = calculate_base_score(vector)
    assert score == expected, f"{desc}: expected {expected}, got {score}"

print(f"  All {len(official_vectors)} official vectors verified against FIRST.org")
print("  Test 2: PASS")
print()

# ──────────────────────────────────────────────────────
# Test 3: Severity mapping
# ──────────────────────────────────────────────────────
print("--- Test 3: Severity mapping ---")
assert severity_from_score(9.8) == "critical"
assert severity_from_score(9.0) == "critical"
assert severity_from_score(8.9) == "high"
assert severity_from_score(7.0) == "high"
assert severity_from_score(6.5) == "medium"
assert severity_from_score(4.0) == "medium"
assert severity_from_score(3.9) == "low"
assert severity_from_score(0.1) == "low"
assert severity_from_score(0.0) == "info"
print("  Severity mapping: all correct")
print("  Test 3: PASS")
print()

# ──────────────────────────────────────────────────────
# Test 4: Heuristic scoring - SQL injection (no auth, external)
# ──────────────────────────────────────────────────────
print("--- Test 4: SQL injection scoring (external, no auth) ---")
ctx = ScoringContext(
    vuln_type="sql_injection",
    is_externally_reachable=True,
    requires_auth=False,
    has_filter=False,
    confidence=0.8,
)
severity, score, vector = score_finding(ctx)
assert severity == "critical" or severity == "high", (
    f"Expected critical or high, got {severity}"
)
assert score >= 7.0, f"Expected score >= 7.0, got {score}"
assert "AV:N" in vector  # External = Network
assert "PR:N" in vector  # No auth required
assert "C:H" in vector  # SQL injection = High confidentiality
print(f"  severity={severity}, score={score}, vector={vector}")
print("  Test 4: PASS")
print()

# ──────────────────────────────────────────────────────
# Test 5: SQL injection with auth required -> PR:L
# ──────────────────────────────────────────────────────
print("--- Test 5: SQL injection with auth required ---")
ctx = ScoringContext(
    vuln_type="sql_injection",
    is_externally_reachable=True,
    requires_auth=True,
    confidence=0.8,
)
severity, score, vector = score_finding(ctx)
assert "PR:L" in vector, f"Expected PR:L, got {vector}"
score_no_auth = calculate_base_score("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
score_auth = calculate_base_score("AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H")
assert score_auth < score_no_auth, (
    f"Auth should lower score: {score_auth} vs {score_no_auth}"
)
print(f"  severity={severity}, score={score}, vector={vector}")
print(f"  (no-auth={score_no_auth}, with-auth={score_auth})")
print("  Test 5: PASS")
print()

# ──────────────────────────────────────────────────────
# Test 6: Command injection -> critical
# ──────────────────────────────────────────────────────
print("--- Test 6: Command injection scoring ---")
ctx = ScoringContext(
    vuln_type="command_injection",
    is_externally_reachable=True,
    requires_auth=False,
    confidence=0.9,
)
severity, score, vector = score_finding(ctx)
assert severity == "critical", f"Expected critical, got {severity}"
assert score >= 9.0, f"Expected >= 9.0, got {score}"
print(f"  severity={severity}, score={score}, vector={vector}")
print("  Test 6: PASS")
print()

# ──────────────────────────────────────────────────────
# Test 7: IDOR -> medium (PR:L, C:H, I:L, A:N = 7.1)
# ──────────────────────────────────────────────────────
print("--- Test 7: IDOR scoring ---")
ctx = ScoringContext(
    vuln_type="broken_access",
    is_externally_reachable=True,
    requires_auth=True,
    confidence=0.6,
)
severity, score, vector = score_finding(ctx)
assert severity in ("medium", "high"), f"Expected medium or high, got {severity}"
assert "PR:L" in vector, f"Expected PR:L for IDOR, got {vector}"
print(f"  severity={severity}, score={score}, vector={vector}")
print("  Test 7: PASS")
print()

# ──────────────────────────────────────────────────────
# Test 8: Sensitive data -> medium
# ──────────────────────────────────────────────────────
print("--- Test 8: Sensitive data scoring ---")
ctx = ScoringContext(
    vuln_type="sensitive_data",
    is_externally_reachable=True,
    requires_auth=False,
    confidence=0.7,
)
severity, score, vector = score_finding(ctx)
assert severity in ("medium", "high"), f"Expected medium or high, got {severity}"
assert "C:H" in vector  # Sensitive data = High confidentiality
print(f"  severity={severity}, score={score}, vector={vector}")
print("  Test 8: PASS")
print()

# ──────────────────────────────────────────────────────
# Test 9: With sanitizer -> lower score
# ──────────────────────────────────────────────────────
print("--- Test 9: With sanitizer -> lower score ---")
ctx_no_san = ScoringContext(
    vuln_type="sql_injection",
    has_sanitizer=False,
    confidence=0.8,
)
ctx_with_san = ScoringContext(
    vuln_type="sql_injection",
    has_sanitizer=True,
    confidence=0.8,
)
sev1, score1, vec1 = score_finding(ctx_no_san)
sev2, score2, vec2 = score_finding(ctx_with_san)
assert score2 < score1, f"Sanitizer should lower: {score2} vs {score1}"
assert "C:L" in vec2, f"Expected C:L with sanitizer, got {vec2}"
print(f"  Without sanitizer: severity={sev1}, score={score1}")
print(f"  With sanitizer:    severity={sev2}, score={score2}")
print("  Test 9: PASS")
print()

# ──────────────────────────────────────────────────────
# Test 10: With filter -> higher AC
# ──────────────────────────────────────────────────────
print("--- Test 10: With filter -> higher AC ---")
ctx_no_filter = ScoringContext(
    vuln_type="sql_injection",
    has_filter=False,
    confidence=0.8,
)
ctx_with_filter = ScoringContext(
    vuln_type="sql_injection",
    has_filter=True,
    confidence=0.8,
)
sev1, score1, vec1 = score_finding(ctx_no_filter)
sev2, score2, vec2 = score_finding(ctx_with_filter)
assert "AC:L" in vec1, f"Expected AC:L without filter, got {vec1}"
assert "AC:H" in vec2, f"Expected AC:H with filter, got {vec2}"
assert score2 <= score1, f"Filter should lower or equal: {score2} vs {score1}"
print(f"  Without filter: AC=L, score={score1}")
print(f"  With filter:    AC=H, score={score2}")
print("  Test 10: PASS")
print()

# ──────────────────────────────────────────────────────
# Test 11: Not externally reachable -> AV:L
# ──────────────────────────────────────────────────────
print("--- Test 11: Not externally reachable -> AV=L ---")
ctx = ScoringContext(
    vuln_type="sql_injection",
    is_externally_reachable=False,
    confidence=0.8,
)
severity, score, vector = score_finding(ctx)
assert "AV:L" in vector, f"Expected AV:L, got {vector}"
print(f"  severity={severity}, score={score}, vector={vector}")
print("  Test 11: PASS")
print()

# ──────────────────────────────────────────────────────
# Test 12: Low confidence -> score reduced
# ──────────────────────────────────────────────────────
print("--- Test 12: Low confidence -> score reduced ---")
ctx_high = ScoringContext(
    vuln_type="sql_injection",
    confidence=0.9,
)
ctx_low = ScoringContext(
    vuln_type="sql_injection",
    confidence=0.2,
)
sev1, score1, _ = score_finding(ctx_high)
sev2, score2, _ = score_finding(ctx_low)
assert score2 < score1, f"Low confidence should lower: {score2} vs {score1}"
print(f"  High confidence (0.9): score={score1}")
print(f"  Low confidence (0.2):  score={score2}")
print("  Test 12: PASS")
print()

# ──────────────────────────────────────────────────────
# Test 13: Batch scoring
# ──────────────────────────────────────────────────────
print("--- Test 13: Batch scoring ---")
findings = [
    {"vuln_type": "sql_injection", "confidence": 0.8, "taint_path": []},
    {"vuln_type": "command_injection", "confidence": 0.9, "taint_path": []},
    {"vuln_type": "file_upload", "confidence": 0.6, "taint_path": []},
    {"vuln_type": "broken_access", "confidence": 0.5, "taint_path": []},
    {"vuln_type": "sensitive_data", "confidence": 0.7, "taint_path": []},
]
findings = score_findings_batch(findings)
for f in findings:
    assert f["severity"] is not None
    assert f["cvss_score"] is not None
    assert f["cvss_vector"] is not None
    print(
        f"  {f['vuln_type']:20s} -> severity={f['severity']:8s} score={f['cvss_score']:4.1f} vector={f['cvss_vector']}"
    )

cmd_finding = next(f for f in findings if f["vuln_type"] == "command_injection")
assert cmd_finding["severity"] == "critical", (
    f"Expected critical for cmd injection, got {cmd_finding['severity']}"
)
print("  Batch scoring: all findings have severity + cvss_score + cvss_vector")
print("  Test 13: PASS")
print()

# ──────────────────────────────────────────────────────
# Test 14: Unknown vuln type -> default medium
# ──────────────────────────────────────────────────────
print("--- Test 14: Unknown vuln type ---")
ctx = ScoringContext(
    vuln_type="unknown_type",
    confidence=0.5,
)
severity, score, vector = score_finding(ctx)
assert severity in ("medium", "low"), (
    f"Expected medium or low for unknown, got {severity}"
)
print(f"  severity={severity}, score={score}, vector={vector}")
print("  Test 14: PASS")
print()

# ──────────────────────────────────────────────────────
# Test 15: XSS scoring (C:L/I:L = medium)
# ──────────────────────────────────────────────────────
print("--- Test 15: XSS scoring ---")
ctx = ScoringContext(
    vuln_type="xss",
    is_externally_reachable=True,
    requires_auth=False,
    confidence=0.6,
)
severity, score, vector = score_finding(ctx)
assert severity == "medium", f"Expected medium for XSS, got {severity}"
assert "UI:R" in vector, f"Expected UI:R for XSS, got {vector}"
print(f"  severity={severity}, score={score}, vector={vector}")
print("  Test 15: PASS")
print()

# ──────────────────────────────────────────────────────
# Test 16: Deserialization -> critical
# ──────────────────────────────────────────────────────
print("--- Test 16: Deserialization scoring ---")
ctx = ScoringContext(
    vuln_type="deserialization",
    is_externally_reachable=True,
    requires_auth=False,
    confidence=0.8,
)
severity, score, vector = score_finding(ctx)
assert severity == "critical", f"Expected critical for deserialization, got {severity}"
print(f"  severity={severity}, score={score}, vector={vector}")
print("  Test 16: PASS")
print()

# ──────────────────────────────────────────────────────
# Test 17: Integration with taint engine findings
# ──────────────────────────────────────────────────────
print("--- Test 17: Integration with taint engine findings ---")
from app.taint.facade import TaintFacade

flask_code = """from flask import Flask, request
app = Flask(__name__)

@app.route("/api/products")
def list_products():
    q = request.args.get("q")
    sql = "SELECT * FROM products WHERE name LIKE '%" + q + "%'"
    return db.session.execute(sql)
"""
findings = TaintFacade.analyze_code(flask_code, "app.py", "python", "flask")
assert len(findings) > 0

findings = score_findings_batch(findings)
for f in findings:
    assert f["status"] == "unverified", f"Expected unverified, got {f['status']}"
    assert f["severity"] in ("critical", "high", "medium", "low", "info")
    assert f["cvss_score"] >= 0.0
    assert f["cvss_vector"] is not None
    print(
        f"  {f['vuln_type']:20s} -> severity={f['severity']:8s} score={f['cvss_score']:4.1f} status={f['status']}"
    )
print("  Test 17: PASS")
print()

# ──────────────────────────────────────────────────────
# Test 18: File upload scoring
# ──────────────────────────────────────────────────────
print("--- Test 18: File upload scoring ---")
ctx = ScoringContext(
    vuln_type="file_upload",
    is_externally_reachable=True,
    requires_auth=True,
    confidence=0.7,
)
severity, score, vector = score_finding(ctx)
assert severity in ("critical", "high"), (
    f"Expected critical or high for file upload, got {severity}"
)
print(f"  severity={severity}, score={score}, vector={vector}")
print("  Test 18: PASS")
print()

# ──────────────────────────────────────────────────────
# Test 19: Sanitizer in taint_path detected by batch scoring
# ──────────────────────────────────────────────────────
print("--- Test 19: Sanitizer in taint_path detected by batch scoring ---")
findings_with_sanitizer = [
    {
        "vuln_type": "sql_injection",
        "confidence": 0.8,
        "taint_path": [
            {"type": "source", "code": 'q = request.args.get("q")'},
            {"type": "sanitizer", "code": "q = db.escape(q)"},
            {"type": "sink", "code": "execute(sql)"},
        ],
    }
]
findings_no_sanitizer = [
    {
        "vuln_type": "sql_injection",
        "confidence": 0.8,
        "taint_path": [
            {"type": "source", "code": 'q = request.args.get("q")'},
            {"type": "sink", "code": "execute(sql)"},
        ],
    }
]
scored_san = score_findings_batch(findings_with_sanitizer)
scored_no_san = score_findings_batch(findings_no_sanitizer)
assert scored_san[0]["cvss_score"] < scored_no_san[0]["cvss_score"], (
    f"Sanitizer in taint_path should lower score: {scored_san[0]['cvss_score']} vs {scored_no_san[0]['cvss_score']}"
)
print(f"  Without sanitizer in path: score={scored_no_san[0]['cvss_score']}")
print(f"  With sanitizer in path:   score={scored_san[0]['cvss_score']}")
print("  Test 19: PASS")
print()

print("=== ALL CVSS SCORING TESTS PASSED (19/19) ===")
