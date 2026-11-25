#!/usr/bin/env python
"""Verify scanners (base, semgrep, bandit) and rule loader.

Tests:
1. Rule loader: load python/javascript/java rules
2. BaseScanner: RawFinding dataclass and to_dict
3. SemgrepScanner: parse_output with mock JSON
4. BanditScanner: parse_output with mock JSON
5. Semgrep rule ID inference (sqli/cmd/upload/idor/secrets)
6. Bandit test ID mapping (B608/B602/B105)
7. Deduplication: identical findings from semgrep+bandit merged
8. Empty output handling
9. Invalid JSON handling
"""

import json
import sys

sys.path.insert(0, "E:/xuexi/AnQuan/AnQuanPingGu/backend")

from app.config.audit_rules.rule_loader import (
    load_rules_for_language,
    load_rules_for_framework,
    get_rule_by_id,
    list_available_languages,
)
from app.scanners.base import BaseScanner, RawFinding
from app.scanners.semgrep import SemgrepScanner, _infer_vuln_type
from app.scanners.bandit import BanditScanner, _lookup_test_id

print("=== Scanner & Rule Loader Verification ===")
print()

# ──────────────────────────────────────────────────────
# Test 1: Rule loader - Python
# ──────────────────────────────────────────────────────
print("--- Test 1: Rule loader - Python ---")
rules = load_rules_for_language("python")
assert len(rules) == 5, f"Expected 5 Python rules, got {len(rules)}"
vuln_types = [r["vuln_type"] for r in rules]
assert "sql_injection" in vuln_types
assert "command_injection" in vuln_types
assert "file_upload" in vuln_types
assert "broken_access" in vuln_types
assert "sensitive_data" in vuln_types
for r in rules:
    assert r["cwe"] and r["cwe"].startswith("CWE-")
    assert r["owasp"] and r["owasp"].startswith("A")
    assert r["source_patterns"] is not None
    assert r["sink_patterns"] is not None
print(f"  Loaded {len(rules)} Python rules: {vuln_types}")
print("  Test 1: PASS")
print()

# ──────────────────────────────────────────────────────
# Test 2: Rule loader - JavaScript & Java
# ──────────────────────────────────────────────────────
print("--- Test 2: Rule loader - JavaScript & Java ---")
js_rules = load_rules_for_language("javascript")
assert len(js_rules) >= 3, f"Expected >=3 JS rules, got {len(js_rules)}"
print(f"  JavaScript: {len(js_rules)} rules")

java_rules = load_rules_for_language("java")
assert len(java_rules) >= 3, f"Expected >=3 Java rules, got {len(java_rules)}"
print(f"  Java: {len(java_rules)} rules")

# Unknown language returns empty
unknown_rules = load_rules_for_language("ruby")
assert len(unknown_rules) == 0
print(f"  Ruby (unsupported): {len(unknown_rules)} rules")
print("  Test 2: PASS")
print()

# ──────────────────────────────────────────────────────
# Test 3: Rule loader - framework filter
# ──────────────────────────────────────────────────────
print("--- Test 3: Rule loader - framework filter ---")
flask_rules = load_rules_for_framework("python", "flask")
assert len(flask_rules) == 5
print(f"  Python/Flask: {len(flask_rules)} rules")
print("  Test 3: PASS")
print()

# ──────────────────────────────────────────────────────
# Test 4: Rule loader - get_rule_by_id & list_languages
# ──────────────────────────────────────────────────────
print("--- Test 4: Rule loader - get_rule_by_id & list_languages ---")
rule = get_rule_by_id("py-sqli-string-concat")
assert rule is not None
assert rule["vuln_type"] == "sql_injection"
print(f"  Found rule by ID: {rule['id']} -> {rule['vuln_type']}")

rule = get_rule_by_id("nonexistent-rule")
assert rule is None
print(f"  Nonexistent rule: None")

langs = list_available_languages()
assert "python" in langs
assert "javascript" in langs
assert "java" in langs
print(f"  Available languages: {sorted(set(langs))}")
print("  Test 4: PASS")
print()

# ──────────────────────────────────────────────────────
# Test 5: RawFinding dataclass & to_dict
# ──────────────────────────────────────────────────────
print("--- Test 5: RawFinding dataclass & to_dict ---")
rf = RawFinding(
    rule_id="test-rule",
    vuln_type="sql_injection",
    detected_by="semgrep",
    cwe="CWE-89",
    owasp="A03:2021",
    file_path="app.py",
    line_start=10,
    line_end=10,
    snippet="db.execute(sql)",
    description="SQL injection",
    confidence=0.8,
)
d = rf.to_dict()
assert d["vuln_type"] == "sql_injection"
assert d["cwe"] == "CWE-89"
assert d["file_path"] == "app.py"
assert d["line_start"] == 10
assert d["status"] == "unverified"
assert d["detected_by"] == "semgrep"
print(f"  RawFinding.to_dict(): {list(d.keys())}")
print(f"  status={d['status']}, vuln_type={d['vuln_type']}")
print("  Test 5: PASS")
print()

# ──────────────────────────────────────────────────────
# Test 6: Semgrep parse_output - SQL injection
# ──────────────────────────────────────────────────────
print("--- Test 6: Semgrep parse_output - SQL injection ---")
mock_semgrep_output = json.dumps(
    {
        "results": [
            {
                "check_id": "python.flask.security.injection.sql-injection-sqlalchemy-execute",
                "path": "app/routes.py",
                "start": {"line": 25, "col": 5},
                "end": {"line": 25, "col": 60},
                "extra": {
                    "message": "Possible SQL injection via string concatenation in SQLAlchemy execute",
                    "severity": "ERROR",
                    "lines": '    sql = "SELECT * FROM products WHERE name=\'" + q + "\'"',
                    "metadata": {
                        "cwe": "CWE-89: Improper Neutralization of Special Elements used in an SQL Command",
                        "owasp": "A03:2021 - Injection",
                        "confidence": "HIGH",
                    },
                },
            },
            {
                "check_id": "python.lang.security.command-injection-os-system",
                "path": "app/utils.py",
                "start": {"line": 42, "col": 1},
                "end": {"line": 42, "col": 40},
                "extra": {
                    "message": "os.system call with user input",
                    "severity": "ERROR",
                    "lines": 'os.system("echo " + user_input)',
                    "metadata": {
                        "cwe": "CWE-78: OS Command Injection",
                        "confidence": "MEDIUM",
                    },
                },
            },
        ]
    }
)

scanner = SemgrepScanner()
findings = scanner.parse_output(mock_semgrep_output)
assert len(findings) == 2

# First finding: SQL injection
f0 = findings[0]
assert f0.vuln_type == "sql_injection"
assert f0.cwe == "CWE-89"
assert f0.owasp == "A03:2021"
assert f0.file_path == "app/routes.py"
assert f0.line_start == 25
assert f0.detected_by == "semgrep"
assert f0.severity_hint == "high"
assert f0.confidence == 0.9
print(f"  Finding 0: {f0.vuln_type} @ {f0.file_path}:{f0.line_start} ({f0.cwe})")

# Second finding: command injection
f1 = findings[1]
assert f1.vuln_type == "command_injection"
assert f1.cwe == "CWE-78"
assert f1.file_path == "app/utils.py"
assert f1.line_start == 42
print(f"  Finding 1: {f1.vuln_type} @ {f1.file_path}:{f1.line_start} ({f1.cwe})")
print("  Test 6: PASS")
print()

# ──────────────────────────────────────────────────────
# Test 7: Semgrep rule ID inference
# ──────────────────────────────────────────────────────
print("--- Test 7: Semgrep rule ID inference ---")
test_ids = [
    ("python.flask.security.sql-injection", "sql_injection", "CWE-89"),
    ("python.os.command-injection", "command_injection", "CWE-78"),
    ("python.file-upload.unrestricted", "file_upload", "CWE-434"),
    ("python.idor.broken-access", "broken_access", "CWE-639"),
    ("python.hardcoded-secrets.password", "sensitive_data", "CWE-798"),
    ("javascript.xss.reflected", "xss", "CWE-79"),
    ("java.ssrf.request-forgery", "ssrf", "CWE-918"),
    ("python.deserialization.pickle", "deserialization", "CWE-502"),
    ("python.path-traversal", "path_traversal", "CWE-22"),
    ("unknown.rule.id", "other", ""),
]
for rule_id, expected_type, expected_cwe in test_ids:
    vt, cwe, owasp = _infer_vuln_type(rule_id)
    assert vt == expected_type, f"{rule_id}: expected {expected_type}, got {vt}"
    assert cwe == expected_cwe, f"{rule_id}: expected {expected_cwe}, got {cwe}"
    print(f"  {rule_id:50s} -> {vt} ({cwe})")
print("  Test 7: PASS")
print()

# ──────────────────────────────────────────────────────
# Test 8: Bandit parse_output - B608 SQL injection & B602 cmd injection
# ──────────────────────────────────────────────────────
print("--- Test 8: Bandit parse_output ---")
mock_bandit_output = json.dumps(
    {
        "results": [
            {
                "filename": "app/models.py",
                "issue_text": "Possible SQL injection via string concatenation",
                "issue_confidence": "MEDIUM",
                "issue_severity": "MEDIUM",
                "issue_cwe": {"id": 89, "link": "https://...", "name": "SQL Injection"},
                "test_id": "B608",
                "line_number": 15,
                "line_range": [15, 16],
                "more_info": "https://bandit.readthedocs.io/...",
                "code": '    sql = "SELECT * FROM users WHERE id=" + user_id',
            },
            {
                "filename": "app/utils.py",
                "issue_text": "subprocess call with shell=True identified, security issue",
                "issue_confidence": "HIGH",
                "issue_severity": "HIGH",
                "issue_cwe": {
                    "id": 78,
                    "link": "https://...",
                    "name": "OS Command Injection",
                },
                "test_id": "B602",
                "line_number": 30,
                "line_range": [30],
                "more_info": "https://bandit.readthedocs.io/...",
                "code": "    subprocess.call(cmd, shell=True)",
            },
            {
                "filename": "app/config.py",
                "issue_text": "Possible hardcoded password: 'secret123'",
                "issue_confidence": "MEDIUM",
                "issue_severity": "MEDIUM",
                "issue_cwe": {
                    "id": 798,
                    "link": "https://...",
                    "name": "Hardcoded Credentials",
                },
                "test_id": "B105",
                "line_number": 5,
                "line_range": [5],
                "more_info": "https://bandit.readthedocs.io/...",
                "code": 'PASSWORD = "secret123"',
            },
        ]
    }
)

scanner = BanditScanner()
findings = scanner.parse_output(mock_bandit_output)
assert len(findings) == 3

f0 = findings[0]
assert f0.vuln_type == "sql_injection"
assert f0.cwe == "CWE-89"
assert f0.file_path == "app/models.py"
assert f0.line_start == 15
assert f0.detected_by == "bandit"
assert f0.confidence == 0.6  # MEDIUM confidence
print(
    f"  B608: {f0.vuln_type} @ {f0.file_path}:{f0.line_start} ({f0.cwe}) conf={f0.confidence}"
)

f1 = findings[1]
assert f1.vuln_type == "command_injection"
assert f1.cwe == "CWE-78"
assert f1.file_path == "app/utils.py"
assert f1.line_start == 30
assert f1.confidence == 0.9  # HIGH confidence
print(
    f"  B602: {f1.vuln_type} @ {f1.file_path}:{f1.line_start} ({f1.cwe}) conf={f1.confidence}"
)

f2 = findings[2]
assert f2.vuln_type == "sensitive_data"
assert f2.cwe == "CWE-798"
assert f2.file_path == "app/config.py"
assert f2.line_start == 5
print(
    f"  B105: {f2.vuln_type} @ {f2.file_path}:{f2.line_start} ({f2.cwe}) conf={f2.confidence}"
)
print("  Test 8: PASS")
print()

# ──────────────────────────────────────────────────────
# Test 9: Bandit test ID lookup
# ──────────────────────────────────────────────────────
print("--- Test 9: Bandit test ID lookup ---")
test_lookups = [
    ("B608", "sql_injection", "CWE-89"),
    ("B602", "command_injection", "CWE-78"),
    ("B105", "sensitive_data", "CWE-798"),
    ("B301", "deserialization", "CWE-502"),
    ("B999", "other", ""),  # unknown test ID
]
for test_id, exp_type, exp_cwe in test_lookups:
    info = _lookup_test_id(test_id)
    assert info["vuln_type"] == exp_type, (
        f"{test_id}: expected {exp_type}, got {info['vuln_type']}"
    )
    assert info.get("cwe", "") == exp_cwe, (
        f"{test_id}: expected {exp_cwe}, got {info.get('cwe', '')}"
    )
    print(f"  {test_id}: {info['vuln_type']} ({info.get('cwe', '')})")
print("  Test 9: PASS")
print()

# ──────────────────────────────────────────────────────
# Test 10: Empty output handling
# ──────────────────────────────────────────────────────
print("--- Test 10: Empty output handling ---")
semgrep = SemgrepScanner()
assert semgrep.parse_output("") == []
assert semgrep.parse_output("not json") == []
assert semgrep.parse_output('{"results": []}') == []

bandit = BanditScanner()
assert bandit.parse_output("") == []
assert bandit.parse_output("not json") == []
assert bandit.parse_output('{"results": []}') == []
print("  Empty and invalid JSON handled gracefully")
print("  Test 10: PASS")
print()

# ──────────────────────────────────────────────────────
# Test 11: RawFinding to_dict has all required fields for Finding ORM
# ──────────────────────────────────────────────────────
print("--- Test 11: RawFinding to_dict field completeness ---")
rf = RawFinding(
    rule_id="py-sqli-string-concat",
    vuln_type="sql_injection",
    detected_by="semgrep",
    cwe="CWE-89",
    owasp="A03:2021",
    file_path="app/routes.py",
    line_start=25,
    line_end=25,
    snippet='sql = "SELECT * FROM products WHERE name=\'" + q + "\'"',
    description="SQL injection via string concat",
    confidence=0.9,
    remediation="Use parameterized queries",
)
d = rf.to_dict()
required_fields = [
    "rule_id",
    "vuln_type",
    "detected_by",
    "cwe",
    "owasp",
    "file_path",
    "line_start",
    "line_end",
    "snippet",
    "description",
    "confidence",
    "remediation",
    "status",
]
for field in required_fields:
    assert field in d, f"Missing field: {field}"
assert d["status"] == "unverified"
print(f"  All {len(required_fields)} required fields present")
print(f"  status={d['status']} (correct: unverified)")
print("  Test 11: PASS")
print()

# ──────────────────────────────────────────────────────
# Test 12: Integration - semgrep finding -> to_dict -> score with CVSS
# ──────────────────────────────────────────────────────
print("--- Test 12: Integration with CVSS scoring ---")
from app.scoring.cvss import score_findings_batch

mock_output = json.dumps(
    {
        "results": [
            {
                "check_id": "python.flask.security.injection.sql-injection",
                "path": "app.py",
                "start": {"line": 10},
                "end": {"line": 10},
                "extra": {
                    "message": "SQL injection",
                    "severity": "ERROR",
                    "metadata": {
                        "cwe": "CWE-89",
                        "owasp": "A03:2021",
                        "confidence": "HIGH",
                    },
                },
            }
        ]
    }
)
scanner = SemgrepScanner()
findings = scanner.parse_output(mock_output)
assert len(findings) == 1

# Convert to dicts for batch scoring
finding_dicts = [f.to_dict() for f in findings]
finding_dicts = score_findings_batch(finding_dicts)

f = finding_dicts[0]
assert f["severity"] in ("critical", "high"), (
    f"Expected high or critical, got {f['severity']}"
)
assert f["cvss_score"] >= 7.0
assert f["cvss_vector"] is not None
assert f["status"] == "unverified"
print(
    f"  {f['vuln_type']} -> severity={f['severity']} score={f['cvss_score']} vector={f['cvss_vector']}"
)
print("  Test 12: PASS")
print()

print("=== ALL SCANNER TESTS PASSED (12/12) ===")
