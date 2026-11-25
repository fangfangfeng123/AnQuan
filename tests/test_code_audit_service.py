#!/usr/bin/env python
"""Verify code_audit_service and finding_service - merge logic and CVSS integration.

Tests:
1. _merge_findings: scanner + taint results merge correctly
2. _merge_single: field priority (taint provides Source/Sink, scanner provides CWE)
3. _deduplicate_raw_findings: duplicates removed
4. score_findings_batch: batch scoring adds severity/cvss_score/cvss_vector
5. TaintFacade.results_to_findings: produces valid finding dicts
6. RawFinding.to_dict: all required fields present
7. End-to-end merge + score: merged findings get CVSS scores
8. Finding dict completeness: all Finding model fields present
"""

import sys
import json

sys.path.insert(0, "E:/xuexi/AnQuan/AnQuanPingGu/backend")

from app.scanners.base import RawFinding
from app.scoring.cvss import score_findings_batch, ScoringContext, score_finding
from app.taint.facade import TaintFacade
from app.services.code_audit_service import (
    _merge_findings,
    _merge_single,
    _deduplicate_raw_findings,
)

passed = 0
failed = 0


def check(name, condition, detail=""):
    global passed, failed
    if condition:
        passed += 1
        print(f"  {name}: PASS")
    else:
        failed += 1
        print(f"  {name}: FAIL - {detail}")


print("=== Code Audit Service + Finding Service Verification ===")
print()

# ── Test 1: _merge_findings - scanner + taint merge ──
print("--- Test 1: _merge_findings (scanner + taint merge) ---")

scanner_findings = [
    {
        "vuln_type": "sql_injection",
        "cwe": "CWE-89",
        "owasp": "A03:2021",
        "file_path": "app.py",
        "line_start": 10,
        "line_end": 10,
        "snippet": "cursor.execute(sql)",
        "detected_by": "semgrep",
        "confidence": 0.9,
        "status": "unverified",
        "source_code": None,
        "sink_code": None,
        "taint_path": None,
    },
    {
        "vuln_type": "command_injection",
        "cwe": "CWE-78",
        "owasp": "A03:2021",
        "file_path": "utils.py",
        "line_start": 5,
        "line_end": 5,
        "snippet": "os.system(cmd)",
        "detected_by": "bandit",
        "confidence": 0.6,
        "status": "unverified",
        "source_code": None,
        "sink_code": None,
        "taint_path": None,
    },
]

taint_findings = [
    {
        "vuln_type": "sql_injection",
        "cwe_id": "CWE-89",
        "owasp": "A03:2021",
        "file_path": "app.py",
        "line_start": 10,
        "line_end": 10,
        "source_file": "app.py",
        "source_line": 8,
        "source_code": "name = request.args.get('name')",
        "sink_file": "app.py",
        "sink_line": 10,
        "sink_code": "cursor.execute(sql)",
        "taint_path": [
            {
                "step": 1,
                "type": "source",
                "file": "app.py",
                "line": 8,
                "code": "name = request.args.get('name')",
                "detail": "",
            },
            {
                "step": 2,
                "type": "transfer",
                "file": "app.py",
                "line": 9,
                "code": "sql = f\"SELECT * FROM users WHERE name='{name}'\"",
                "detail": "",
            },
            {
                "step": 3,
                "type": "sink",
                "file": "app.py",
                "line": 10,
                "code": "cursor.execute(sql)",
                "detail": "",
            },
        ],
        "detected_by": "taint_engine",
        "confidence": 0.8,
        "status": "unverified",
    },
    {
        "vuln_type": "sensitive_data",
        "cwe_id": "CWE-798",
        "owasp": "A02:2021",
        "file_path": "config.py",
        "line_start": 3,
        "line_end": 3,
        "source_code": None,
        "sink_code": 'SECRET_KEY = "hardcoded-secret"',
        "taint_path": [],
        "detected_by": "taint_engine",
        "confidence": 0.7,
        "status": "unverified",
    },
]

merged = _merge_findings(scanner_findings, taint_findings)

# Should have 3 findings (2 scanner + 1 taint-only)
check("merged count", len(merged) == 3, f"expected 3, got {len(merged)}")

# The SQL injection finding should have Source/Sink from taint
sql_finding = [f for f in merged if f.get("vuln_type") == "sql_injection"][0]
check(
    "sql has source_code",
    sql_finding.get("source_code") is not None,
    "source_code is None",
)
check(
    "sql has sink_code", sql_finding.get("sink_code") is not None, "sink_code is None"
)
check(
    "sql has taint_path",
    sql_finding.get("taint_path") is not None and len(sql_finding["taint_path"]) == 3,
    f"taint_path len = {len(sql_finding.get('taint_path') or [])}",
)
check(
    "sql detected_by merged",
    "+" in sql_finding.get("detected_by", ""),
    f"detected_by = {sql_finding.get('detected_by')}",
)
check(
    "sql confidence max",
    sql_finding.get("confidence") == 0.9,
    f"confidence = {sql_finding.get('confidence')}",
)

# Command injection (scanner-only) should not have Source/Sink
cmd_finding = [f for f in merged if f.get("vuln_type") == "command_injection"][0]
check(
    "cmd no source_code",
    cmd_finding.get("source_code") is None,
    f"source_code = {cmd_finding.get('source_code')}",
)
check(
    "cmd detected_by bandit",
    cmd_finding.get("detected_by") == "bandit",
    f"detected_by = {cmd_finding.get('detected_by')}",
)

# Sensitive data (taint-only) should be present
sensitive_finding = [f for f in merged if f.get("vuln_type") == "sensitive_data"]
check(
    "sensitive data present",
    len(sensitive_finding) == 1,
    f"count = {len(sensitive_finding)}",
)

print()

# ── Test 2: _merge_single field priority ──
print("--- Test 2: _merge_single (field priority) ---")

scanner_f = {
    "vuln_type": "sql_injection",
    "cwe": "CWE-89",
    "owasp": "A03:2021",
    "file_path": "app.py",
    "line_start": 10,
    "detected_by": "semgrep",
    "confidence": 0.9,
    "snippet": "cursor.execute(sql)",
    "source_code": None,
    "sink_code": None,
    "taint_path": None,
    "status": "unverified",
}

taint_f = {
    "vuln_type": "sql_injection",
    "cwe": "CWE-89",
    "owasp": "A03:2021",
    "file_path": "app.py",
    "line_start": 10,
    "detected_by": "taint_engine",
    "confidence": 0.7,
    "source_code": "name = request.args.get('name')",
    "sink_code": "cursor.execute(sql)",
    "taint_path": [
        {
            "step": 1,
            "type": "source",
            "file": "app.py",
            "line": 8,
            "code": "",
            "detail": "",
        }
    ],
    "status": "unverified",
}

merged_single = _merge_single(scanner_f, taint_f)

check(
    "source from taint",
    merged_single["source_code"] == "name = request.args.get('name')",
    merged_single.get("source_code"),
)
check(
    "sink from taint",
    merged_single["sink_code"] == "cursor.execute(sql)",
    merged_single.get("sink_code"),
)
check(
    "taint_path from taint",
    len(merged_single["taint_path"]) == 1,
    f"len = {len(merged_single.get('taint_path') or [])}",
)
check(
    "detected_by merged",
    merged_single["detected_by"] == "semgrep+taint_engine",
    merged_single.get("detected_by"),
)
check(
    "confidence max",
    merged_single["confidence"] == 0.9,
    f"confidence = {merged_single.get('confidence')}",
)
check("cwe from scanner", merged_single["cwe"] == "CWE-89", merged_single.get("cwe"))
check(
    "status unverified",
    merged_single["status"] == "unverified",
    merged_single.get("status"),
)

print()

# ── Test 3: _deduplicate_raw_findings ──
print("--- Test 3: _deduplicate_raw_findings ---")

raw_findings = [
    RawFinding(
        rule_id="semgrep-sqli-1",
        vuln_type="sql_injection",
        detected_by="semgrep",
        cwe="CWE-89",
        owasp="A03:2021",
        file_path="app.py",
        line_start=10,
        line_end=10,
        snippet="cursor.execute(sql)",
        confidence=0.9,
    ),
    RawFinding(
        rule_id="semgrep-sqli-1",
        vuln_type="sql_injection",
        detected_by="semgrep",
        cwe="CWE-89",
        owasp="A03:2021",
        file_path="app.py",
        line_start=10,
        line_end=10,
        snippet="cursor.execute(sql)",
        confidence=0.9,
    ),
    RawFinding(
        rule_id="bandit-B608",
        vuln_type="sql_injection",
        detected_by="bandit",
        cwe="CWE-89",
        owasp="A03:2021",
        file_path="app.py",
        line_start=10,
        line_end=10,
        snippet="cursor.execute(sql)",
        confidence=0.6,
    ),
    RawFinding(
        rule_id="semgrep-cmd-1",
        vuln_type="command_injection",
        detected_by="semgrep",
        cwe="CWE-78",
        owasp="A03:2021",
        file_path="utils.py",
        line_start=5,
        line_end=5,
        snippet="os.system(cmd)",
        confidence=0.8,
    ),
]

deduped = _deduplicate_raw_findings(raw_findings)
check(
    "dedup count",
    len(deduped) == 3,
    f"expected 3 (2 semgrep + 1 bandit), got {len(deduped)}",
)
check(
    "first is semgrep sqli",
    deduped[0].detected_by == "semgrep" and deduped[0].vuln_type == "sql_injection",
    f"{deduped[0].detected_by} {deduped[0].vuln_type}",
)
check(
    "second is bandit sqli",
    deduped[1].detected_by == "bandit" and deduped[1].vuln_type == "sql_injection",
    f"{deduped[1].detected_by} {deduped[1].vuln_type}",
)

print()

# ── Test 4: score_findings_batch on merged findings ──
print("--- Test 4: score_findings_batch on merged findings ---")

test_findings = [
    {
        "vuln_type": "sql_injection",
        "confidence": 0.9,
        "taint_path": [
            {
                "step": 1,
                "type": "source",
                "file": "app.py",
                "line": 8,
                "code": "",
                "detail": "",
            },
            {
                "step": 2,
                "type": "sink",
                "file": "app.py",
                "line": 10,
                "code": "",
                "detail": "",
            },
        ],
    },
    {
        "vuln_type": "command_injection",
        "confidence": 0.8,
        "taint_path": [],
    },
    {
        "vuln_type": "broken_access",
        "confidence": 0.6,
        "taint_path": [],
    },
    {
        "vuln_type": "sensitive_data",
        "confidence": 0.7,
        "taint_path": [],
    },
    {
        "vuln_type": "file_upload",
        "confidence": 0.5,
        "taint_path": [],
    },
]

scored = score_findings_batch(test_findings)

all_scored = all(
    f.get("severity") is not None
    and f.get("cvss_score") is not None
    and f.get("cvss_vector") is not None
    for f in scored
)
check("all have severity+score+vector", all_scored, "missing fields")

# SQL injection should be critical (9.8)
sql = [f for f in scored if f["vuln_type"] == "sql_injection"][0]
check(
    "sql_injection critical",
    sql["severity"] == "critical" and sql["cvss_score"] == 9.8,
    f"severity={sql['severity']}, score={sql['cvss_score']}",
)

# Command injection should be critical (9.8)
cmd = [f for f in scored if f["vuln_type"] == "command_injection"][0]
check(
    "command_injection critical",
    cmd["severity"] == "critical" and cmd["cvss_score"] == 9.8,
    f"severity={cmd['severity']}, score={cmd['cvss_score']}",
)

# IDOR should be high (7.1)
idor = [f for f in scored if f["vuln_type"] == "broken_access"][0]
check(
    "broken_access high",
    idor["severity"] == "high" and idor["cvss_score"] == 7.1,
    f"severity={idor['severity']}, score={idor['cvss_score']}",
)

print()

# ── Test 5: TaintFacade full pipeline ──
print("--- Test 5: TaintFacade full pipeline ---")

# SQL injection code
sql_code = """
from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route('/search')
def search():
    name = request.args.get('name')
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    sql = f"SELECT * FROM users WHERE name='{name}'"
    cursor.execute(sql)
    results = cursor.fetchall()
    return str(results)
"""

findings = TaintFacade.analyze_code(sql_code, "app.py", "python", "flask")
check("taint finds sql_injection", len(findings) > 0, f"found {len(findings)}")
if findings:
    f = findings[0]
    check(
        "finding has vuln_type",
        f.get("vuln_type") == "sql_injection",
        f"vuln_type={f.get('vuln_type')}",
    )
    check(
        "finding has source_code",
        f.get("source_code") is not None,
        "source_code is None",
    )
    check("finding has sink_code", f.get("sink_code") is not None, "sink_code is None")
    check(
        "finding has taint_path",
        f.get("taint_path") is not None and len(f["taint_path"]) >= 2,
        f"taint_path len={len(f.get('taint_path') or [])}",
    )
    check(
        "finding status unverified",
        f.get("status") == "unverified",
        f"status={f.get('status')}",
    )

print()

# ── Test 6: RawFinding.to_dict completeness ──
print("--- Test 6: RawFinding.to_dict completeness ---")

raw = RawFinding(
    rule_id="semgrep-sqli-1",
    vuln_type="sql_injection",
    detected_by="semgrep",
    cwe="CWE-89",
    owasp="A03:2021",
    file_path="app.py",
    line_start=10,
    line_end=10,
    snippet="cursor.execute(sql)",
    description="Possible SQL injection",
    severity_hint="high",
    confidence=0.9,
    remediation="Use parameterized queries",
)

raw_dict = raw.to_dict()

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
    "severity_hint",
    "confidence",
    "remediation",
    "extra",
    "status",
]

all_present = all(field in raw_dict for field in required_fields)
check(
    "all required fields present",
    all_present,
    f"missing: {[f for f in required_fields if f not in raw_dict]}",
)
check(
    "status is unverified",
    raw_dict["status"] == "unverified",
    f"status={raw_dict['status']}",
)

print()

# ── Test 7: End-to-end merge + score ──
print("--- Test 7: End-to-end merge + score ---")

# First run taint analysis to get the actual sink line number
_taint_pre = TaintFacade.analyze_code(sql_code, "app.py", "python", "flask")
_sink_line = 13  # default
for _tf in _taint_pre:
    if _tf.get("vuln_type") == "sql_injection" and _tf.get("sink_code", "").startswith(
        "cursor.execute"
    ):
        _sink_line = _tf.get("line_start", 13)
        break

# Simulate scanner findings at the same line the taint engine identifies
scanner_results = [
    RawFinding(
        rule_id="semgrep-sqli",
        vuln_type="sql_injection",
        detected_by="semgrep",
        cwe="CWE-89",
        owasp="A03:2021",
        file_path="app.py",
        line_start=_sink_line,
        line_end=_sink_line,
        snippet="cursor.execute(sql)",
        confidence=0.9,
    ).to_dict(),
]

# Simulate taint findings
taint_results = TaintFacade.analyze_code(sql_code, "app.py", "python", "flask")

# Merge
final_merged = _merge_findings(scanner_results, taint_results)

# Score
score_findings_batch(final_merged)

check("e2e merged count", len(final_merged) >= 1, f"count={len(final_merged)}")

if final_merged:
    final = final_merged[0]
    check(
        "e2e has severity",
        "severity" in final and final["severity"] is not None,
        f"severity={final.get('severity')}",
    )
    check(
        "e2e has cvss_score",
        "cvss_score" in final and final["cvss_score"] is not None,
        f"cvss_score={final.get('cvss_score')}",
    )
    check(
        "e2e has cvss_vector",
        "cvss_vector" in final and final["cvss_vector"] is not None,
        f"cvss_vector={final.get('cvss_vector')}",
    )
    check(
        "e2e has source_code",
        final.get("source_code") is not None,
        "source_code is None",
    )
    check("e2e has sink_code", final.get("sink_code") is not None, "sink_code is None")
    check(
        "e2e has taint_path",
        final.get("taint_path") is not None and len(final["taint_path"]) >= 2,
        f"taint_path len={len(final.get('taint_path') or [])}",
    )
    check(
        "e2e detected_by merged",
        "+" in final.get("detected_by", ""),
        f"detected_by={final.get('detected_by')}",
    )
    check(
        "e2e status unverified",
        final.get("status") == "unverified",
        f"status={final.get('status')}",
    )

print()

# ── Test 8: Finding dict has all Finding model fields ──
print("--- Test 8: Finding dict completeness ---")

# After merge + score, the finding dict should have all fields needed by finding_service
finding_model_fields = [
    "vuln_type",
    "cwe",
    "owasp",
    "status",
    "severity",
    "cvss_score",
    "cvss_vector",
    "file_path",
    "line_start",
    "line_end",
    "snippet",
    "source_file",
    "source_line",
    "source_code",
    "sink_file",
    "sink_line",
    "sink_code",
    "taint_path",
    "detected_by",
    "confidence",
]

if final_merged:
    f = final_merged[0]
    missing = [field for field in finding_model_fields if field not in f]
    check("all Finding model fields present", len(missing) == 0, f"missing: {missing}")

print()
print(f"=== CODE AUDIT SERVICE TESTS: {passed} passed, {failed} failed ===")
if failed > 0:
    sys.exit(1)
print("ALL TESTS PASSED")
