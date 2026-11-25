#!/usr/bin/env python
"""Verify Finding schemas with full object construction."""

import sys

sys.path.insert(0, "E:/xuexi/AnQuan/AnQuanPingGu/backend")

from app.schemas.finding import (
    FindingResponse,
    FindingSummaryResponse,
    FindingListResponse,
    TaintStep,
    FindingUpdateRequest,
    FindingFilterParams,
)
from app.enums import FindingStatus, Severity, VulnerabilityType

print("=== Finding Schema Verification ===")
print()

# Test 1: TaintStep
step = TaintStep(
    step=1,
    type="source",
    file="app.py",
    line=12,
    code='q = request.args.get("q")',
    detail="HTTP parameter",
)
assert step.step == 1
assert step.type == "source"
print("TaintStep: OK")

# Test 2: FindingResponse with all fields
finding = FindingResponse(
    id="01JBKP7V2E3K0X1Y2Z",
    task_id="01JBKP7V2E3K0X1Y2ZTASK",
    vuln_type="sql_injection",
    cwe_id="CWE-89",
    owasp="A03:2021",
    status="unverified",
    severity="high",
    cvss_score=8.6,
    cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    file_path="app.py",
    line_start=12,
    line_end=14,
    snippet='sql = "SELECT * FROM products WHERE name LIKE \'%" + q + "%\'"',
    source_file="app.py",
    source_line=12,
    source_code='q = request.args.get("q")',
    sink_file="app.py",
    sink_line=13,
    sink_code="db.session.execute(sql)",
    taint_path=[
        {
            "step": 1,
            "type": "source",
            "file": "app.py",
            "line": 12,
            "code": 'q = request.args.get("q")',
            "detail": "HTTP param",
        },
        {
            "step": 2,
            "type": "transfer",
            "file": "app.py",
            "line": 13,
            "code": 'sql = "..." + q + "..."',
            "detail": "String concat",
        },
        {
            "step": 3,
            "type": "sink",
            "file": "app.py",
            "line": 14,
            "code": "db.session.execute(sql)",
            "detail": "SQL execute",
        },
    ],
    detected_by="taint_engine",
    confidence=0.85,
    remediation="Use parameterized queries",
)
assert finding.status == "unverified"
assert finding.cwe_id == "CWE-89"
assert finding.owasp == "A03:2021"
assert finding.severity == "high"
assert finding.cvss_score == 8.6
assert finding.file_path == "app.py"
assert finding.line_start == 12
assert finding.line_end == 14
assert len(finding.taint_path) == 3
assert finding.taint_path[0]["type"] == "source"
assert finding.taint_path[2]["type"] == "sink"
print("FindingResponse (full): OK")

# Test 3: FindingResponse with minimal fields (unknown project, no vuln)
finding_empty = FindingResponse(
    id="01JBKP7V2E3K0X1Y2Z2",
    task_id="01JBKP7V2E3K0X1Y2ZTASK",
    vuln_type="other",
    status="unverified",
    severity="info",
)
assert finding_empty.snippet is None
assert finding_empty.taint_path is None
assert finding_empty.file_path is None
print("FindingResponse (minimal): OK")

# Test 4: FindingListResponse
findings_list = FindingListResponse(
    items=[finding, finding_empty],
    total=2,
    verified_count=0,
    unverified_count=2,
)
assert findings_list.total == 2
assert findings_list.unverified_count == 2
assert findings_list.verified_count == 0
print("FindingListResponse: OK")

# Test 5: FindingSummaryResponse
summary = FindingSummaryResponse(
    total=5,
    by_severity={"critical": 1, "high": 2, "medium": 1, "low": 1, "info": 0},
    by_status={"unverified": 5, "verified": 0, "latent": 0, "false_positive": 0},
    by_type={
        "sql_injection": 2,
        "command_injection": 1,
        "sensitive_data": 1,
        "broken_access": 1,
    },
)
assert summary.total == 5
assert summary.by_severity["critical"] == 1
assert summary.by_status["unverified"] == 5
assert summary.by_type["sql_injection"] == 2
print("FindingSummaryResponse: OK")

# Test 6: FindingUpdateRequest
update_req = FindingUpdateRequest(
    status="false_positive", false_positive_reason="Sanitized input"
)
assert update_req.status == "false_positive"
print("FindingUpdateRequest: OK")

# Test 7: FindingFilterParams
filter_params = FindingFilterParams(severity="high", status="unverified")
assert filter_params.severity == "high"
print("FindingFilterParams: OK")

# Test 8: Enums
assert FindingStatus.UNVERIFIED.value == "unverified"
assert Severity.HIGH.value == "high"
assert VulnerabilityType.SQL_INJECTION.value == "sql_injection"
print("Enums: OK")

print()
print("ALL SCHEMA TESTS PASSED (8/8)")
