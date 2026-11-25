"""PoC 验证模块单元测试。

测试覆盖：
1. payloads.py: 探针生成（SQL注入/IDOR/文件上传/命令注入）
2. verifier.py: SQL注入 True/False 验证、IDOR 验证、文件上传验证、命令注入验证
3. is_verifiable: 漏洞类型可验证判断
"""

import sys
import os

# 添加 backend 到 path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from app.poc.payloads import (
    PocProbe,
    get_sql_injection_probes,
    get_idor_probes,
    get_file_upload_probes,
    get_command_injection_probes,
    get_probes_for_vuln_type,
    is_verifiable,
)
from app.poc.verifier import (
    verify,
    verify_sql_injection,
    verify_idor,
    verify_file_upload,
    verify_command_injection,
    VerificationResult,
)

passed = 0
failed = 0


def check(name, actual, expected):
    global passed, failed
    if actual == expected:
        passed += 1
    else:
        failed += 1
        print(f"FAIL: {name}")
        print(f"  expected: {expected}")
        print(f"  actual:   {actual}")


# ── 1. payloads.py 测试 ──

# SQL 注入探针
probes = get_sql_injection_probes("/order")
check("sql_probes_count", len(probes), 3)
check("sql_probe_0_name", probes[0].name, "normal")
check("sql_probe_1_name", probes[1].name, "true_condition")
check("sql_probe_2_name", probes[2].name, "false_condition")
check("sql_probe_0_method", probes[0].method, "GET")
check("sql_probe_1_params_id", probes[1].params.get("id"), "1 AND 1=1")
check("sql_probe_2_params_id", probes[2].params.get("id"), "1 AND 1=2")

# IDOR 探针
probes = get_idor_probes("/api/user")
check("idor_probes_count", len(probes), 2)
check("idor_probe_0_name", probes[0].name, "normal")
check("idor_probe_1_name", probes[1].name, "cross_access")
check(
    "idor_probe_1_headers_auth",
    "mock_token_user_a" in probes[1].headers.get("Authorization", ""),
    True,
)

# 文件上传探针
probes = get_file_upload_probes("/upload")
check("upload_probes_count", len(probes), 1)
check("upload_probe_0_name", probes[0].name, "upload_text")
check("upload_probe_0_is_multipart", probes[0].is_multipart, True)
check("upload_probe_0_file_name", probes[0].multipart_file_name, "poc_safe_test.txt")
check("upload_harmless_content", "harmless" in probes[0].multipart_file_content, True)

# 命令注入探针
probes = get_command_injection_probes("/ping")
check("cmd_probes_count", len(probes), 1)
check("cmd_probe_0_name", probes[0].name, "echo_marker")
check(
    "cmd_probe_0_marker", "poc_marker_12345" in probes[0].params.get("host", ""), True
)

# get_probes_for_vuln_type
probes = get_probes_for_vuln_type("sql_injection")
check("get_probes_sql", len(probes), 3)
probes = get_probes_for_vuln_type("sensitive_info")
check("get_probes_sensitive_empty", len(probes), 0)

# is_verifiable
check("verifiable_sql", is_verifiable("sql_injection"), True)
check("verifiable_idor", is_verifiable("idor"), True)
check("verifiable_upload", is_verifiable("file_upload"), True)
check("verifiable_cmd", is_verifiable("command_injection"), True)
check("verifiable_sensitive", is_verifiable("sensitive_info"), False)
check("verifiable_deserialization", is_verifiable("deserialization"), False)


# ── 2. verifier.py 测试 ──

# SQL 注入验证：True 一致 + False 不同 => passed
probe_results = [
    {"name": "normal", "response_status": 200, "response_body": '{"order": "data1"}'},
    {
        "name": "true_condition",
        "response_status": 200,
        "response_body": '{"order": "data1"}',
    },
    {
        "name": "false_condition",
        "response_status": 200,
        "response_body": '{"error": "not found"}',
    },
]
result = verify_sql_injection(probe_results)
check("sql_verify_matched", result.matched, True)
check("sql_verify_status", result.validation_status, "passed")

# SQL 注入验证：True 不一致 + False 相同 => failed
probe_results = [
    {"name": "normal", "response_status": 200, "response_body": "normal_data"},
    {"name": "true_condition", "response_status": 200, "response_body": "different"},
    {"name": "false_condition", "response_status": 200, "response_body": "normal_data"},
]
result = verify_sql_injection(probe_results)
check("sql_verify_fail_matched", result.matched, False)
check("sql_verify_fail_status", result.validation_status, "failed")

# SQL 注入验证：缺少探针 => error
result = verify_sql_injection([{"name": "normal", "response_body": "x"}])
check("sql_verify_missing_status", result.validation_status, "error")

# IDOR 验证：cross_access 返回 200 => passed
probe_results = [
    {"name": "normal", "response_status": 200, "response_body": "user_a_data"},
    {"name": "cross_access", "response_status": 200, "response_body": "user_b_data"},
]
result = verify_idor(probe_results)
check("idor_verify_matched", result.matched, True)
check("idor_verify_status", result.validation_status, "passed")

# IDOR 验证：cross_access 返回 403 => failed
probe_results = [
    {"name": "cross_access", "response_status": 403, "response_body": "Forbidden"},
]
result = verify_idor(probe_results)
check("idor_verify_403_matched", result.matched, False)
check("idor_verify_403_status", result.validation_status, "failed")

# 文件上传验证：返回 200 + 包含 filename => passed
probe_results = [
    {
        "name": "upload_text",
        "response_status": 200,
        "response_body": '{"filename": "poc_safe_test.txt", "path": "/uploads/poc_safe_test.txt"}',
    },
]
result = verify_file_upload(probe_results)
check("upload_verify_matched", result.matched, True)
check("upload_verify_status", result.validation_status, "passed")

# 文件上传验证：返回 403 => failed
probe_results = [
    {"name": "upload_text", "response_status": 403, "response_body": "Forbidden"},
]
result = verify_file_upload(probe_results)
check("upload_verify_403_matched", result.matched, False)
check("upload_verify_403_status", result.validation_status, "failed")

# 命令注入验证：响应包含 marker => passed
probe_results = [
    {
        "name": "echo_marker",
        "response_status": 200,
        "response_body": "PING 127.0.0.1\npoc_marker_12345\n",
    },
]
result = verify_command_injection(probe_results)
check("cmd_verify_matched", result.matched, True)
check("cmd_verify_status", result.validation_status, "passed")

# 命令注入验证：响应不含 marker => failed
probe_results = [
    {
        "name": "echo_marker",
        "response_status": 200,
        "response_body": "PING 127.0.0.1\n",
    },
]
result = verify_command_injection(probe_results)
check("cmd_verify_fail_matched", result.matched, False)
check("cmd_verify_fail_status", result.validation_status, "failed")

# verify 调度器
result = verify(
    "sql_injection",
    [
        {"name": "normal", "response_body": "a"},
        {"name": "true_condition", "response_body": "a"},
        {"name": "false_condition", "response_body": "b"},
    ],
)
check("verify_dispatch_sql_matched", result.matched, True)

result = verify("sensitive_info", [])
check("verify_dispatch_unknown", result.validation_status, "error")


# ── 3. curl 命令构建测试 ──
from app.poc.executor import _build_curl_command, _parse_curl_output

probe = PocProbe(name="test", method="GET", path="/order", params={"id": "1"})
cmd = _build_curl_command(probe, "http://127.0.0.1:5000")
check("curl_cmd_has_url", "127.0.0.1:5000/order" in cmd, True)
check("curl_cmd_has_get", "-X" in cmd, True)

# curl 输出解析
sample_output = (
    "HTTP/1.0 200 OK\r\n"
    "Content-Type: application/json\r\n"
    "Content-Length: 17\r\n"
    "\r\n"
    '{"status": "ok"}'
)
parsed = _parse_curl_output(sample_output)
check("parse_status", parsed["status_code"], 200)
check("parse_headers_ct", parsed["headers"].get("Content-Type"), "application/json")
check("parse_body", parsed["body"], '{"status": "ok"}')

# 空输出解析
parsed = _parse_curl_output("")
check("parse_empty_status", parsed["status_code"], 0)
check("parse_empty_body", parsed["body"], "")


print(f"\n{'=' * 60}")
print(f"PoC Module Tests: {passed} passed, {failed} failed")
print(f"{'=' * 60}")
if failed > 0:
    sys.exit(1)
