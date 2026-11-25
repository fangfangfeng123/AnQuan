"""PoC 结果验证器模块。

比对探针响应与预期特征，判断漏洞是否可利用。

验证策略按漏洞类型区分：
- SQL 注入：True 条件响应 == 正常响应，False 条件响应 != 正常响应
- IDOR：A 用户用自己 Token 能读到 B 用户的数据
- 文件上传：上传后返回文件名，且文件确实可访问
- 命令注入：响应中包含注入的 marker 字符串
"""

from dataclasses import dataclass
from typing import Any

from app.poc.payloads import PocProbe


@dataclass
class VerificationResult:
    """单次探针验证结果。"""

    matched: bool
    """是否匹配成功"""

    validation_status: str
    """passed / failed / error"""

    expected_feature: str
    """预期特征描述"""

    actual_feature: str
    """实际观察到的特征"""

    reason: str = ""
    """验证说明"""


def _normalize_body(body: str | None) -> str:
    """标准化响应体，去除首尾空白。"""
    if not body:
        return ""
    return body.strip()


def _bodies_equal(a: str | None, b: str | None) -> bool:
    """比较两个响应体是否实质相等（忽略首尾空白和大小写差异）。"""
    return _normalize_body(a).lower() == _normalize_body(b).lower()


def _bodies_different(a: str | None, b: str | None) -> bool:
    """判断两个响应体是否实质不同。"""
    return not _bodies_equal(a, b)


def verify_sql_injection(
    probe_results: list[dict[str, Any]],
) -> VerificationResult:
    """SQL 注入验证：True/False 条件对比。

    判定规则：
    - True 条件响应 == 正常响应
    - False 条件响应 != 正常响应
    - 两者同时满足 => matched=True

    Args:
        probe_results: 每个探针的执行结果列表，包含 name / response_status / response_body
    """
    normal = None
    true_resp = None
    false_resp = None

    for r in probe_results:
        name = r.get("name", "")
        if name == "normal":
            normal = r
        elif name == "true_condition":
            true_resp = r
        elif name == "false_condition":
            false_resp = r

    if not normal or not true_resp or not false_resp:
        return VerificationResult(
            matched=False,
            validation_status="error",
            expected_feature="需要 normal / true_condition / false_condition 三个探针",
            actual_feature="缺少部分探针结果",
            reason="探针不完整",
        )

    normal_body = normal.get("response_body")
    true_body = true_resp.get("response_body")
    false_body = false_resp.get("response_body")

    true_match = _bodies_equal(normal_body, true_body)
    false_diff = _bodies_different(normal_body, false_body)

    if true_match and false_diff:
        return VerificationResult(
            matched=True,
            validation_status="passed",
            expected_feature="True 条件响应与正常一致，False 条件响应与正常不同",
            actual_feature=f"true_equal={true_match}, false_different={false_diff}",
            reason="SQL 注入确认：True/False 条件响应差异成立",
        )

    return VerificationResult(
        matched=False,
        validation_status="failed",
        expected_feature="True 条件响应与正常一致，False 条件响应与正常不同",
        actual_feature=f"true_equal={true_match}, false_different={false_diff}",
        reason="True/False 条件响应无差异，注入可能不存在或已过滤",
    )


def verify_idor(
    probe_results: list[dict[str, Any]],
) -> VerificationResult:
    """IDOR 越权验证：A 用户 Token 访问 B 用户数据。

    判定规则：
    - normal 和 cross_access 请求都返回 200 且有响应体
    - cross_access 响应与 normal 响应不同，说明读取到了另一个用户的数据
    - cross_access 返回 403/401 => 已有权限控制，无越权
    """
    normal = None
    cross = None
    for r in probe_results:
        name = r.get("name")
        if name == "normal":
            normal = r
        elif name == "cross_access":
            cross = r

    if not normal or not cross:
        return VerificationResult(
            matched=False,
            validation_status="error",
            expected_feature="需要 normal / cross_access 两个探针",
            actual_feature="缺少部分探针结果",
            reason="探针不完整",
        )

    cross_status = cross.get("response_status", 0)
    cross_body = cross.get("response_body", "")
    normal_body = normal.get("response_body", "")

    if cross_status == 200 and cross_body and not _bodies_equal(normal_body, cross_body):
        return VerificationResult(
            matched=True,
            validation_status="passed",
            expected_feature="A 用户能访问 B 用户数据",
            actual_feature=(
                f"normal 与 cross_access 响应不同，"
                f"cross 响应体长度={len(cross_body)}"
            ),
            reason="越权访问成功：A 用户 Token 访问 B 用户数据返回正常",
        )

    if cross_status in (401, 403):
        return VerificationResult(
            matched=False,
            validation_status="failed",
            expected_feature="A 用户能访问 B 用户数据",
            actual_feature=f"cross_access 返回 {cross_status}（有权限控制）",
            reason=f"服务端已拦截越权访问（HTTP {cross_status}），IDOR 不成立",
        )

    return VerificationResult(
        matched=False,
        validation_status="failed",
        expected_feature="A 用户能访问 B 用户数据",
        actual_feature=f"cross_access 返回 {cross_status}，normal/cross 响应相同",
        reason="未观察到不同用户数据的差异，IDOR 不成立",
    )


def verify_file_upload(
    probe_results: list[dict[str, Any]],
) -> VerificationResult:
    """文件上传验证：上传无害文本，检查保存成功。

    判定规则：
    - 返回 200 且响应体包含文件名或路径 => 上传成功
    """
    upload = None
    for r in probe_results:
        if r.get("name") == "upload_text":
            upload = r
            break

    if not upload:
        return VerificationResult(
            matched=False,
            validation_status="error",
            expected_feature="上传成功且返回文件路径",
            actual_feature="缺少 upload 探针结果",
            reason="探针不完整",
        )

    status = upload.get("response_status", 0)
    body = upload.get("response_body", "")

    if status == 200 and body:
        body_lower = body.lower()
        if any(
            kw in body_lower for kw in ["filename", "path", "saved", "success", "上传"]
        ):
            return VerificationResult(
                matched=True,
                validation_status="passed",
                expected_feature="上传成功且返回文件路径",
                actual_feature=f"返回 200，响应含文件信息: {body[:200]}",
                reason="文件上传成功，服务端未限制类型",
            )

    return VerificationResult(
        matched=False,
        validation_status="failed",
        expected_feature="上传成功且返回文件路径",
        actual_feature=f"返回 {status}, body={body[:200] if body else 'empty'}",
        reason="上传未成功或服务端已拒绝",
    )


def verify_command_injection(
    probe_results: list[dict[str, Any]],
) -> VerificationResult:
    """命令注入验证：检测 marker 回显。

    判定规则：
    - 响应体包含注入的 marker 字符串 => 命令注入成立
    """
    echo = None
    for r in probe_results:
        if r.get("name") == "echo_marker":
            echo = r
            break

    if not echo:
        return VerificationResult(
            matched=False,
            validation_status="error",
            expected_feature="响应包含 poc_marker_12345",
            actual_feature="缺少 echo_marker 探针结果",
            reason="探针不完整",
        )

    body = echo.get("response_body", "")
    marker = "poc_marker_12345"

    if marker in body:
        return VerificationResult(
            matched=True,
            validation_status="passed",
            expected_feature=f"响应包含 {marker}",
            actual_feature=f"响应体中找到 {marker}",
            reason="命令注入确认：注入的命令被执行并回显",
        )

    return VerificationResult(
        matched=False,
        validation_status="failed",
        expected_feature=f"响应包含 {marker}",
        actual_feature=f"响应体中未找到 {marker}",
        reason="命令注入未确认：marker 未在响应中出现",
    )


def verify(
    vuln_type: str,
    probe_results: list[dict[str, Any]],
) -> VerificationResult:
    """根据漏洞类型调度对应的验证器。

    Args:
        vuln_type: 漏洞类型（sql_injection / idor / file_upload / command_injection）
        probe_results: 每个探针的执行结果列表

    Returns:
        VerificationResult：验证结论
    """
    verifiers = {
        "sql_injection": verify_sql_injection,
        "idor": verify_idor,
        "broken_access": verify_idor,
        "file_upload": verify_file_upload,
        "command_injection": verify_command_injection,
    }

    verifier_fn = verifiers.get(vuln_type)
    if verifier_fn is None:
        return VerificationResult(
            matched=False,
            validation_status="error",
            expected_feature="",
            actual_feature="",
            reason=f"不支持验证漏洞类型: {vuln_type}",
        )

    return verifier_fn(probe_results)
