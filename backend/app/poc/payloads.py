"""探针模板库模块。

按漏洞类型预置安全（无害）的验证载荷。
所有探针都经过安全设计，不造成实际破坏：
- SQL 注入：True/False 条件对比，不读取真实数据
- IDOR：使用模拟用户 Token 访问他人数据
- 文件上传：上传无害文本文件
- 命令注入：发送 marker 字符串检测回显
- 敏感信息：不进行动态验证，保持 unverified 或 latent
"""

import re
from dataclasses import dataclass, field
from urllib.parse import urlencode
from typing import Any


@dataclass
class PocProbe:
    """单个探针定义。"""

    name: str
    """探针名称，如 normal / true_condition / false_condition"""

    method: str = "GET"
    """HTTP 方法"""

    path: str = "/"
    """请求路径"""

    params: dict[str, str] = field(default_factory=dict)
    """查询参数"""

    headers: dict[str, str] = field(default_factory=dict)
    """请求头"""

    body: str | None = None
    """请求体"""

    content_type: str | None = None
    """请求体 Content-Type"""

    expected_feature: str = ""
    """预期特征描述"""

    expected_status: int = 200
    """预期 HTTP 状态码"""

    is_multipart: bool = False
    """是否 multipart 上传"""

    multipart_fields: dict[str, str] = field(default_factory=dict)
    """multipart 表单字段"""

    multipart_file_content: str = ""
    """上传文件内容（无害文本）"""

    multipart_file_name: str = "poc_test.txt"
    """上传文件名"""


def get_sql_injection_probes(
    base_path: str = "/api/order",
    param_name: str = "id",
    http_method: str = "GET",
) -> list[PocProbe]:
    """SQL 注入探针：True/False 条件对比。

    策略：发送三个请求，对比正常请求与注入 True/False 条件后的响应。
    - normal：{param}=1（正常请求，获取基线响应）
    - true_condition：{param}=1 AND 1=1（True 条件，预期与 normal 一致）
    - false_condition：{param}=1 AND 1=2（False 条件，预期与 normal 不同）

    不读取真实数据，仅通过条件响应差异确认注入。

    Args:
        base_path: HTTP 路由路径（从 finding code_context 提取）
        param_name: 注入参数名（从 finding source_code 提取）
    """
    def make_probe(name: str, value: str, feature: str) -> PocProbe:
        params = {} if http_method.upper() == "POST" else {param_name: value}
        body = (
            urlencode({param_name: value})
            if http_method.upper() == "POST"
            else None
        )
        return PocProbe(
            name=name,
            method=http_method.upper(),
            path=base_path,
            params=params,
            body=body,
            content_type=(
                "application/x-www-form-urlencoded"
                if http_method.upper() == "POST"
                else None
            ),
            expected_feature=feature,
            expected_status=200,
        )

    return [
        make_probe("normal", "1", "正常响应（基线）"),
        make_probe(
            "true_condition",
            "1 AND 1=1",
            "与正常响应一致（True 条件注入成功）",
        ),
        make_probe(
            "false_condition",
            "1 AND 1=2",
            "与正常响应不同（False 条件生效）",
        ),
    ]


def get_idor_probes(base_path: str = "/api/user") -> list[PocProbe]:
    """构造真实 IDOR 路径参数的 normal/cross 探针。

    只有路由中确实声明了路径参数时才会验证，避免把普通查询接口误判成越权。
    """
    if "<" not in base_path:
        return []

    def with_user_id(value: int) -> str:
        return re.sub(r"<(?:\w+:)?\w+>", str(value), base_path)

    return [
        PocProbe(
            name="normal",
            method="GET",
            path=with_user_id(1),
            headers={"Authorization": "Bearer mock_token_user_a"},
            expected_feature="A 用户能访问自己的数据",
            expected_status=200,
        ),
        PocProbe(
            name="cross_access",
            method="GET",
            path=with_user_id(2),
            headers={"Authorization": "Bearer mock_token_user_a"},
            expected_feature="A 用户能访问 B 用户的数据（越权成功）",
            expected_status=200,
        ),
    ]


def get_file_upload_probes(base_path: str = "/api/upload") -> list[PocProbe]:
    return [
        PocProbe(
            name="upload_text",
            method="POST",
            path=base_path,
            is_multipart=True,
            multipart_fields={"description": "poc_test"},
            multipart_file_content="this is a harmless poc test file\n",
            multipart_file_name="poc_safe_test.txt",
            expected_feature="上传成功且返回文件路径",
            expected_status=200,
        ),
    ]


def get_command_injection_probes(
    base_path: str = "/api/ping",
    param_name: str = "host",
    http_method: str = "GET",
) -> list[PocProbe]:
    params = {} if http_method.upper() == "POST" else {param_name: "127.0.0.1; echo poc_marker_12345"}
    body = (
        urlencode({param_name: "127.0.0.1; echo poc_marker_12345"})
        if http_method.upper() == "POST"
        else None
    )
    return [
        PocProbe(
            name="echo_marker",
            method=http_method.upper(),
            path=base_path,
            params=params,
            body=body,
            content_type=(
                "application/x-www-form-urlencoded"
                if http_method.upper() == "POST"
                else None
            ),
            expected_feature="响应包含 poc_marker_12345",
            expected_status=200,
        ),
    ]


def get_probes_for_vuln_type(
    vuln_type: str,
    base_path: str | None = None,
    param_name: str | None = None,
    http_method: str = "GET",
) -> list[PocProbe]:
    """根据漏洞类型获取探针列表。

    对于不支持动态验证的类型（如敏感信息泄露），
    返回空列表，调用方应跳过验证。

    Args:
        vuln_type: 漏洞类型
        base_path: HTTP 路由路径（从 finding code_context 提取，None 用默认值）
        param_name: 注入参数名（从 finding source_code 提取，None 用默认值）
    """
    # 各漏洞类型的默认路径和参数名
    defaults: dict[str, tuple[str, str | None]] = {
        "sql_injection": ("/api/order", "id"),
        "idor": ("/api/user", None),
        "broken_access": ("/api/user", None),
        "file_upload": ("/api/upload", None),
        "command_injection": ("/api/ping", "host"),
    }

    default_path, default_param = defaults.get(vuln_type, ("/", None))
    path = base_path or default_path
    param = param_name or default_param

    # 按漏洞类型调用对应的工厂函数
    if vuln_type == "sql_injection":
        return get_sql_injection_probes(
            base_path=path,
            param_name=param or "id",
            http_method=http_method,
        )
    elif vuln_type in ("idor", "broken_access"):
        return get_idor_probes(base_path=path)
    elif vuln_type == "file_upload":
        return get_file_upload_probes(base_path=path)
    elif vuln_type == "command_injection":
        return get_command_injection_probes(
            base_path=path,
            param_name=param or "host",
            http_method=http_method,
        )
    else:
        return []


def is_verifiable(vuln_type: str) -> bool:
    """判断该漏洞类型是否适合动态验证。

    敏感信息泄露（硬编码密钥）等不适合动态验证，
    应保持 unverified 或归为 latent。
    """
    return vuln_type in {
        "sql_injection",
        "idor",
        "broken_access",
        "file_upload",
        "command_injection",
    }
