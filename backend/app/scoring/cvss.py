"""CVSS 3.1 评分计算器模块。

本模块实现两部分功能：
1. 启发式 CVSS 评分：根据漏洞类型、上下文因素（外部可达性、是否需登录、
   是否有过滤）自动生成 CVSS 3.1 向量字符串和分数，并映射到严重等级。
2. CVSS 3.1 Base Score 精确计算：解析向量字符串，按 CVSS 3.1 规范
   计算 Base Score。

启发式评分规则（第一版）：
- RCE / 反序列化 / SQL注入 / 文件上传组合风险 → high 或 critical
- IDOR / SSRF / 敏感信息泄露 → high 或 medium
- 结合是否外部可达（路由暴露）、是否需要登录（鉴权）、是否存在过滤

CVSS 3.1 Base Score 公式：
  ISS = 1 - [(1-C) * (1-I) * (1-A)]
  if S == U: Impact = 6.42 * ISS
  if S == C: Impact = 7.52 * (ISS - 0.029) - 3.25 * (ISS - 0.02)^15
  exploitability = 8.22 * AV * AC * PR * UI
  if Impact <= 0: BaseScore = 0
  if S == U: BaseScore = roundup(Impact + exploitability)
  if S == C: BaseScore = roundup(1.08 * (Impact + exploitability))

严重等级映射：
  >= 9.0: critical
  7.0-8.9: high
  4.0-6.9: medium
  0.1-3.9: low
  0.0: info
"""

import math
from dataclasses import dataclass
from enum import Enum


class Severity(str, Enum):
    """严重等级（CVSS 对齐）。"""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# ──────────────────────────────────────────────────────
# CVSS 3.1 度量值表
# ──────────────────────────────────────────────────────

# Attack Vector (AV)
_AV_VALUES: dict[str, float] = {
    "N": 0.85,  # Network
    "A": 0.62,  # Adjacent
    "L": 0.55,  # Local
    "P": 0.2,  # Physical
}

# Attack Complexity (AC)
_AC_VALUES: dict[str, float] = {
    "L": 0.77,  # Low
    "H": 0.44,  # High
}

# Privileges Required (PR) — Scope U / C 不同
_PR_VALUES: dict[str, dict[str, float]] = {
    "N": {"U": 0.85, "C": 0.85},  # None
    "L": {"U": 0.62, "C": 0.68},  # Low
    "H": {"U": 0.27, "C": 0.5},  # High
}

# User Interaction (UI)
_UI_VALUES: dict[str, float] = {
    "N": 0.85,  # None
    "R": 0.62,  # Required
}

# CIA Impact values
_CIA_VALUES: dict[str, float] = {
    "H": 0.56,  # High
    "L": 0.22,  # Low
    "N": 0.0,  # None
}


def _roundup(score: float) -> float:
    """CVSS 3.1 Roundup: 向上取整到小数点后 1 位。"""
    int_input = int(score * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (int_input // 10000 + 1) / 10.0


def calculate_base_score(vector: str) -> float:
    """根据 CVSS 3.1 向量字符串计算 Base Score。

    向量格式如: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

    Args:
        vector: CVSS 3.1 向量字符串

    Returns:
        Base Score (0.0 - 10.0)
    """
    metrics = _parse_vector(vector)
    return _compute_base_score(metrics)


def _parse_vector(vector: str) -> dict[str, str]:
    """解析 CVSS 向量字符串为度量字典。"""
    metrics: dict[str, str] = {}
    for part in vector.split("/"):
        part = part.strip()
        if ":" in part:
            k, v = part.split(":", 1)
            metrics[k.strip()] = v.strip()
    return metrics


def _compute_base_score(metrics: dict[str, str]) -> float:
    """根据度量字典计算 Base Score。"""
    av = _AV_VALUES.get(metrics.get("AV", "N"), 0.85)
    ac = _AC_VALUES.get(metrics.get("AC", "L"), 0.77)
    pr = _PR_VALUES.get(metrics.get("PR", "N"), {}).get(metrics.get("S", "U"), 0.85)
    ui = _UI_VALUES.get(metrics.get("UI", "N"), 0.85)
    scope = metrics.get("S", "U")

    c = _CIA_VALUES.get(metrics.get("C", "N"), 0.0)
    i = _CIA_VALUES.get(metrics.get("I", "N"), 0.0)
    a = _CIA_VALUES.get(metrics.get("A", "N"), 0.0)

    # Impact Sub-Score
    iss = 1 - (1 - c) * (1 - i) * (1 - a)

    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15

    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0

    if scope == "U":
        base_score = _roundup(impact + exploitability)
    else:
        base_score = _roundup(1.08 * (impact + exploitability))

    return min(base_score, 10.0)


def severity_from_score(score: float) -> str:
    """根据 CVSS 分数映射严重等级。

    Args:
        score: CVSS 分数 (0.0 - 10.0)

    Returns:
        严重等级字符串 (critical / high / medium / low / info)
    """
    if score >= 9.0:
        return Severity.CRITICAL.value
    elif score >= 7.0:
        return Severity.HIGH.value
    elif score >= 4.0:
        return Severity.MEDIUM.value
    elif score >= 0.1:
        return Severity.LOW.value
    else:
        return Severity.INFO.value


# ──────────────────────────────────────────────────────
# 启发式评分
# ──────────────────────────────────────────────────────

# 漏洞类型 -> 默认 CVSS 向量模板
# 向量格式: AV:N/AC:L/PR:N/UI:N/S:U/C:./I:./A:.
# 根据上下文因素调整 PR 和 CIA


@dataclass
class ScoringContext:
    """启发式评分上下文。

    用于描述漏洞的上下文因素，影响最终 CVSS 评分。

    Attributes:
        vuln_type: 漏洞类型 (sql_injection / command_injection / file_upload / broken_access / sensitive_data 等)
        is_externally_reachable: 是否外部可达（路由是否暴露在 HTTP 接口）
        requires_auth: 是否需要登录（True 表示需要登录才能触发，降低 PR）
        has_filter: 是否存在部分过滤（增加 AC 到 High）
        has_sanitizer: 是否存在有效净化器（大幅降分）
        confidence: 原始检测置信度 (0-1)
    """

    vuln_type: str
    is_externally_reachable: bool = True
    requires_auth: bool = False
    has_filter: bool = False
    has_sanitizer: bool = False
    confidence: float = 0.5


# 各漏洞类型的默认影响评估 (C, I, A)
# 格式: (confidentiality, integrity, availability) — H/L/N
_VULN_TYPE_DEFAULTS: dict[str, dict] = {
    "sql_injection": {
        "C": "H",
        "I": "H",
        "A": "H",
        "base_vector": "AV:N/AC:L/PR:N/UI:N/S:U",
        "base_severity": "high",
        "base_score": 9.8,  # AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    },
    "command_injection": {
        "C": "H",
        "I": "H",
        "A": "H",
        "base_vector": "AV:N/AC:L/PR:N/UI:N/S:U",
        "base_severity": "critical",
        "base_score": 9.8,
    },
    "file_upload": {
        "C": "H",
        "I": "H",
        "A": "H",
        "base_vector": "AV:N/AC:L/PR:N/UI:N/S:U",
        "base_severity": "high",
        "base_score": 9.8,
    },
    "broken_access": {  # IDOR
        "C": "H",
        "I": "L",
        "A": "N",
        "base_vector": "AV:N/AC:L/PR:L/UI:N/S:U",
        "base_severity": "high",
        "base_score": 7.1,  # AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N
    },
    "sensitive_data": {
        "C": "H",
        "I": "N",
        "A": "N",
        "base_vector": "AV:N/AC:L/PR:N/UI:N/S:U",
        "base_severity": "medium",
        "base_score": 7.5,  # AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
    },
    "path_traversal": {
        "C": "H",
        "I": "H",
        "A": "N",
        "base_vector": "AV:N/AC:L/PR:N/UI:N/S:U",
        "base_severity": "high",
        "base_score": 7.5,
    },
    "ssrf": {
        "C": "H",
        "I": "L",
        "A": "N",
        "base_vector": "AV:N/AC:L/PR:N/UI:N/S:U",
        "base_severity": "medium",
        "base_score": 7.5,
    },
    "deserialization": {
        "C": "H",
        "I": "H",
        "A": "H",
        "base_vector": "AV:N/AC:L/PR:N/UI:N/S:U",
        "base_severity": "critical",
        "base_score": 9.8,
    },
    "xss": {
        "C": "L",
        "I": "L",
        "A": "N",
        "base_vector": "AV:N/AC:L/PR:N/UI:R/S:U",
        "base_severity": "medium",
        "base_score": 5.4,  # AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N
    },
}


def score_finding(context: ScoringContext) -> tuple[str, float, str]:
    """根据上下文对漏洞进行启发式 CVSS 评分。

    Args:
        context: 评分上下文（漏洞类型、可达性、鉴权、过滤等）

    Returns:
        (severity, cvss_score, cvss_vector)
        - severity: critical / high / medium / low / info
        - cvss_score: 0.0 - 10.0
        - cvss_vector: CVSS 3.1 向量字符串
    """
    defaults = _VULN_TYPE_DEFAULTS.get(
        context.vuln_type,
        {
            "C": "L",
            "I": "L",
            "A": "N",
            "base_vector": "AV:N/AC:L/PR:N/UI:N/S:U",
            "base_severity": "medium",
            "base_score": 5.4,
        },
    )

    # ── 1. 从默认向量开始 ──
    base_parts = defaults["base_vector"].split("/")
    av = _get_part(base_parts, "AV", "N")
    ac = _get_part(base_parts, "AC", "L")
    pr = _get_part(base_parts, "PR", "N")
    ui = _get_part(base_parts, "UI", "N")
    scope = _get_part(base_parts, "S", "U")

    # ── 2. 根据上下文调整 ──

    # 外部可达性：如果不可外部达，降级到 Local
    if not context.is_externally_reachable:
        av = "L"

    # 鉴权要求：需要登录 -> PR=L（低权限），否则保持 PR=N
    if context.requires_auth:
        pr = "L"
    else:
        pr = "N"

    # 过滤：有部分过滤 -> AC=H（攻击复杂度升高）
    if context.has_filter:
        ac = "H"

    # 有净化器：大幅降分（CIA 降为 Low）
    if context.has_sanitizer:
        c_imp = "L"
        i_imp = "L"
        a_imp = "N"
    else:
        c_imp = defaults["C"]
        i_imp = defaults["I"]
        a_imp = defaults["A"]

    # ── 3. 构造向量 ──
    vector = f"AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{scope}/C:{c_imp}/I:{i_imp}/A:{a_imp}"

    # ── 4. 计算 Base Score ──
    score = calculate_base_score(vector)

    # ── 5. 根据置信度微调（不改变 CVSS，但影响最终上报）──
    # 低置信度的发现降低一档
    if context.confidence < 0.3:
        score = max(0.0, score - 2.0)

    # ── 6. 映射严重等级 ──
    severity = severity_from_score(score)

    return severity, round(score, 1), vector


def _get_part(parts: list[str], key: str, default: str) -> str:
    """从向量片段列表中提取指定 key 的值。"""
    for part in parts:
        if part.startswith(f"{key}:"):
            return part.split(":", 1)[1]
    return default


def score_findings_batch(
    finding_dicts: list[dict],
) -> list[dict]:
    """批量对 Finding 字典列表进行 CVSS 评分。

    会原地修改每个 finding 字典，添加/覆盖 severity、cvss_score、cvss_vector 字段。

    Args:
        finding_dicts: Finding 字典列表

    Returns:
        同一列表（原地修改后）
    """
    # 某些漏洞类型默认需要登录才能触发（影响 PR 评级）
    _AUTH_REQUIRED_TYPES = {"broken_access", "idor"}

    for f in finding_dicts:
        vuln_type = f.get("vuln_type", "other")
        context = ScoringContext(
            vuln_type=vuln_type,
            is_externally_reachable=True,
            requires_auth=vuln_type in _AUTH_REQUIRED_TYPES,
            has_filter=False,
            has_sanitizer=False,
            confidence=f.get("confidence", 0.5),
        )

        # 从 taint_path 中推断是否有 sanitizer
        taint_path = f.get("taint_path", [])
        if taint_path:
            for step in taint_path:
                if isinstance(step, dict) and step.get("type") == "sanitizer":
                    context.has_sanitizer = True
                    break

        severity, score, vector = score_finding(context)
        f["severity"] = severity
        f["cvss_score"] = score
        f["cvss_vector"] = vector

    return finding_dicts
