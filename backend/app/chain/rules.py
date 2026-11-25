"""攻击链串联规则模块。

本模块定义漏洞类型间的串联规则，用于判断两个已验证漏洞能否串联：
- 前一个漏洞的后置能力（post_capability）是否满足后一个漏洞的前置条件（precondition）
- 权限跃迁路径：anonymous -> user -> admin -> system
- 各漏洞类型的默认前置条件、后置能力和权限变化

规则设计依据常见攻击路径模式：
- SQL注入 -> 读取凭证 -> 后台登录（admin） -> 文件上传 -> WebShell -> RCE
- IDOR/越权 -> 获取敏感数据 -> 凭证窃取 -> 后台操作 -> RCE
- 反序列化 -> 直接 RCE
- 路径穿越 -> 读取敏感文件 -> 凭证窃取
- SSRF -> 内网探测 -> 攻击内部服务

权限级别排序（从低到高）：
  none < anonymous < user < admin < system
"""

from dataclasses import dataclass, field


# ──────────────────────────────────────────────────────
# 权限级别定义
# ──────────────────────────────────────────────────────

PRIVILEGE_LEVELS = ["none", "anonymous", "user", "admin", "system"]


def privilege_rank(level: str) -> int:
    """返回权限级别的数值排名（越高权限越大）。

    Args:
        level: 权限级别字符串（none/anonymous/user/admin/system）

    Returns:
        0-4 的整数排名，未知级别返回 0
    """
    level_lower = (level or "none").lower().strip()
    if level_lower in PRIVILEGE_LEVELS:
        return PRIVILEGE_LEVELS.index(level_lower)
    # 尝试模糊匹配
    if "system" in level_lower or "root" in level_lower:
        return 4
    if "admin" in level_lower:
        return 3
    if "user" in level_lower:
        return 2
    if "anon" in level_lower or "guest" in level_lower:
        return 1
    return 0


def parse_privilege_pair(privilege_level: str) -> tuple[int, int]:
    """解析 "anonymous -> admin" 格式的权限变化字符串。

    Args:
        privilege_level: 权限变化字符串，如 "anonymous -> admin"

    Returns:
        (前置权限级别, 后置权限级别) 的数值排名
    """
    if not privilege_level:
        return (0, 0)
    parts = privilege_level.replace("->", "|").split("|")
    pre = parts[0].strip() if parts else "none"
    post = parts[1].strip() if len(parts) > 1 else pre
    return (privilege_rank(pre), privilege_rank(post))


# ──────────────────────────────────────────────────────
# 串联规则定义
# ──────────────────────────────────────────────────────


@dataclass
class ChainRule:
    """单条串联规则：定义漏洞类型 A 的后置能力如何满足漏洞类型 B 的前置条件。

    Attributes:
        rule_id: 规则唯一标识
        source_vuln_type: 源漏洞类型（如 sql_injection）
        target_vuln_type: 目标漏洞类型（如 file_upload）
        condition: 串联条件描述（如 "SQL注入获取管理员凭证"）
        action: 攻击动作描述（如 "使用管理员凭证登录后台"）
        privilege_escalation: 权限跃迁描述（如 "anonymous -> admin"）
        required_pre_privilege: 目标漏洞需要的最低前置权限级别
        granted_post_privilege: 源漏洞赋予的后置权限级别
    """

    rule_id: str
    source_vuln_type: str
    target_vuln_type: str
    condition: str = ""
    action: str = ""
    privilege_escalation: str = ""
    required_pre_privilege: str = "none"
    granted_post_privilege: str = "none"


# ──────────────────────────────────────────────────────
# 漏洞类型默认属性
# ──────────────────────────────────────────────────────


@dataclass
class VulnTypeProfile:
    """漏洞类型的默认属性配置。

    为每种漏洞类型定义默认的：
    - precondition: 前置条件（攻击者需要什么才能利用此漏洞）
    - post_capability: 后置能力（利用此漏洞后攻击者获得什么）
    - privilege_level: 权限变化（如 anonymous -> admin）
    - final_impact: 单独利用时的最终影响
    - asset_hint: 资产提示（通常是哪个端点）
    """

    vuln_type: str
    precondition: str = ""
    post_capability: str = ""
    privilege_level: str = ""
    final_impact: str = ""
    asset_hint: str = ""

    def label(self) -> str:
        """生成默认节点标签。"""
        impact = self.final_impact or self.post_capability or self.vuln_type
        return impact


# 各漏洞类型的默认属性
VULN_TYPE_PROFILES: dict[str, VulnTypeProfile] = {
    "sql_injection": VulnTypeProfile(
        vuln_type="sql_injection",
        precondition="可访问目标接口（无需认证或已知有效参数）",
        post_capability="读取/修改数据库内容，可获取管理员凭证",
        privilege_level="anonymous -> admin",
        final_impact="数据库数据泄露或篡改，可能获取管理员凭证",
        asset_hint="SQL查询接口",
    ),
    "command_injection": VulnTypeProfile(
        vuln_type="command_injection",
        precondition="可访问存在命令拼接的接口",
        post_capability="在服务器上执行任意系统命令",
        privilege_level="anonymous -> system",
        final_impact="服务器完全控制权（RCE）",
        asset_hint="命令执行接口",
    ),
    "file_upload": VulnTypeProfile(
        vuln_type="file_upload",
        precondition="拥有后台管理员权限（或上传接口无鉴权）",
        post_capability="上传 WebShell 获得服务端命令执行权",
        privilege_level="admin -> system",
        final_impact="服务器完全控制权（RCE via WebShell）",
        asset_hint="文件上传接口",
    ),
    "broken_access": VulnTypeProfile(
        vuln_type="broken_access",
        precondition="拥有普通用户权限（或接口无鉴权）",
        post_capability="越权访问其他用户数据，可能获取管理员信息",
        privilege_level="user -> admin",
        final_impact="敏感数据越权访问",
        asset_hint="用户数据接口",
    ),
    "sensitive_data": VulnTypeProfile(
        vuln_type="sensitive_data",
        precondition="可访问目标应用（信息泄露接口或硬编码）",
        post_capability="获取密钥、Token、数据库连接串等敏感信息",
        privilege_level="anonymous -> user",
        final_impact="敏感信息泄露",
        asset_hint="信息暴露接口",
    ),
    "path_traversal": VulnTypeProfile(
        vuln_type="path_traversal",
        precondition="可访问文件读取/下载接口",
        post_capability="读取服务器任意文件，可能获取配置和凭证",
        privilege_level="anonymous -> user",
        final_impact="敏感文件读取",
        asset_hint="文件操作接口",
    ),
    "ssrf": VulnTypeProfile(
        vuln_type="ssrf",
        precondition="可访问发起外部请求的接口",
        post_capability="探测内网服务，访问内部资源",
        privilege_level="anonymous -> user",
        final_impact="内网信息泄露与服务探测",
        asset_hint="URL请求接口",
    ),
    "deserialization": VulnTypeProfile(
        vuln_type="deserialization",
        precondition="可访问反序列化入口（需构造恶意序列化数据）",
        post_capability="直接在服务器上执行任意代码",
        privilege_level="anonymous -> system",
        final_impact="服务器完全控制权（RCE）",
        asset_hint="反序列化接口",
    ),
    "xss": VulnTypeProfile(
        vuln_type="xss",
        precondition="可向页面注入脚本（需要受害者访问）",
        post_capability="窃取用户Cookie/Session，可能获取管理员权限",
        privilege_level="anonymous -> user",
        final_impact="客户端脚本执行与凭证窃取",
        asset_hint="输入输出接口",
    ),
}


def get_vuln_profile(vuln_type: str) -> VulnTypeProfile:
    """获取漏洞类型的默认属性配置。

    Args:
        vuln_type: 漏洞类型字符串

    Returns:
        VulnTypeProfile 实例，未知类型返回通用配置
    """
    if vuln_type in VULN_TYPE_PROFILES:
        return VULN_TYPE_PROFILES[vuln_type]
    return VulnTypeProfile(
        vuln_type=vuln_type,
        precondition="可访问目标接口",
        post_capability="利用漏洞获取未授权访问或数据",
        privilege_level="anonymous -> user",
        final_impact=f"{vuln_type} 漏洞利用",
        asset_hint="目标接口",
    )


# ──────────────────────────────────────────────────────
# 串联规则集合
# ──────────────────────────────────────────────────────

CHAIN_RULES: list[ChainRule] = [
    # ── SQL注入 -> 文件上传 ──
    ChainRule(
        rule_id="SQL-TO-UPLOAD",
        source_vuln_type="sql_injection",
        target_vuln_type="file_upload",
        condition="SQL注入读取管理员凭证表，获取后台登录权限",
        action="使用窃取的管理员凭证登录后台，访问文件上传功能",
        privilege_escalation="admin -> admin",
        required_pre_privilege="admin",
        granted_post_privilege="admin",
    ),
    # ── SQL注入 -> 命令注入 ──
    ChainRule(
        rule_id="SQL-TO-CMD",
        source_vuln_type="sql_injection",
        target_vuln_type="command_injection",
        condition="SQL注入获取管理员凭证，登录后台访问命令执行功能",
        action="使用管理员权限触发命令注入接口",
        privilege_escalation="user -> admin",
        required_pre_privilege="admin",
        granted_post_privilege="admin",
    ),
    # ── 文件上传 -> 命令注入 ──
    ChainRule(
        rule_id="UPLOAD-TO-CMD",
        source_vuln_type="file_upload",
        target_vuln_type="command_injection",
        condition="通过文件上传 WebShell 获得初始执行权",
        action="利用 WebShell 进一步触发命令注入扩大控制",
        privilege_escalation="admin -> system",
        required_pre_privilege="admin",
        granted_post_privilege="system",
    ),
    # ── IDOR/越权 -> 文件上传 ──
    ChainRule(
        rule_id="IDOR-TO-UPLOAD",
        source_vuln_type="broken_access",
        target_vuln_type="file_upload",
        condition="越权获取管理员账户信息，冒用管理员身份",
        action="使用越权获取的管理员凭证访问后台文件上传功能",
        privilege_escalation="user -> admin",
        required_pre_privilege="admin",
        granted_post_privilege="admin",
    ),
    # ── IDOR/越权 -> SQL注入 ──
    ChainRule(
        rule_id="IDOR-TO-SQL",
        source_vuln_type="broken_access",
        target_vuln_type="sql_injection",
        condition="越权获取其他用户数据，发现内部API参数",
        action="使用越权获取的信息访问SQL注入接口",
        privilege_escalation="user -> admin",
        required_pre_privilege="admin",
        granted_post_privilege="admin",
    ),
    # ── 敏感信息泄露 -> 文件上传 ──
    ChainRule(
        rule_id="SENSITIVE-TO-UPLOAD",
        source_vuln_type="sensitive_data",
        target_vuln_type="file_upload",
        condition="敏感信息泄露获取管理员凭证或API Key",
        action="使用泄露的凭证登录后台访问文件上传功能",
        privilege_escalation="user -> admin",
        required_pre_privilege="admin",
        granted_post_privilege="admin",
    ),
    # ── 敏感信息泄露 -> SQL注入 ──
    ChainRule(
        rule_id="SENSITIVE-TO-SQL",
        source_vuln_type="sensitive_data",
        target_vuln_type="sql_injection",
        condition="敏感信息泄露获取内部API参数或凭证",
        action="使用泄露的信息访问SQL注入接口",
        privilege_escalation="user -> admin",
        required_pre_privilege="admin",
        granted_post_privilege="admin",
    ),
    # ── 路径穿越 -> 文件上传 ──
    ChainRule(
        rule_id="PATH-TO-UPLOAD",
        source_vuln_type="path_traversal",
        target_vuln_type="file_upload",
        condition="路径穿越读取配置文件获取管理员凭证",
        action="使用获取的凭证访问后台文件上传功能",
        privilege_escalation="user -> admin",
        required_pre_privilege="admin",
        granted_post_privilege="admin",
    ),
    # ── 路径穿越 -> SQL注入 ──
    ChainRule(
        rule_id="PATH-TO-SQL",
        source_vuln_type="path_traversal",
        target_vuln_type="sql_injection",
        condition="路径穿越读取配置文件获取数据库连接信息",
        action="使用获取的数据库信息直接访问或进一步利用SQL注入",
        privilege_escalation="user -> admin",
        required_pre_privilege="admin",
        granted_post_privilege="admin",
    ),
    # ── XSS -> 文件上传 ──
    ChainRule(
        rule_id="XSS-TO-UPLOAD",
        source_vuln_type="xss",
        target_vuln_type="file_upload",
        condition="XSS窃取管理员Cookie/Session",
        action="使用窃取的管理员会话访问后台文件上传功能",
        privilege_escalation="user -> admin",
        required_pre_privilege="admin",
        granted_post_privilege="admin",
    ),
    # ── SSRF -> SQL注入 ──
    ChainRule(
        rule_id="SSRF-TO-SQL",
        source_vuln_type="ssrf",
        target_vuln_type="sql_injection",
        condition="SSRF探测内部服务，发现可访问的SQL接口",
        action="通过SSRF访问内部SQL注入接口",
        privilege_escalation="user -> admin",
        required_pre_privilege="admin",
        granted_post_privilege="admin",
    ),
    # ── SQL注入 -> 反序列化 ──
    ChainRule(
        rule_id="SQL-TO-DESER",
        source_vuln_type="sql_injection",
        target_vuln_type="deserialization",
        condition="SQL注入获取管理员凭证，访问反序列化接口",
        action="使用管理员权限访问反序列化入口",
        privilege_escalation="user -> admin",
        required_pre_privilege="admin",
        granted_post_privilege="admin",
    ),
    # ── 文件上传 -> 反序列化 ──
    ChainRule(
        rule_id="UPLOAD-TO-DESER",
        source_vuln_type="file_upload",
        target_vuln_type="deserialization",
        condition="通过文件上传 WebShell 获得初始执行权",
        action="利用 WebShell 访问反序列化入口扩大控制",
        privilege_escalation="admin -> system",
        required_pre_privilege="admin",
        granted_post_privilege="system",
    ),
]


def find_chain_rule(
    source_vuln_type: str,
    target_vuln_type: str,
) -> ChainRule | None:
    """查找两个漏洞类型之间的串联规则。

    Args:
        source_vuln_type: 源漏洞类型
        target_vuln_type: 目标漏洞类型

    Returns:
        匹配的 ChainRule，无匹配返回 None
    """
    for rule in CHAIN_RULES:
        if (
            rule.source_vuln_type == source_vuln_type
            and rule.target_vuln_type == target_vuln_type
        ):
            return rule
    return None


def find_all_chainable_targets(source_vuln_type: str) -> list[ChainRule]:
    """查找源漏洞类型可以串联到的所有目标漏洞类型。

    Args:
        source_vuln_type: 源漏洞类型

    Returns:
        所有匹配的 ChainRule 列表
    """
    return [rule for rule in CHAIN_RULES if rule.source_vuln_type == source_vuln_type]


def can_chain(
    source_vuln_type: str,
    target_vuln_type: str,
    source_privilege_level: str | None = None,
) -> ChainRule | None:
    """判断两个漏洞能否串联。

    串联条件：
    1. 存在从 source_vuln_type 到 target_vuln_type 的串联规则
    2. 源漏洞的后置权限级别 >= 目标漏洞的前置权限要求

    Args:
        source_vuln_type: 源漏洞类型
        target_vuln_type: 目标漏洞类型
        source_privilege_level: 源漏洞的权限变化字符串（如 "anonymous -> admin"）

    Returns:
        匹配的 ChainRule（可串联），None（不可串联）
    """
    rule = find_chain_rule(source_vuln_type, target_vuln_type)
    if rule is None:
        return None

    # 检查权限：源漏洞的后置权限 >= 目标漏洞的前置权限要求
    if source_privilege_level:
        _, source_post_rank = parse_privilege_pair(source_privilege_level)
    else:
        source_post_rank = privilege_rank(
            get_vuln_profile(source_vuln_type).privilege_level.split("->")[-1].strip()
            if get_vuln_profile(source_vuln_type).privilege_level
            else "none"
        )

    required_rank = privilege_rank(rule.required_pre_privilege)

    if source_post_rank >= required_rank:
        return rule
    return None


# ──────────────────────────────────────────────────────
# 组合风险等级计算
# ──────────────────────────────────────────────────────


def calculate_chain_severity(
    vuln_types: list[str],
    individual_cvss_scores: list[float | None] | None = None,
) -> tuple[str, float]:
    """计算攻击链的组合风险等级和组合 CVSS 评分。

    组合风险等级取链中所有漏洞的最高风险等级，并在此基础上提升一级
    （因为组合攻击比单点攻击危害更大），但不超过 critical。

    Args:
        vuln_types: 链中所有漏洞类型列表
        individual_cvss_scores: 各漏洞的 CVSS 评分列表

    Returns:
        (组合风险等级, 组合CVSS评分)
    """
    if not vuln_types:
        return ("info", 0.0)

    # 获取各漏洞类型的默认评分
    from app.scoring.cvss import _VULN_TYPE_DEFAULTS

    scores: list[float] = []
    severities: list[str] = []

    for i, vt in enumerate(vuln_types):
        if individual_cvss_scores and i < len(individual_cvss_scores):
            score = individual_cvss_scores[i]
        else:
            defaults = _VULN_TYPE_DEFAULTS.get(vt, {})
            score = defaults.get("base_score", 5.0)

        if score is None:
            score = 5.0
        scores.append(score)

        defaults = _VULN_TYPE_DEFAULTS.get(vt, {})
        sev = defaults.get("base_severity", "medium")
        severities.append(sev)

    # 最高 CVSS 评分
    max_score = max(scores) if scores else 0.0

    # 组合评分：取最高分 + 链长度加成（每多一步加0.5，上限10.0）
    chain_bonus = min(0.5 * (len(vuln_types) - 1), 2.0)
    combined_score = min(max_score + chain_bonus, 10.0)

    # 组合风险等级
    severity_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    rank_to_severity = {v: k for k, v in severity_rank.items()}

    max_sev_rank = max(severity_rank.get(s, 2) for s in severities) if severities else 2

    # 组合攻击提升一级，但不超过 critical
    combined_rank = min(max_sev_rank + (1 if len(vuln_types) > 1 else 0), 4)
    combined_severity = rank_to_severity[combined_rank]

    return (combined_severity, round(combined_score, 1))


def calculate_final_impact(vuln_types: list[str]) -> str:
    """根据攻击链的漏洞类型组合推断最终影响描述。

    Args:
        vuln_types: 链中所有漏洞类型列表（按攻击顺序）

    Returns:
        最终影响描述字符串
    """
    if not vuln_types:
        return "未知影响"

    # 如果链中包含能直接 RCE 的漏洞类型
    rce_types = {"command_injection", "deserialization", "file_upload"}
    if any(vt in rce_types for vt in vuln_types):
        return "获取服务器完全控制权（RCE），可执行任意命令、持久化后门、横向移动"

    # 如果链中包含数据获取类漏洞
    data_types = {"sql_injection", "broken_access", "sensitive_data", "path_traversal"}
    if any(vt in data_types for vt in vuln_types):
        return "数据库内容泄露、敏感信息窃取、可能获取管理员凭证用于进一步攻击"

    # 如果链中包含 SSRF
    if "ssrf" in vuln_types:
        return "内网服务探测与信息泄露，可能作为跳板攻击内部系统"

    # 如果链中包含 XSS
    if "xss" in vuln_types:
        return "客户端脚本执行，可窃取用户会话凭证"

    # 默认
    return "多个安全漏洞组合利用，扩大攻击面和数据泄露范围"
