"""审计规则加载器。

从 config/audit_rules/ 目录按语言加载 JSON 格式的扫描规则，
供 Code Audit Agent 根据 runtimeProfile.language 选择对应规则集。
"""

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# 规则文件目录
_RULES_DIR = Path(__file__).parent

# 语言 -> 规则文件名映射
_LANGUAGE_FILES = {
    "python": "python_rules.json",
    "javascript": "javascript_rules.json",
    "js": "javascript_rules.json",
    "typescript": "javascript_rules.json",
    "ts": "javascript_rules.json",
    "java": "java_rules.json",
}


def load_rules_for_language(language: str) -> list[dict[str, Any]]:
    """加载指定语言的审计规则。

    Args:
        language: 语言名称（python / javascript / java 等）

    Returns:
        规则字典列表，每条包含 id / vuln_type / cwe / owasp /
        severity / description / source_patterns / sink_patterns /
        sanitizer_patterns
    """
    filename = _LANGUAGE_FILES.get(language.lower())
    if filename is None:
        logger.warning("No audit rules for language: %s", language)
        return []

    rule_path = _RULES_DIR / filename
    if not rule_path.exists():
        logger.warning("Rule file not found: %s", rule_path)
        return []

    try:
        with open(rule_path, encoding="utf-8") as f:
            data = json.load(f)
        rules = data.get("rules", [])
        logger.info("Loaded %d rules for language=%s", len(rules), language)
        return rules
    except Exception as exc:
        logger.error("Failed to load rules from %s: %s", rule_path, exc)
        return []


def load_rules_for_framework(language: str, framework: str) -> list[dict[str, Any]]:
    """加载指定语言和框架的审计规则。

    先加载语言级规则，再根据 framework 过滤适用的规则。
    目前框架过滤不裁剪规则（所有规则都适用于所有框架），
    但保留接口以便未来按框架加载不同规则集。

    Args:
        language: 语言名称
        framework: 框架名称（flask / django / express 等）

    Returns:
        规则字典列表
    """
    rules = load_rules_for_language(language)
    # 当前版本不做框架级过滤，返回全部语言规则
    return rules


def get_rule_by_id(rule_id: str) -> dict[str, Any] | None:
    """按规则 ID 查找单条规则。

    遍历所有语言的规则文件查找匹配 ID。
    """
    for filename in _LANGUAGE_FILES.values():
        rule_path = _RULES_DIR / filename
        if not rule_path.exists():
            continue
        try:
            with open(rule_path, encoding="utf-8") as f:
                data = json.load(f)
            for rule in data.get("rules", []):
                if rule.get("id") == rule_id:
                    return rule
        except Exception:
            continue
    return None


def list_available_languages() -> list[str]:
    """列出所有有规则文件的语言。"""
    return list(set(_LANGUAGE_FILES.keys()))
