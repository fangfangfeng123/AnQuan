"""扫描器基类模块。

本模块定义所有扫描器的统一接口和数据结构：
- BaseScanner：抽象基类，定义 run() 和 parse_output() 接口
- ScanResult：统一扫描结果数据结构
- RawFinding：扫描器原始输出转换为统一格式后的中间结果

每个具体扫描器（SemgrepScanner / BanditScanner 等）继承此类并实现
run() 和 parse_output()，最终输出 list[RawFinding] 供 taint engine 进一步分析。
"""

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class RawFinding:
    """扫描器原始输出转换后的统一中间格式。

    与最终 Finding ORM 模型的区别：
    - RawFinding 是扫描器层面的初步结果，尚未经过污点分析
    - 经过 taint engine 处理后会补充 source_code / sink_code / taint_path
    - 经过 cvss scoring 后会补充 cvss_score / cvss_vector / 最终 severity
    """

    # ── 基本标识 ──
    rule_id: str  # 规则 ID（如 semgrep 规则名或 bandit test ID）
    vuln_type: str  # 漏洞类型（sql_injection / command_injection 等）
    detected_by: str  # 检测工具名（semgrep / bandit / taint_engine）

    # ── CWE / OWASP ──
    cwe: str = ""  # 如 "CWE-89"
    owasp: str = ""  # 如 "A03:2021"

    # ── 位置信息 ──
    file_path: str = ""  # 相对路径
    line_start: int = 0
    line_end: int = 0
    snippet: str = ""  # 命中代码片段

    # ── 描述 ──
    description: str = ""
    severity_hint: str = ""  # 扫描器给出的原始严重等级（会被 cvss 覆盖）
    confidence: float = 0.5  # 扫描器置信度 (0-1)

    # ── 修复建议 ──
    remediation: str = ""

    # ── 额外元数据 ──
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """转换为字典格式，供 taint engine 和 finding_service 使用。"""
        return {
            "rule_id": self.rule_id,
            "vuln_type": self.vuln_type,
            "detected_by": self.detected_by,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "file_path": self.file_path,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "snippet": self.snippet,
            "description": self.description,
            "severity_hint": self.severity_hint,
            "confidence": self.confidence,
            "remediation": self.remediation,
            "extra": self.extra,
            # 初始状态为 unverified
            "status": "unverified",
        }


class BaseScanner(ABC):
    """扫描器抽象基类。

    所有具体扫描器继承此类并实现：
    - run(target_path) -> str：在沙箱内执行扫描工具，返回原始 JSON 输出
    - parse_output(raw_output) -> list[RawFinding]：解析原始输出为 RawFinding 列表
    - get_version() -> str：获取工具版本

    调用方通过 scan() 方法获得完整的 RawFinding 列表。
    """

    def __init__(self, name: str = "base"):
        self.name = name
        self.logger = logging.getLogger(f"scanners.{name}")

    async def scan(
        self,
        db,
        redis,
        task_id: str,
        source_path: str = "/workspace/source",
        **kwargs: Any,
    ) -> list[RawFinding]:
        """执行完整扫描流程：run -> parse_output -> 返回 RawFinding 列表。

        Args:
            db: 数据库会话
            redis: Redis 连接
            task_id: 任务 ID
            source_path: 源码在沙箱内的挂载路径
            **kwargs: 传递给 run() 的额外参数

        Returns:
            RawFinding 列表（可能为空）
        """
        try:
            raw_output = await self.run(
                db=db,
                redis=redis,
                task_id=task_id,
                source_path=source_path,
                **kwargs,
            )
            if not raw_output:
                self.logger.info("[%s] Scanner returned empty output", self.name)
                return []
            findings = self.parse_output(raw_output)
            self.logger.info(
                "[%s] Parsed %d findings from output", self.name, len(findings)
            )
            return findings
        except Exception as exc:
            self.logger.error("[%s] Scan failed: %s", self.name, exc)
            return []

    @abstractmethod
    async def run(
        self,
        db,
        redis,
        task_id: str,
        source_path: str = "/workspace/source",
        **kwargs: Any,
    ) -> str:
        """在沙箱内执行扫描工具，返回原始 JSON 输出字符串。

        子类必须实现此方法。
        """
        raise NotImplementedError

    @abstractmethod
    def parse_output(self, raw_output: str) -> list[RawFinding]:
        """将扫描工具的原始 JSON 输出解析为 RawFinding 列表。

        子类必须实现此方法。
        """
        raise NotImplementedError

    def get_version(self) -> str:
        """获取工具版本号（子类可覆盖）。"""
        return "unknown"
