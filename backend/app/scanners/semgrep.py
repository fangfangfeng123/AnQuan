"""Semgrep 扫描器适配器模块。

本模块适配 Semgrep 工具：
- 在沙箱容器内执行 `semgrep --json` 命令
- 解析 Semgrep JSON 输出为统一 RawFinding 格式
- 映射 Semgrep 规则 ID 到漏洞类型和 CWE 编号
- 映射 Semgrep severity 到系统 Severity 枚举
- 支持自定义规则集配置

Semgrep 安装在沙箱镜像中（python:3.11-slim + pip install semgrep）。
扫描器通过 exec_in_sandbox 在容器内运行 semgrep，获取 JSON 输出。
"""

import json
import logging
import re
from typing import Any

from app.scanners.base import BaseScanner, RawFinding

logger = logging.getLogger(__name__)

# ── Semgrep severity -> 系统 severity 映射 ──
_SEMGREP_SEVERITY_MAP = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "low",
}

# ── Semgrep 规则 ID -> 漏洞类型/CWE/OWASP 映射 ──
# 支持自动推断：如果规则 ID 包含 sqli/sql_injection 等关键字
_RULE_ID_TO_VULN = {
    "sqli": {
        "vuln_type": "sql_injection",
        "cwe": "CWE-89",
        "owasp": "A03:2021",
    },
    "sql-injection": {
        "vuln_type": "sql_injection",
        "cwe": "CWE-89",
        "owasp": "A03:2021",
    },
    "sql_injection": {
        "vuln_type": "sql_injection",
        "cwe": "CWE-89",
        "owasp": "A03:2021",
    },
    "cmd-injection": {
        "vuln_type": "command_injection",
        "cwe": "CWE-78",
        "owasp": "A03:2021",
    },
    "command-injection": {
        "vuln_type": "command_injection",
        "cwe": "CWE-78",
        "owasp": "A03:2021",
    },
    "command_injection": {
        "vuln_type": "command_injection",
        "cwe": "CWE-78",
        "owasp": "A03:2021",
    },
    "cmd-injection": {
        "vuln_type": "command_injection",
        "cwe": "CWE-78",
        "owasp": "A03:2021",
    },
    "os-command": {
        "vuln_type": "command_injection",
        "cwe": "CWE-78",
        "owasp": "A03:2021",
    },
    "os-system": {
        "vuln_type": "command_injection",
        "cwe": "CWE-78",
        "owasp": "A03:2021",
    },
    "file-upload": {
        "vuln_type": "file_upload",
        "cwe": "CWE-434",
        "owasp": "A04:2021",
    },
    "idor": {
        "vuln_type": "broken_access",
        "cwe": "CWE-639",
        "owasp": "A01:2021",
    },
    "broken-access": {
        "vuln_type": "broken_access",
        "cwe": "CWE-639",
        "owasp": "A01:2021",
    },
    "hardcoded": {
        "vuln_type": "sensitive_data",
        "cwe": "CWE-798",
        "owasp": "A02:2021",
    },
    "hardcoded-secrets": {
        "vuln_type": "sensitive_data",
        "cwe": "CWE-798",
        "owasp": "A02:2021",
    },
    "secret": {
        "vuln_type": "sensitive_data",
        "cwe": "CWE-798",
        "owasp": "A02:2021",
    },
    "xss": {
        "vuln_type": "xss",
        "cwe": "CWE-79",
        "owasp": "A03:2021",
    },
    "ssrf": {
        "vuln_type": "ssrf",
        "cwe": "CWE-918",
        "owasp": "A10:2021",
    },
    "deserialization": {
        "vuln_type": "deserialization",
        "cwe": "CWE-502",
        "owasp": "A08:2021",
    },
    "path-traversal": {
        "vuln_type": "path_traversal",
        "cwe": "CWE-22",
        "owasp": "A01:2021",
    },
}


def _infer_vuln_type(rule_id: str) -> tuple[str, str, str]:
    """根据规则 ID 推断漏洞类型、CWE 和 OWASP 分类。

    Args:
        rule_id: Semgrep 规则 ID

    Returns:
        (vuln_type, cwe, owasp) 元组
    """
    rule_lower = rule_id.lower()

    # 精确匹配
    for key, info in _RULE_ID_TO_VULN.items():
        if key in rule_lower:
            return info["vuln_type"], info["cwe"], info["owasp"]

    # 模糊匹配
    if "sql" in rule_lower:
        return "sql_injection", "CWE-89", "A03:2021"
    if (
        "cmd" in rule_lower
        or "command" in rule_lower
        or "exec" in rule_lower
        or "system" in rule_lower
    ):
        return "command_injection", "CWE-78", "A03:2021"
    if "upload" in rule_lower or "file" in rule_lower:
        return "file_upload", "CWE-434", "A04:2021"
    if "access" in rule_lower or "idor" in rule_lower:
        return "broken_access", "CWE-639", "A01:2021"
    if "secret" in rule_lower or "password" in rule_lower or "token" in rule_lower:
        return "sensitive_data", "CWE-798", "A02:2021"

    return "other", "", ""


class SemgrepScanner(BaseScanner):
    """Semgrep 扫描器。

    在沙箱容器内运行 semgrep --json 扫描源码，
    解析 JSON 输出为统一 RawFinding 格式。

    用法:
        scanner = SemgrepScanner()
        findings = await scanner.scan(db, redis, task_id, "/workspace/source")
    """

    def __init__(self) -> None:
        super().__init__(name="semgrep")

    async def run(
        self,
        db,
        redis,
        task_id: str,
        source_path: str = "/workspace/source",
        **kwargs: Any,
    ) -> str:
        """在沙箱容器内执行 semgrep 扫描。

        使用 `--config auto` 自动规则集，或传入自定义规则路径。
        输出 JSON 格式结果。

        Args:
            db: 数据库会话
            redis: Redis 连接
            task_id: 任务 ID
            source_path: 源码挂载路径
            **kwargs:
                config: semgrep 配置参数（默认 "auto"）
                timeout: 扫描超时秒数

        Returns:
            semgrep JSON 输出字符串
        """
        from app.services.sandbox_service import exec_in_sandbox

        config = kwargs.get("config", "auto")
        timeout = kwargs.get("timeout", 300)

        # 构建 semgrep 命令
        command = (
            f"cd {source_path} && "
            f"semgrep --json --config {config} --quiet --no-rewrite-rule-ids ."
        )

        self.logger.info(
            "[%s] Running semgrep scan (task=%s, config=%s)",
            self.name,
            task_id,
            config,
        )

        result = await exec_in_sandbox(
            db=db,
            redis=redis,
            task_id=task_id,
            command=command,
            timeout=timeout,
            working_dir=source_path,
            agent="code_audit_agent",
            phase="code_audit",
        )

        exit_code = result.get("exit_code", -1)
        stdout = result.get("stdout", "")
        stderr = result.get("stderr", "")

        # semgrep 退出码 0 = 无发现，1 = 有发现（都是正常）
        if exit_code not in (0, 1):
            self.logger.warning(
                "[%s] semgrep exited with code %d, stderr: %s",
                self.name,
                exit_code,
                stderr[:500],
            )

        if not stdout.strip():
            self.logger.warning("[%s] semgrep returned empty stdout", self.name)
            return ""

        self.logger.info(
            "[%s] semgrep scan completed (exit=%d, output_len=%d)",
            self.name,
            exit_code,
            len(stdout),
        )

        return stdout

    def parse_output(self, raw_output: str) -> list[RawFinding]:
        """解析 Semgrep JSON 输出为 RawFinding 列表。

        Semgrep JSON 结构:
        {
          "results": [
            {
              "check_id": "python.flask.security.injection.sql-injection",
              "path": "app.py",
              "start": {"line": 10, "col": 5},
              "end": {"line": 10, "col": 50},
              "extra": {
                "message": "Possible SQL injection via string concatenation",
                "severity": "ERROR",
                "metadata": {
                  "cwe": "CWE-89: ...",
                  "owasp": "A03:2021 - Injection",
                  "confidence": "HIGH"
                }
              }
            }
          ]
        }
        """
        findings: list[RawFinding] = []

        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError as exc:
            self.logger.error("Failed to parse semgrep JSON: %s", exc)
            return []

        results = data.get("results", [])
        if not results:
            self.logger.info("[%s] No findings in semgrep output", self.name)
            return []

        for item in results:
            finding = self._parse_result(item)
            if finding:
                findings.append(finding)

        return findings

    def _parse_result(self, item: dict[str, Any]) -> RawFinding | None:
        """解析单个 semgrep 结果项为 RawFinding。"""
        try:
            check_id = item.get("check_id", "unknown")
            path = item.get("path", "")
            if path.startswith("./"):
                path = path[2:]
            start = item.get("start", {})
            end = item.get("end", {})
            extra = item.get("extra", {})

            line_start = start.get("line", 0)
            line_end = end.get("line", line_start)

            message = extra.get("message", "")
            severity_raw = extra.get("severity", "INFO")
            severity_hint = _SEMGREP_SEVERITY_MAP.get(severity_raw.upper(), "low")

            # 从 metadata 提取 CWE 和 confidence
            metadata = extra.get("metadata", {})
            cwe_raw = metadata.get("cwe", "")
            if isinstance(cwe_raw, list):
                cwe_raw = " ".join(str(v) for v in cwe_raw)
            elif not isinstance(cwe_raw, str):
                cwe_raw = str(cwe_raw)
            confidence_str = metadata.get("confidence", "MEDIUM")
            owasp_raw = metadata.get("owasp", "")
            if isinstance(owasp_raw, list):
                owasp_raw = " ".join(str(v) for v in owasp_raw)
            elif not isinstance(owasp_raw, str):
                owasp_raw = str(owasp_raw)

            # 提取 CWE 编号
            cwe_match = re.search(r"CWE-(\d+)", cwe_raw)
            cwe = f"CWE-{cwe_match.group(1)}" if cwe_match else ""

            # 提取 OWASP 编号
            owasp_match = re.search(r"(A\d{2}:\d{4})", owasp_raw)
            owasp = owasp_match.group(1) if owasp_match else ""

            # 从规则 ID 推断漏洞类型
            vuln_type, inferred_cwe, inferred_owasp = _infer_vuln_type(check_id)

            # 使用 metadata 中的 CWE 优先，否则用推断的
            cwe = cwe or inferred_cwe
            owasp = owasp or inferred_owasp

            # 转换 confidence
            confidence_map = {
                "HIGH": 0.9,
                "MEDIUM": 0.6,
                "LOW": 0.3,
            }
            confidence = confidence_map.get(str(confidence_str).upper(), 0.5)

            # 提取代码片段
            lines = item.get("extra", {}).get("lines", "")
            snippet = lines.strip() if lines else ""

            return RawFinding(
                rule_id=check_id,
                vuln_type=vuln_type,
                detected_by="semgrep",
                cwe=cwe,
                owasp=owasp,
                file_path=path,
                line_start=line_start,
                line_end=line_end,
                snippet=snippet,
                description=message,
                severity_hint=severity_hint,
                confidence=confidence,
                remediation=metadata.get("remediation", ""),
                extra={
                    "semgrep_severity": severity_raw,
                    "metadata": metadata,
                },
            )
        except Exception as exc:
            self.logger.error("Failed to parse semgrep result: %s", exc)
            return None

    def get_version(self) -> str:
        """获取 semgrep 版本（通过沙箱执行 semgrep --version）。"""
        return "semgrep"
