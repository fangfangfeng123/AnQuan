"""Bandit 扫描器适配器模块。

本模块适配 Bandit 工具（Python 专用安全扫描器）：
- 在沙箱容器内执行 `bandit -f json` 命令
- 解析 Bandit JSON 输出为统一 RawFinding 格式
- 映射 Bandit issue test ID 到漏洞类型和 CWE 编号
- 映射 Bandit severity（HIGH / MEDIUM / LOW）到系统 Severity 枚举

Bandit 通过 pip 安装在沙箱镜像中（python:3.11-slim + pip install bandit）。
仅用于 Python 项目扫描。
"""

import json
import logging
import re
from typing import Any

from app.scanners.base import BaseScanner, RawFinding

logger = logging.getLogger(__name__)

# ── Bandit severity -> 系统 severity 映射 ──
_BANDIT_SEVERITY_MAP = {
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
}

# ── Bandit confidence -> 系统置信度映射 ──
_BANDIT_CONFIDENCE_MAP = {
    "HIGH": 0.9,
    "MEDIUM": 0.6,
    "LOW": 0.3,
}

# ── Bandit test ID -> 漏洞类型/CWE/OWASP 映射 ──
# Bandit test ID 格式: B001-B999
# 参考: https://bandit.readthedocs.io/en/latest/plugins/index.html
_BANDIT_TEST_MAP = {
    "B601": {  # paramiko.exec_command
        "vuln_type": "command_injection",
        "cwe": "CWE-78",
        "owasp": "A03:2021",
        "description": "Paramiko exec_command 可能导致命令注入",
    },
    "B602": {  # subprocess shell=True
        "vuln_type": "command_injection",
        "cwe": "CWE-78",
        "owasp": "A03:2021",
        "description": "subprocess 调用使用 shell=True 可能导致命令注入",
    },
    "B603": {  # subprocess without shell
        "vuln_type": "command_injection",
        "cwe": "CWE-78",
        "owasp": "A03:2021",
        "description": "subprocess 调用缺少 shell 参数校验",
    },
    "B605": {  # os.system
        "vuln_type": "command_injection",
        "cwe": "CWE-78",
        "owasp": "A03:2021",
        "description": "os.system 调用可能导致命令注入",
    },
    "B607": {  # subprocess partial path
        "vuln_type": "command_injection",
        "cwe": "CWE-78",
        "owasp": "A03:2021",
        "description": "subprocess 使用部分路径可能导致命令注入",
    },
    "B324": {  # hashlib weak hash
        "vuln_type": "sensitive_data",
        "cwe": "CWE-327",
        "owasp": "A02:2021",
        "description": "使用弱哈希算法（MD5/SHA1）",
    },
    "B105": {  # hardcoded password
        "vuln_type": "sensitive_data",
        "cwe": "CWE-798",
        "owasp": "A02:2021",
        "description": "硬编码密码字符串",
    },
    "B106": {  # hardcoded password function arg
        "vuln_type": "sensitive_data",
        "cwe": "CWE-798",
        "owasp": "A02:2021",
        "description": "函数参数中硬编码密码",
    },
    "B107": {  # hardcoded password default
        "vuln_type": "sensitive_data",
        "cwe": "CWE-798",
        "owasp": "A02:2021",
        "description": "默认参数中硬编码密码",
    },
    "B108": {  # hardcoded tmp directory
        "vuln_type": "insecure_config",
        "cwe": "CWE-798",
        "owasp": "A02:2021",
        "description": "硬编码临时目录",
    },
    "B501": {  # request ssl verify disabled
        "vuln_type": "insecure_config",
        "cwe": "CWE-295",
        "owasp": "A02:2021",
        "description": "SSL 证书验证被禁用",
    },
    "B301": {  # pickle
        "vuln_type": "deserialization",
        "cwe": "CWE-502",
        "owasp": "A08:2021",
        "description": "pickle 反序列化可能导致远程代码执行",
    },
    "B303": {  # crypto hashlib md5
        "vuln_type": "sensitive_data",
        "cwe": "CWE-327",
        "owasp": "A02:2021",
        "description": "使用弱加密哈希算法",
    },
    "B311": {  # random.random
        "vuln_type": "insecure_config",
        "cwe": "CWE-330",
        "owasp": "A02:2021",
        "description": "使用不安全的随机数生成器",
    },
    "B608": {  # hardcoded sql expressions
        "vuln_type": "sql_injection",
        "cwe": "CWE-89",
        "owasp": "A03:2021",
        "description": "SQL 查询中可能存在字符串拼接注入",
    },
    "B612": {  # httpoxy
        "vuln_type": "other",
        "cwe": "CWE-20",
        "owasp": "A06:2021",
        "description": "HTTPoxy 代理头注入",
    },
}


def _lookup_test_id(test_id: str) -> dict[str, str]:
    """根据 Bandit test ID 查找漏洞信息。

    Returns:
        包含 vuln_type / cwe / owasp / description 的字典
    """
    info = _BANDIT_TEST_MAP.get(test_id)
    if info:
        return info

    # 未知 test ID 的默认处理
    return {
        "vuln_type": "other",
        "cwe": "",
        "owasp": "",
        "description": "",
    }


class BanditScanner(BaseScanner):
    """Bandit 扫描器。

    在沙箱容器内运行 bandit -f json 扫描 Python 源码，
    解析 JSON 输出为统一 RawFinding 格式。

    用法:
        scanner = BanditScanner()
        findings = await scanner.scan(db, redis, task_id, "/workspace/source")
    """

    def __init__(self) -> None:
        super().__init__(name="bandit")

    async def run(
        self,
        db,
        redis,
        task_id: str,
        source_path: str = "/workspace/source",
        **kwargs: Any,
    ) -> str:
        """在沙箱容器内执行 bandit 扫描。

        使用 `bandit -r -f json` 递归扫描源码目录。
        仅适用于 Python 项目。

        Args:
            db: 数据库会话
            redis: Redis 连接
            task_id: 任务 ID
            source_path: 源码挂载路径
            **kwargs:
                timeout: 扫描超时秒数
                skip_tests: 跳过的 Bandit test ID 列表

        Returns:
            bandit JSON 输出字符串
        """
        from app.services.sandbox_service import exec_in_sandbox

        timeout = kwargs.get("timeout", 180)
        skip_tests = kwargs.get("skip_tests", [])

        # 构建 bandit 命令
        # -r: 递归扫描
        # -f json: JSON 格式输出
        # -q: 安静模式（不打印 banner）
        # -ll: 只报告 LOW 及以上（可选，默认全部报告）
        skip_arg = ""
        if skip_tests:
            skip_arg = " -s " + ",".join(skip_tests)

        command = f"cd {source_path} && bandit -r . -f json -q{skip_arg}"

        self.logger.info("[%s] Running bandit scan (task=%s)", self.name, task_id)

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

        # bandit 退出码: 0 = 无发现, 1 = 有低危, 2 = 有中高危
        if exit_code not in (0, 1, 2):
            self.logger.warning(
                "[%s] bandit exited with code %d, stderr: %s",
                self.name,
                exit_code,
                stderr[:500],
            )

        if not stdout.strip():
            self.logger.warning("[%s] bandit returned empty stdout", self.name)
            return ""

        self.logger.info(
            "[%s] bandit scan completed (exit=%d, output_len=%d)",
            self.name,
            exit_code,
            len(stdout),
        )

        return stdout

    def parse_output(self, raw_output: str) -> list[RawFinding]:
        """解析 Bandit JSON 输出为 RawFinding 列表。

        Bandit JSON 结构:
        {
          "results": [
            {
              "filename": "app.py",
              "issue_text": "Possible SQL injection via string concatenation",
              "issue_confidence": "MEDIUM",
              "issue_severity": "MEDIUM",
              "issue_cwe": {
                "id": 89,
                "link": "https://...",
                "name": "..."
              },
              "test_id": "B608",
              "line_number": 10,
              "line_range": [10, 11],
              "more_info": "https://...",
              "issue_severity_confidence": "MEDIUM"
            }
          ]
        }
        """
        findings: list[RawFinding] = []

        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError as exc:
            self.logger.error("Failed to parse bandit JSON: %s", exc)
            return []

        results = data.get("results", [])
        if not results:
            self.logger.info("[%s] No findings in bandit output", self.name)
            return []

        for item in results:
            finding = self._parse_result(item)
            if finding:
                findings.append(finding)

        return findings

    def _parse_result(self, item: dict[str, Any]) -> RawFinding | None:
        """解析单个 bandit 结果项为 RawFinding。"""
        try:
            test_id = item.get("test_id", "unknown")
            filename = item.get("filename", "")
            if filename.startswith("./"):
                filename = filename[2:]
            issue_text = item.get("issue_text", "")
            confidence_raw = item.get("issue_confidence", "MEDIUM")
            severity_raw = item.get("issue_severity", "MEDIUM")
            line_number = item.get("line_number", 0)
            line_range = item.get("line_range", [line_number])

            # 提取 CWE
            cwe_info = item.get("issue_cwe", {})
            cwe_id = cwe_info.get("id", "")
            cwe = f"CWE-{cwe_id}" if cwe_id else ""

            # 查找漏洞类型
            vuln_info = _lookup_test_id(test_id)
            vuln_type = vuln_info.get("vuln_type", "other")
            owasp = vuln_info.get("owasp", "")
            description = vuln_info.get("description", issue_text)

            # 使用 bandit 提供的 CWE 优先
            if not cwe and vuln_info.get("cwe"):
                cwe = vuln_info["cwe"]

            # 映射 severity 和 confidence
            severity_hint = _BANDIT_SEVERITY_MAP.get(severity_raw.upper(), "low")
            confidence = _BANDIT_CONFIDENCE_MAP.get(confidence_raw.upper(), 0.5)

            line_start = line_range[0] if line_range else line_number
            line_end = (
                line_range[-1] if line_range and len(line_range) > 1 else line_start
            )

            # 代码片段
            snippet = item.get("code", "")
            if not snippet:
                snippet = issue_text

            return RawFinding(
                rule_id=f"bandit-{test_id}",
                vuln_type=vuln_type,
                detected_by="bandit",
                cwe=cwe,
                owasp=owasp,
                file_path=filename,
                line_start=line_start,
                line_end=line_end,
                snippet=snippet,
                description=description or issue_text,
                severity_hint=severity_hint,
                confidence=confidence,
                remediation=item.get("more_info", ""),
                extra={
                    "test_id": test_id,
                    "bandit_severity": severity_raw,
                    "bandit_confidence": confidence_raw,
                    "line_range": line_range,
                },
            )
        except Exception as exc:
            self.logger.error("Failed to parse bandit result: %s", exc)
            return None

    def get_version(self) -> str:
        """获取 bandit 版本。"""
        return "bandit"
