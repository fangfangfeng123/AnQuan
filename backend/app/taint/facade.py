"""污点分析统一入口模块。

本模块为 Agent 层提供污点分析的统一调用接口。
Agent 不直接调用 engine，只通过 facade 访问。

TaintFacade 提供:
- analyze(source_path, language, framework) -> list[TaintResult]
  分析单个源码文件
- analyze_files(source_files, language, framework) -> list[TaintResult]
  批量分析多个文件
- results_to_findings(results) -> list[dict]
  将 TaintResult 转换为 Finding 字典列表
"""

import logging
import os
from dataclasses import dataclass

from app.taint.engine import analyze_file
from app.taint.result import TaintResult

logger = logging.getLogger(__name__)


@dataclass
class TaintFacade:
    """污点分析统一入口。

    用法:
        facade = TaintFacade()
        results = facade.analyze(code, "app.py", "python", "flask")
        findings = facade.results_to_findings(results)
    """

    @staticmethod
    def analyze(
        code_content: str,
        file_path: str,
        language: str,
        framework: str = "generic",
    ) -> list[TaintResult]:
        """分析单个文件。

        Args:
            code_content: 源码内容
            file_path: 文件相对路径
            language: 语言
            framework: 框架

        Returns:
            TaintResult 列表（可能为空）
        """
        if not code_content.strip():
            return []

        try:
            return analyze_file(code_content, file_path, language, framework)
        except Exception as e:
            logger.error(f"TaintFacade.analyze error: {file_path}: {e}", exc_info=True)
            return []

    @staticmethod
    def analyze_files(
        source_files: list[dict],
        language: str,
        framework: str = "generic",
    ) -> list[TaintResult]:
        """批量分析多个文件。

        Args:
            source_files: [{"path": "app.py", "content": "..."}]
            language: 语言
            framework: 框架

        Returns:
            合并的 TaintResult 列表
        """
        all_results: list[TaintResult] = []

        for sf in source_files:
            path = sf.get("path", "unknown")
            content = sf.get("content", "")
            if not content:
                continue

            results = TaintFacade.analyze(content, path, language, framework)
            all_results.extend(results)

        logger.info(
            f"TaintFacade.analyze_files: {len(source_files)} files, "
            f"{len(all_results)} findings"
        )

        return all_results

    @staticmethod
    def analyze_from_sandbox_output(
        file_listing: list[dict],
        language: str,
        framework: str = "generic",
    ) -> list[TaintResult]:
        """从沙箱输出的文件列表进行分析。

        沙箱执行 `cat` 命令后返回的文件内容列表，每项包含
        path 和 content。

        Args:
            file_listing: [{"path": "app.py", "content": "import flask..."}]
            language: 语言
            framework: 框架

        Returns:
            合并的 TaintResult 列表
        """
        return TaintFacade.analyze_files(file_listing, language, framework)

    @staticmethod
    def results_to_findings(
        results: list[TaintResult],
    ) -> list[dict]:
        """将 TaintResult 列表转换为 Finding 字典列表。

        Args:
            results: TaintResult 列表

        Returns:
            Finding 字典列表，可直接用于 FindingService.save_findings
        """
        findings: list[dict] = []

        for r in results:
            if not r.is_vulnerable:
                continue
            findings.append(r.to_finding_dict())

        logger.info(
            f"TaintFacade.results_to_findings: {len(results)} results "
            f"-> {len(findings)} findings"
        )

        return findings

    @staticmethod
    def analyze_code(
        code_content: str,
        file_path: str = "inline.py",
        language: str = "python",
        framework: str = "generic",
    ) -> list[dict]:
        """一步到位：分析代码并直接返回 Finding 字典列表。

        这是 Agent 层最常用的便捷方法，合并了 analyze + results_to_findings。

        Args:
            code_content: 源码内容
            file_path: 文件路径（用于结果记录）
            language: 语言
            framework: 框架

        Returns:
            Finding 字典列表
        """
        results = TaintFacade.analyze(code_content, file_path, language, framework)
        return TaintFacade.results_to_findings(results)
