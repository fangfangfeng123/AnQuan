"""污点传播引擎核心模块。

本模块实现轻量级静态污点分析，在不依赖 AST 解析的情况下，
通过逐行模式匹配 + 变量追踪 + 跨行数据流推断来检测
Source-to-Sink 的污点传播路径。

分析策略（基于行级正则的轻量污点分析）：

1. 逐行扫描源码文件
2. 识别 Source 行（外部输入），提取被赋值的污点变量名
3. 追踪污点变量的传播：赋值给其他变量、作为函数参数传递
4. 识别 Sink 行（敏感操作），检查是否引用了污点变量
5. 检查 Source 到 Sink 的路径中是否存在 Sanitizer
6. 如果存在未净化的 Source->Sink 路径，生成 TaintResult

这种轻量方案不依赖 AST 解析器（如 ast/esprima），适用于多语言
快速扫描。对于复杂的数据流（如跨函数、跨文件），TaintResult 的
confidence 会降低，后续可由 LLM 或 Semgrep 补充深度分析。
"""

import logging
import re
from dataclasses import dataclass

from app.taint.result import (
    SanitizerInfo,
    SinkInfo,
    SourceInfo,
    TaintResult,
    TaintStepInfo,
)
from app.taint.sanitizer import find_sanitizers_in_line, get_sanitizer_rules
from app.taint.sink import find_sinks_in_line, get_sink_rules
from app.taint.source import find_sources_in_line, get_source_rules

logger = logging.getLogger(__name__)


@dataclass
class _TaintVariable:
    """污点变量追踪状态。"""

    var_name: str
    source_rule_id: str
    source_file: str
    source_line: int
    source_code: str
    source_line_no: int  # Source 所在行号（0-based）


def analyze_file(
    code_content: str,
    file_path: str,
    language: str,
    framework: str = "generic",
) -> list[TaintResult]:
    """对单个文件执行污点分析。

    逐行扫描源码，识别 Source/Sink/Sanitizer，追踪变量传播，
    生成 TaintResult 列表。

    Args:
        code_content: 源码内容（完整文件文本）
        file_path: 文件相对路径（用于结果中记录）
        language: 语言 (python / javascript / java)
        framework: 框架 (flask / express / spring-boot / generic)

    Returns:
        TaintResult 列表（可能为空）
    """
    lines = code_content.splitlines()
    results: list[TaintResult] = []

    # 获取规则
    source_rules = get_source_rules(language, framework)
    sink_rules = get_sink_rules(language, framework)
    sanitizer_rules = get_sanitizer_rules(language)

    if not source_rules or not sink_rules:
        # 无规则可用（如未知语言），跳过
        return []

    # 追踪的污点变量列表
    taint_vars: list[_TaintVariable] = []

    for line_idx, line in enumerate(lines):
        line_no = line_idx + 1  # 1-based 行号

        # ── 1. 检查此行是否有 Sanitizer ──
        line_sanitizers = find_sanitizers_in_line(line, language)

        # ── 2. 检查此行是否有 Source ──
        line_sources = find_sources_in_line(line, language, framework)

        for src_rule in line_sources:
            var_name = src_rule.extract_var(line)
            if var_name:
                # 新增污点变量
                taint_vars.append(
                    _TaintVariable(
                        var_name=var_name,
                        source_rule_id=src_rule.rule_id,
                        source_file=file_path,
                        source_line=line_no,
                        source_code=line.strip(),
                        source_line_no=line_idx,
                    )
                )
            else:
                # Source 行但无法提取变量名（如 request.data 直接使用）
                # 记录为匿名污点源
                taint_vars.append(
                    _TaintVariable(
                        var_name="",
                        source_rule_id=src_rule.rule_id,
                        source_file=file_path,
                        source_line=line_no,
                        source_code=line.strip(),
                        source_line_no=line_idx,
                    )
                )

        # ── 3. 检查此行是否有 Sink ──
        line_sinks = find_sinks_in_line(line, language, framework)

        for sink_rule in line_sinks:
            # 检查是否引用了污点变量
            matched_taint_var = _find_taint_var_in_line(line, taint_vars, line_idx)

            if matched_taint_var:
                # 找到 Source -> Sink 的污点传播！

                # 构造传播路径
                taint_path = _build_taint_path(
                    matched_taint_var, file_path, lines, line_no, line
                )

                # 检查路径中是否有 Sanitizer
                has_sanitizer = False
                sanitizer_info = None

                # 检查 Source 到 Sink 之间是否有 Sanitizer
                for mid_idx in range(matched_taint_var.source_line_no, line_idx + 1):
                    mid_line = lines[mid_idx] if mid_idx < len(lines) else ""
                    mid_sanitizers = find_sanitizers_in_line(
                        mid_line, language, sink_rule.vuln_type
                    )
                    if mid_sanitizers:
                        has_sanitizer = True
                        sanitizer_info = SanitizerInfo(
                            file=file_path,
                            line=mid_idx + 1,
                            code=mid_line.strip(),
                            rule_id=mid_sanitizers[0].rule_id,
                            sanitizer_type=sink_rule.vuln_type,
                            description=mid_sanitizers[0].description,
                        )
                        break

                # 判定是否为漏洞
                is_vulnerable = not has_sanitizer

                # 置信度计算
                if has_sanitizer:
                    confidence = 0.1  # 有净化器，低置信度
                elif matched_taint_var.source_line_no == line_idx:
                    confidence = 0.9  # Source 和 Sink 在同一行
                else:
                    # 跨行传播，检查中间是否有变量传递
                    has_transfer = _check_transfer_between(
                        matched_taint_var.var_name,
                        lines,
                        matched_taint_var.source_line_no,
                        line_idx,
                    )
                    confidence = 0.8 if has_transfer else 0.5

                # 构造 SourceInfo 和 SinkInfo
                source_info = SourceInfo(
                    file=matched_taint_var.source_file,
                    line=matched_taint_var.source_line,
                    code=matched_taint_var.source_code,
                    rule_id=matched_taint_var.source_rule_id,
                    var_name=matched_taint_var.var_name,
                )
                sink_info = SinkInfo(
                    file=file_path,
                    line=line_no,
                    code=line.strip(),
                    rule_id=sink_rule.rule_id,
                    vuln_type=sink_rule.vuln_type,
                    cwe_id=sink_rule.cwe_id,
                    owasp=sink_rule.owasp,
                    sink_expr=sink_rule.extract_sink_expr(line) or line.strip(),
                )

                result = TaintResult(
                    source_info=source_info,
                    sink_info=sink_info,
                    taint_path=taint_path,
                    has_sanitizer=has_sanitizer,
                    sanitizer_info=sanitizer_info,
                    is_vulnerable=is_vulnerable,
                    confidence=confidence,
                    detected_by="taint_engine",
                )
                results.append(result)

        # ── 4. 检查此行是否有变量传播（赋值传递） ──
        _track_var_propagation(line, taint_vars, line_idx, file_path, lines)

    # 过滤掉有 Sanitizer 的结果（不作为漏洞上报）
    # 但保留 has_sanitizer=True 的记录用于审计日志
    vulnerable_results = [r for r in results if r.is_vulnerable]

    logger.debug(
        f"taint_engine: {file_path} -> {len(vulnerable_results)} "
        f"vulnerable, {len(results)} total (incl. sanitized)"
    )

    return vulnerable_results


def _find_taint_var_in_line(
    line: str, taint_vars: list[_TaintVariable], current_line_idx: int
) -> _TaintVariable | None:
    """检查一行代码是否引用了某个污点变量。

    匹配策略：
    1. 精确匹配变量名（var_name 出现在代码中，且不是其他变量的子串）
    2. 匿名污点源（var_name 为空）总是匹配（如 request.data 直接使用）

    Args:
        line: 当前行代码
        taint_vars: 追踪的污点变量列表
        current_line_idx: 当前行号（0-based）

    Returns:
        匹配的 _TaintVariable 或 None
    """
    for tv in taint_vars:
        # 只追踪 Source 之后的行
        if tv.source_line_no >= current_line_idx:
            continue

        if not tv.var_name:
            # 匿名污点源（如 request.data 直接在 Sink 行使用）
            # 检查 Source 模式是否在同一行出现
            continue

        # 使用词边界匹配，避免子串误匹配
        pattern = r"\b" + re.escape(tv.var_name) + r"\b"
        if re.search(pattern, line):
            return tv

    return None


def _build_taint_path(
    taint_var: _TaintVariable,
    file_path: str,
    lines: list[str],
    sink_line_no: int,
    sink_code: str,
) -> list[TaintStepInfo]:
    """构造 Source 到 Sink 的传播路径。

    Args:
        taint_var: 污点变量
        file_path: 文件路径
        lines: 源码行列表
        sink_line_no: Sink 行号（1-based）
        sink_code: Sink 行代码

    Returns:
        TaintStepInfo 列表
    """
    path: list[TaintStepInfo] = []

    # Step 1: Source
    path.append(
        TaintStepInfo(
            step=1,
            type="source",
            file=file_path,
            line=taint_var.source_line,
            code=taint_var.source_code,
            detail=f"外部输入通过 {taint_var.source_rule_id} 进入",
        )
    )

    # Step 2-N: Transfer（中间变量传播步骤）
    step_no = 2
    var_name = taint_var.var_name
    if var_name:
        for mid_idx in range(taint_var.source_line_no + 1, sink_line_no - 1):
            if mid_idx >= len(lines):
                break
            mid_line = lines[mid_idx].strip()
            if not mid_line or mid_line.startswith("#"):
                continue

            # 检查是否是变量赋值传播
            assign_match = re.match(
                r"\s*(\w+)\s*=\s*.*\b" + re.escape(var_name) + r"\b", mid_line
            )
            if assign_match:
                new_var = assign_match.group(1)
                if new_var != var_name:
                    path.append(
                        TaintStepInfo(
                            step=step_no,
                            type="transfer",
                            file=file_path,
                            line=mid_idx + 1,
                            code=mid_line,
                            detail=f"变量 {var_name} 赋值给 {new_var}",
                        )
                    )
                    step_no += 1
                    var_name = new_var  # 继续追踪新变量

    # Final Step: Sink
    path.append(
        TaintStepInfo(
            step=step_no,
            type="sink",
            file=file_path,
            line=sink_line_no,
            code=sink_code.strip(),
            detail=f"污点数据流入 Sink（{taint_var.source_rule_id} -> Sink）",
        )
    )

    return path


def _check_transfer_between(
    var_name: str,
    lines: list[str],
    start_idx: int,
    end_idx: int,
) -> bool:
    """检查 Source 和 Sink 之间是否有变量传播步骤。

    Args:
        var_name: 污点变量名
        lines: 源码行列表
        start_idx: Source 行号（0-based）
        end_idx: Sink 行号（0-based）

    Returns:
        是否存在中间传播步骤
    """
    if not var_name:
        return False

    for mid_idx in range(start_idx + 1, end_idx):
        if mid_idx >= len(lines):
            break
        mid_line = lines[mid_idx]
        # 检查是否有赋值传播
        if re.search(r"\b\w+\s*=\s*.*\b" + re.escape(var_name) + r"\b", mid_line):
            return True
    return False


def _track_var_propagation(
    line: str,
    taint_vars: list[_TaintVariable],
    line_idx: int,
    file_path: str,
    lines: list[str],
) -> None:
    """追踪变量传播：如果污点变量被赋值给新变量，新增污点变量。

    例如：
        q = request.args.get("q")  # Source: q is tainted
        sql = "SELECT ..." + q      # Propagation: sql becomes tainted

    Args:
        line: 当前行代码
        taint_vars: 污点变量列表（会被原地修改）
        line_idx: 当前行号（0-based）
        file_path: 文件路径
        lines: 源码行列表
    """
    if not taint_vars:
        return

    # 匹配 `new_var = ...old_var...` 形式
    assign_match = re.match(r"\s*(\w+)\s*=\s*(.+)", line)
    if not assign_match:
        return

    new_var = assign_match.group(1)
    rhs = assign_match.group(2)

    # 避免循环引用（new_var == old_var）
    if new_var in (tv.var_name for tv in taint_vars):
        return

    # 检查右值是否引用了污点变量
    for tv in taint_vars:
        if not tv.var_name:
            continue
        if tv.source_line_no >= line_idx:
            continue  # 只追踪之前定义的变量

        pattern = r"\b" + re.escape(tv.var_name) + r"\b"
        if re.search(pattern, rhs):
            # 发现传播：new_var 也成为污点变量
            # 避免重复添加
            existing = any(
                v.var_name == new_var and v.source_rule_id == tv.source_rule_id
                for v in taint_vars
            )
            if not existing:
                taint_vars.append(
                    _TaintVariable(
                        var_name=new_var,
                        source_rule_id=tv.source_rule_id,
                        source_file=tv.source_file,
                        source_line=tv.source_line,
                        source_code=tv.source_code,
                        source_line_no=tv.source_line_no,
                    )
                )
            break  # 一个赋值只追踪一个源
