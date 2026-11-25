"""代码审计服务层模块。

本模块是 Code Audit Agent 的核心服务层，负责：
1. 根据 runtimeProfile.language 选择扫描规则和扫描器
2. 在沙箱容器内执行 Semgrep / Bandit 静态扫描
3. 从沙箱读取源码文件内容，调用 TaintFacade 做 Source/Sink 分析
4. 合并扫描器结果与污点分析结果，提取 taintPath
5. 调用 CVSS 评分模块计算严重等级和 CVSS 分数
6. 通过 finding_service 保存漏洞到数据库
7. 发布 WebSocket 事件（finding_new / phase_completed）+ 写入日志

输入：task_id + 沙箱容器（已创建并挂载源码）+ runtimeProfile（来自 recon）
输出：finding 列表（全部 status=unverified）+ Code Audit 阶段 completed + 日志 + WS 事件
"""

import json
import logging
from typing import Any

from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config.audit_rules.rule_loader import load_rules_for_framework
from app.core.errors import SandboxError
from app.models import RuntimeProfile, Task
from app.scanners.base import RawFinding
from app.scanners.bandit import BanditScanner
from app.scanners.semgrep import SemgrepScanner
from app.scoring.cvss import score_findings_batch
from app.services.finding_service import save_findings
from app.services.recon_service import get_runtime_profile
from app.services.sandbox_service import exec_in_sandbox
from app.taint.facade import TaintFacade
from app.utils import append_task_log, generate_id
from app.websockets.publisher import EventPublisher

logger = logging.getLogger(__name__)

# Code Audit 阶段标识
AUDIT_AGENT = "code_audit_agent"
AUDIT_PHASE = "code_audit"

# 沙箱内源码挂载路径
SOURCE_PATH = "/workspace/source"

# 支持的扫描器映射（按语言）
_SCANNER_MAP: dict[str, list[str]] = {
    "python": ["semgrep", "bandit"],
    "javascript": ["semgrep"],
    "js": ["semgrep"],
    "typescript": ["semgrep"],
    "ts": ["semgrep"],
    "java": ["semgrep"],
}


async def _publish(
    redis: Redis,
    task_id: str,
    event_type: str,
    payload: dict,
) -> None:
    """发布 WebSocket 事件。"""
    await EventPublisher.publish(redis, task_id, event_type, payload)


async def _exec_in_sandbox(
    db: AsyncSession,
    redis: Redis,
    task_id: str,
    command: str,
    timeout: int = 300,
) -> str:
    """在沙箱中执行命令并返回 stdout。

    对命令失败有韧性：返回空字符串而非抛异常。
    """
    try:
        result = await exec_in_sandbox(
            db,
            redis,
            task_id,
            command,
            timeout=timeout,
            agent=AUDIT_AGENT,
            phase=AUDIT_PHASE,
        )
        return result.get("stdout", "")
    except SandboxError as e:
        logger.warning("沙箱命令执行失败: cmd=%s, error=%s", command[:80], e)
        return ""


# ── 主流程 ──


async def run_code_audit(
    db: AsyncSession,
    redis: Redis,
    task_id: str,
) -> dict[str, Any]:
    """执行完整代码审计流程。

    流程：
    1. 获取 runtimeProfile（来自 recon 阶段）
    2. 根据语言加载扫描规则
    3. 在沙箱内执行 Semgrep 扫描
    4. 如果是 Python，额外执行 Bandit 扫描
    5. 合并扫描器结果，去重
    6. 从沙箱读取有发现的源码文件内容
    7. 调用 TaintFacade 做 Source/Sink 分析
    8. 合并扫描结果与污点分析结果
    9. 调用 CVSS 评分
    10. 通过 finding_service 保存
    11. 发布 WS 事件 + 写日志

    Args:
        db: 数据库会话
        redis: Redis 连接
        task_id: 任务 ID

    Returns:
        审计摘要字典，包含 finding_count / by_severity / by_type 等

    Raises:
        SandboxError: 沙箱执行失败
    """
    # ── 1. 获取 runtimeProfile ──
    await _publish(
        redis,
        task_id,
        "code_audit_progress",
        {"step": "loading_profile", "message": "正在加载环境侦察结果..."},
    )

    profile = await get_runtime_profile(db, task_id)
    if profile is None:
        raise SandboxError(
            "未找到 runtimeProfile，请确认环境侦察阶段已完成",
            detail={"task_id": task_id},
        )

    language = profile.language or "unknown"
    framework = profile.framework or "generic"

    logger.info(
        "Code Audit 启动: task=%s, lang=%s, fw=%s", task_id, language, framework
    )

    # ── 2. 加载扫描规则 ──
    rules = load_rules_for_framework(language, framework)
    logger.info("加载 %d 条审计规则 (lang=%s, fw=%s)", len(rules), language, framework)

    await _publish(
        redis,
        task_id,
        "code_audit_progress",
        {
            "step": "rules_loaded",
            "message": f"已加载 {len(rules)} 条审计规则",
            "language": language,
            "framework": framework,
            "rule_count": len(rules),
        },
    )

    # ── 3. 执行扫描器 ──
    all_raw_findings: list[RawFinding] = []
    scanner_names = _SCANNER_MAP.get(language.lower(), ["semgrep"])

    # 3a. Semgrep 扫描
    if "semgrep" in scanner_names:
        await _publish(
            redis,
            task_id,
            "code_audit_progress",
            {"step": "semgrep_scanning", "message": "正在执行 Semgrep 静态扫描..."},
        )

        semgrep_scanner = SemgrepScanner()
        semgrep_findings = await semgrep_scanner.scan(
            db=db,
            redis=redis,
            task_id=task_id,
            source_path=SOURCE_PATH,
            config="auto",
            timeout=300,
        )
        logger.info("Semgrep 发现 %d 条结果", len(semgrep_findings))
        all_raw_findings.extend(semgrep_findings)

    # 3b. Bandit 扫描（仅 Python）
    if "bandit" in scanner_names and language.lower() in ("python",):
        await _publish(
            redis,
            task_id,
            "code_audit_progress",
            {"step": "bandit_scanning", "message": "正在执行 Bandit 安全扫描..."},
        )

        bandit_scanner = BanditScanner()
        bandit_findings = await bandit_scanner.scan(
            db=db,
            redis=redis,
            task_id=task_id,
            source_path=SOURCE_PATH,
            timeout=180,
        )
        logger.info("Bandit 发现 %d 条结果", len(bandit_findings))
        all_raw_findings.extend(bandit_findings)

    # ── 4. 去重 RawFindings ──
    all_raw_findings = _deduplicate_raw_findings(all_raw_findings)
    logger.info("合并去重后共 %d 条 RawFinding", len(all_raw_findings))

    # ── 5. 将 RawFindings 转为 finding 字典 ──
    finding_dicts: list[dict[str, Any]] = []
    for raw in all_raw_findings:
        fdict = raw.to_dict()
        # 补充 CWE/OWASP 字段名（to_dict 用 cwe，finding_service 用 cwe 或 cwe_id）
        fdict["cwe"] = raw.cwe
        finding_dicts.append(fdict)

    # ── 6. 从沙箱读取源码文件，做污点分析 ──
    await _publish(
        redis,
        task_id,
        "code_audit_progress",
        {"step": "taint_analysis", "message": "正在进行污点追踪分析..."},
    )

    taint_findings = await _run_taint_analysis(
        db, redis, task_id, language, framework, finding_dicts
    )

    # ── 7. 合并扫描结果与污点分析结果 ──
    merged_findings = _merge_findings(finding_dicts, taint_findings)
    logger.info(
        "合并后共 %d 条 finding（扫描 %d + 污点 %d）",
        len(merged_findings),
        len(finding_dicts),
        len(taint_findings),
    )

    # ── 8. CVSS 评分 ──
    if merged_findings:
        score_findings_batch(merged_findings)
        logger.info("CVSS 评分完成，共 %d 条", len(merged_findings))

    # ── 9. 保存 findings ──
    await _publish(
        redis,
        task_id,
        "code_audit_progress",
        {
            "step": "saving_findings",
            "message": f"正在保存 {len(merged_findings)} 条漏洞记录...",
            "finding_count": len(merged_findings),
        },
    )

    saved_findings = await save_findings(
        db=db,
        redis=redis,
        task_id=task_id,
        findings_data=merged_findings,
        agent=AUDIT_AGENT,
    )

    # ── 10. 写日志 ──
    # 统计摘要
    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    by_type: dict[str, int] = {}
    for f in merged_findings:
        sev = f.get("severity", "info")
        by_severity[sev] = by_severity.get(sev, 0) + 1
        vt = f.get("vuln_type", "other")
        by_type[vt] = by_type.get(vt, 0) + 1

    log_msg = (
        f"代码审计完成: language={language}, framework={framework}, "
        f"scanner_findings={len(finding_dicts)}, taint_findings={len(taint_findings)}, "
        f"merged={len(merged_findings)}, saved={len(saved_findings)}, "
        f"by_severity={by_severity}"
    )
    await append_task_log(
        db,
        task_id,
        AUDIT_PHASE,
        AUDIT_AGENT,
        "info",
        log_msg,
        detail={
            "language": language,
            "framework": framework,
            "rule_count": len(rules),
            "scanner_finding_count": len(finding_dicts),
            "taint_finding_count": len(taint_findings),
            "merged_finding_count": len(merged_findings),
            "saved_finding_count": len(saved_findings),
            "by_severity": by_severity,
            "by_type": by_type,
            "scanners_used": scanner_names,
        },
    )
    await db.commit()

    # ── 11. 返回摘要 ──
    summary = {
        "language": language,
        "framework": framework,
        "rule_count": len(rules),
        "scanner_finding_count": len(finding_dicts),
        "taint_finding_count": len(taint_findings),
        "merged_finding_count": len(merged_findings),
        "saved_finding_count": len(saved_findings),
        "by_severity": by_severity,
        "by_type": by_type,
        "scanners_used": scanner_names,
    }

    logger.info("Code Audit 完成: task=%s, summary=%s", task_id, summary)
    return summary


async def _run_taint_analysis(
    db: AsyncSession,
    redis: Redis,
    task_id: str,
    language: str,
    framework: str,
    scanner_findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """对扫描器发现有漏洞的文件做污点追踪分析。

    从沙箱中读取有发现的源码文件内容，调用 TaintFacade 进行
    Source/Sink 分析，返回带完整污点路径的 finding 字典列表。

    Args:
        db: 数据库会话
        redis: Redis 连接
        task_id: 任务 ID
        language: 主语言
        framework: 主框架
        scanner_findings: 扫描器产出的 finding 字典列表

    Returns:
        污点分析产出的 finding 字典列表
    """
    # 收集扫描器发现文件路径
    file_paths: set[str] = set()
    for f in scanner_findings:
        fp = f.get("file_path", "")
        if fp:
            file_paths.add(fp)

    # 对 Python 项目额外全量扫描 .py 文件，避免扫描器空结果导致污点分析也不执行
    source_listing = await _exec_in_sandbox(
        db,
        redis,
        task_id,
        f"find {SOURCE_PATH} -type f -name '*.py' | head -200",
    )
    for line in source_listing.splitlines():
        line = line.strip()
        if not line:
            continue
        relative_file = line
        if line.startswith(f"{SOURCE_PATH}/"):
            relative_file = line[len(f"{SOURCE_PATH}/") :]
        file_paths.add(relative_file)

    # 从沙箱读取源码文件内容
    source_files: list[dict[str, str]] = []
    for fp in file_paths:
        # 构建沙箱内完整路径
        sandbox_path = f"{SOURCE_PATH}/{fp}" if not fp.startswith("/") else fp
        content = await _exec_in_sandbox(
            db, redis, task_id, f"cat {sandbox_path} 2>/dev/null"
        )
        if content.strip():
            source_files.append({"path": fp, "content": content})
        else:
            logger.debug("无法读取源码文件: %s", fp)

    if not source_files:
        logger.warning("无法从沙箱读取任何源码文件，跳过污点分析")
        return []

    logger.info("从沙箱读取 %d 个源码文件用于污点分析", len(source_files))

    # 扫描器有时只返回 message 片段（如 "requires login"），
    # 这里用真实源码回填 snippet/source_code/sink_code，避免补丁和详情为空。
    source_by_path = {sf["path"]: sf["content"] for sf in source_files}
    for fdict in scanner_findings:
        relative_file = (fdict.get("file_path") or "").replace("\\", "/")
        if relative_file.startswith("/workspace/source/"):
            relative_file = relative_file[len("/workspace/source/") :]
        content = source_by_path.get(relative_file)
        if content is None:
            continue
        file_lines = content.splitlines()
        line_start = fdict.get("line_start") or 1
        line_end = fdict.get("line_end") or line_start
        start = max(0, int(line_start) - 1)
        end = min(len(file_lines), int(line_end))
        real_code = "\n".join(file_lines[start:end]) or content

        if not fdict.get("snippet") or "requires login" in fdict.get("snippet", ""):
            fdict["snippet"] = real_code
        if (
            not fdict.get("source_code")
            or "requires login" in fdict.get("source_code", "")
        ):
            fdict["source_code"] = real_code
        if not fdict.get("sink_code") or "requires login" in fdict.get("sink_code", ""):
            fdict["sink_code"] = real_code

    # 调用 TaintFacade 批量分析
    taint_results = TaintFacade.analyze_files(source_files, language, framework)
    taint_findings = TaintFacade.results_to_findings(taint_results)

    logger.info("污点分析产出 %d 条 finding", len(taint_findings))
    return taint_findings


def _deduplicate_raw_findings(
    findings: list[RawFinding],
) -> list[RawFinding]:
    """对 RawFinding 列表去重。

    去重 key: (file_path, line_start, vuln_type, detected_by)
    保留第一条（置信度最高的）。
    """
    seen: set[tuple] = set()
    unique: list[RawFinding] = []

    for f in findings:
        key = (f.file_path, f.line_start, f.vuln_type, f.detected_by)
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)

    return unique


def _merge_findings(
    scanner_findings: list[dict[str, Any]],
    taint_findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """合并扫描器结果与污点分析结果。

    合并策略：
    1. 以 (file_path, line_start, vuln_type) 为 key 匹配
    2. 如果两边都发现同一个漏洞：
       - 以扫描器结果为基础
       - 用污点分析的 Source/Sink/taintPath 覆盖扫描器结果中的空字段
       - detected_by 合并（如 "semgrep+taint_engine"）
       - confidence 取较高值
    3. 如果只有扫描器发现：保留扫描器结果（Source/Sink 可能为空）
    4. 如果只有污点分析发现：直接添加污点分析结果

    Args:
        scanner_findings: 扫描器产出的 finding 字典列表
        taint_findings: 污点分析产出的 finding 字典列表

    Returns:
        合并后的 finding 字典列表
    """
    # 构建污点分析结果索引
    taint_index: dict[tuple, dict[str, Any]] = {}
    for tf in taint_findings:
        key = (
            tf.get("file_path", ""),
            tf.get("line_start", 0),
            tf.get("vuln_type", ""),
        )
        taint_index[key] = tf

    merged: list[dict[str, Any]] = []
    matched_taint_keys: set[tuple] = set()

    # 遍历扫描器结果，合并污点信息
    for sf in scanner_findings:
        key = (
            sf.get("file_path", ""),
            sf.get("line_start", 0),
            sf.get("vuln_type", ""),
        )

        tf = taint_index.get(key)
        if tf:
            # 匹配到了污点分析结果，合并
            matched_taint_keys.add(key)
            merged_finding = _merge_single(sf, tf)
            merged.append(merged_finding)
        else:
            # 没有匹配到污点分析，保留扫描器结果
            # 补充 source_code/sink_code：用 snippet 作为 fallback
            sf_copy = dict(sf)
            snippet = sf_copy.get("snippet") or ""
            if snippet:
                if not sf_copy.get("source_code"):
                    sf_copy["source_code"] = snippet
                if not sf_copy.get("sink_code"):
                    sf_copy["sink_code"] = snippet
                if not sf_copy.get("sink_file"):
                    sf_copy["sink_file"] = sf_copy.get("file_path", "")
                if not sf_copy.get("sink_line"):
                    sf_copy["sink_line"] = sf_copy.get("line_start", 0)
                if not sf_copy.get("source_file"):
                    sf_copy["source_file"] = sf_copy.get("file_path", "")
                if not sf_copy.get("source_line"):
                    sf_copy["source_line"] = sf_copy.get("line_start", 0)
            merged.append(sf_copy)

    # 添加只有污点分析发现的漏洞
    for key, tf in taint_index.items():
        if key not in matched_taint_keys:
            merged.append(dict(tf))

    return merged


def _merge_single(
    scanner_finding: dict[str, Any],
    taint_finding: dict[str, Any],
) -> dict[str, Any]:
    """合并单条扫描器结果与污点分析结果。

    扫描器提供：vuln_type / cwe / owasp / snippet / confidence / detected_by
    污点分析提供：source_code / source_file / source_line /
                  sink_code / sink_file / sink_line / taint_path / confidence

    合并优先级：污点分析的 Source/Sink/taintPath 优先（更精确），
    扫描器的 CWE/OWASP/snippet 优先（扫描器有 metadata）。
    """
    merged = dict(scanner_finding)

    # 污点分析提供的字段（优先使用）
    taint_fields = [
        "source_file",
        "source_line",
        "source_code",
        "sink_file",
        "sink_line",
        "sink_code",
        "taint_path",
        "code_context",
    ]
    for field in taint_fields:
        taint_val = taint_finding.get(field)
        if taint_val:
            merged[field] = taint_val

    # detected_by 合并
    scanner_by = scanner_finding.get("detected_by", "scanner")
    taint_by = taint_finding.get("detected_by", "taint_engine")
    if taint_by and taint_by not in scanner_by:
        merged["detected_by"] = f"{scanner_by}+{taint_by}"

    # confidence 取较高值
    scanner_conf = scanner_finding.get("confidence", 0.5)
    taint_conf = taint_finding.get("confidence", 0.5)
    merged["confidence"] = max(scanner_conf, taint_conf)

    # CWE/OWASP 优先用扫描器的（有 metadata），如果扫描器没有则用污点分析的
    if not merged.get("cwe") and taint_finding.get("cwe"):
        merged["cwe"] = taint_finding["cwe"]
    if not merged.get("owasp") and taint_finding.get("owasp"):
        merged["owasp"] = taint_finding["owasp"]

    # 确保状态为 unverified
    merged["status"] = "unverified"

    return merged
