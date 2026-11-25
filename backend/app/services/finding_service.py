"""漏洞管理服务模块。

本模块封装漏洞数据的全部业务逻辑：
- save_findings(db, redis, task_id, findings_data)：批量保存漏洞记录 + WS 事件
- get_findings(db, task_id, filters)：查询任务下的漏洞列表
- get_finding(db, finding_id)：获取单条漏洞详情
- get_finding_summary(db, task_id)：获取漏洞统计摘要
- update_finding_status(db, finding_id, status, reason)：更新漏洞状态
- merge_duplicate_findings(db, task_id)：合并重复漏洞
"""

import logging
from typing import Any

from redis.asyncio import Redis
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import FindingNotFoundError
from app.models import Finding
from app.utils import generate_id
from app.websockets.publisher import EventPublisher

logger = logging.getLogger(__name__)

# 默认置信度
_DEFAULT_CONFIDENCE = 0.5


async def save_findings(
    db: AsyncSession,
    redis: Redis,
    task_id: str,
    findings_data: list[dict[str, Any]],
    agent: str = "code_audit_agent",
) -> list[Finding]:
    """批量保存漏洞记录。

    将 taint engine + cvss scoring 处理后的 finding 字典列表
    写入 findings 表，并为每条新漏洞发布 finding_new WebSocket 事件。

    去重逻辑：如果同一 task_id + file_path + line_start + vuln_type
    已存在，则跳过（不重复插入）。

    Args:
        db: 数据库会话
        redis: Redis 连接
        task_id: 任务 ID
        findings_data: finding 字典列表（每条包含 vuln_type / cwe / owasp /
                       severity / cvss_score / cvss_vector / file_path /
                       line_start / line_end / snippet / source_code /
                       sink_code / taint_path / detected_by / confidence）
        agent: 日志中的 agent 名称

    Returns:
        已保存的 Finding ORM 对象列表
    """
    saved: list[Finding] = []

    if not findings_data:
        logger.info("[finding_service] No findings to save for task=%s", task_id)
        return saved

    # 查询已存在的 findings，用于去重
    existing = await db.execute(select(Finding).where(Finding.task_id == task_id))
    existing_set: set[tuple[str, int, str]] = set()
    for row in existing.scalars():
        key = (
            row.file_path or "",
            row.line_start or 0,
            row.vuln_type or "",
        )
        existing_set.add(key)

    for fdict in findings_data:
        file_path = fdict.get("file_path", "")
        line_start = fdict.get("line_start", 0)
        vuln_type = fdict.get("vuln_type", "other")

        # 去重检查
        dedup_key = (file_path, line_start, vuln_type)
        if dedup_key in existing_set:
            logger.debug(
                "[finding_service] Skipping duplicate: %s:%d %s",
                file_path,
                line_start,
                vuln_type,
            )
            continue

        # 创建 Finding 记录
        finding = Finding(
            id=generate_id(),
            task_id=task_id,
            vuln_type=vuln_type,
            cwe_id=fdict.get("cwe") or fdict.get("cwe_id"),
            owasp=fdict.get("owasp"),
            status=fdict.get("status", "unverified"),
            severity=fdict.get("severity", "info"),
            cvss_score=fdict.get("cvss_score"),
            cvss_vector=fdict.get("cvss_vector"),
            file_path=file_path or None,
            line_start=line_start or None,
            line_end=fdict.get("line_end") or None,
            snippet=fdict.get("snippet"),
            source_file=fdict.get("source_file") or file_path or None,
            source_line=fdict.get("source_line"),
            source_code=fdict.get("source_code"),
            sink_file=fdict.get("sink_file") or file_path or None,
            sink_line=fdict.get("sink_line"),
            sink_code=fdict.get("sink_code"),
            taint_path=fdict.get("taint_path"),
            code_context=fdict.get("code_context"),
            detected_by=fdict.get("detected_by", "semgrep"),
            confidence=fdict.get("confidence", _DEFAULT_CONFIDENCE),
            remediation=fdict.get("remediation"),
        )
        db.add(finding)
        saved.append(finding)
        existing_set.add(dedup_key)

    # 批量 flush
    if saved:
        await db.flush()
        logger.info(
            "[finding_service] Saved %d findings for task=%s (skipped %d duplicates)",
            len(saved),
            task_id,
            len(findings_data) - len(saved),
        )

        # 发布 WebSocket 事件
        for finding in saved:
            await EventPublisher.publish(
                redis,
                task_id,
                "finding_new",
                {
                    "finding_id": finding.id,
                    "vuln_type": finding.vuln_type,
                    "severity": finding.severity,
                    "cvss_score": finding.cvss_score,
                    "file_path": finding.file_path,
                    "line_start": finding.line_start,
                    "status": finding.status,
                    "detected_by": finding.detected_by,
                    "cwe_id": finding.cwe_id,
                    "owasp": finding.owasp,
                    "source_code": finding.source_code,
                    "sink_code": finding.sink_code,
                    "snippet": finding.snippet,
                },
            )

    return saved


async def get_findings(
    db: AsyncSession,
    task_id: str,
    severity: str | None = None,
    status: str | None = None,
    vuln_type: str | None = None,
    detected_by: str | None = None,
    limit: int = 200,
    offset: int = 0,
) -> list[Finding]:
    """查询任务下的漏洞列表。

    Args:
        db: 数据库会话
        task_id: 任务 ID
        severity: 按严重等级过滤（critical/high/medium/low/info）
        status: 按验证状态过滤（unverified/verified/latent/false_positive）
        vuln_type: 按漏洞类型过滤
        detected_by: 按检测工具过滤
        limit: 返回上限
        offset: 偏移量

    Returns:
        Finding ORM 对象列表
    """
    stmt = (
        select(Finding)
        .where(Finding.task_id == task_id)
        .order_by(
            # 按严重等级排序：critical > high > medium > low > info
            # 使用 CASE 映射
            Finding.severity.desc(),
            Finding.cvss_score.desc().nulls_last(),
            Finding.created_at.desc(),
        )
        .limit(limit)
        .offset(offset)
    )

    if severity:
        stmt = stmt.where(Finding.severity == severity)
    if status:
        stmt = stmt.where(Finding.status == status)
    if vuln_type:
        stmt = stmt.where(Finding.vuln_type == vuln_type)
    if detected_by:
        stmt = stmt.where(Finding.detected_by == detected_by)

    result = await db.execute(stmt)
    return list(result.scalars().all())


async def get_finding(
    db: AsyncSession,
    finding_id: str,
) -> Finding:
    """获取单条漏洞详情。

    Args:
        db: 数据库会话
        finding_id: 漏洞 ID

    Returns:
        Finding ORM 对象

    Raises:
        FindingNotFoundError: 漏洞不存在
    """
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if finding is None:
        raise FindingNotFoundError(f"Finding {finding_id} not found")
    return finding


async def get_finding_summary(
    db: AsyncSession,
    task_id: str,
) -> dict[str, Any]:
    """获取漏洞统计摘要。

    按严重等级、验证状态和漏洞类型分组统计。

    Args:
        db: 数据库会话
        task_id: 任务 ID

    Returns:
        {
            "total": int,
            "by_severity": {"critical": N, "high": N, ...},
            "by_status": {"unverified": N, "verified": N, ...},
            "by_type": {"sql_injection": N, "command_injection": N, ...},
        }
    """
    # 总数
    total_result = await db.execute(
        select(func.count(Finding.id)).where(Finding.task_id == task_id)
    )
    total = total_result.scalar() or 0

    # 按严重等级
    severity_result = await db.execute(
        select(Finding.severity, func.count(Finding.id))
        .where(Finding.task_id == task_id)
        .group_by(Finding.severity)
    )
    by_severity = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }
    for sev, cnt in severity_result:
        by_severity[sev] = cnt

    # 按验证状态
    status_result = await db.execute(
        select(Finding.status, func.count(Finding.id))
        .where(Finding.task_id == task_id)
        .group_by(Finding.status)
    )
    by_status = {
        "unverified": 0,
        "verified": 0,
        "latent": 0,
        "false_positive": 0,
    }
    for sts, cnt in status_result:
        by_status[sts] = cnt

    # 按漏洞类型
    type_result = await db.execute(
        select(Finding.vuln_type, func.count(Finding.id))
        .where(Finding.task_id == task_id)
        .group_by(Finding.vuln_type)
    )
    by_type = {vt: cnt for vt, cnt in type_result}

    return {
        "total": total,
        "by_severity": by_severity,
        "by_status": by_status,
        "by_type": by_type,
    }


async def update_finding_status(
    db: AsyncSession,
    redis: Redis,
    task_id: str,
    finding_id: str,
    status: str,
    severity: str | None = None,
    cvss_score: float | None = None,
    reason: str | None = None,
) -> Finding:
    """更新漏洞状态。

    Args:
        db: 数据库会话
        redis: Redis 连接
        task_id: 任务 ID
        finding_id: 漏洞 ID
        status: 新状态（verified/unverified/false_positive/latent）
        severity: 覆盖严重等级（可选）
        cvss_score: 覆盖 CVSS 分数（可选）
        reason: 状态变更原因（可选）

    Returns:
        更新后的 Finding ORM 对象

    Raises:
        FindingNotFoundError: 漏洞不存在
    """
    finding = await get_finding(db, finding_id)
    old_status = finding.status
    finding.status = status

    if severity is not None:
        finding.severity = severity
    if cvss_score is not None:
        finding.cvss_score = cvss_score

    await db.flush()

    # 发布状态更新事件
    await EventPublisher.publish(
        redis,
        task_id,
        "finding_status_changed",
        {
            "finding_id": finding.id,
            "old_status": old_status,
            "new_status": status,
            "severity": finding.severity,
            "cvss_score": finding.cvss_score,
            "reason": reason,
        },
    )

    logger.info(
        "[finding_service] Finding %s status changed: %s -> %s",
        finding_id,
        old_status,
        status,
    )
    return finding


async def merge_duplicate_findings(
    db: AsyncSession,
    task_id: str,
) -> int:
    """合并重复漏洞。

    同一 task_id + file_path + line_start + vuln_type 的记录只保留一条
    （保留置信度最高的）。

    Args:
        db: 数据库会话
        task_id: 任务 ID

    Returns:
        被删除的重复记录数
    """
    findings = await get_findings(db, task_id, limit=10000)
    if not findings:
        return 0

    # 按去重 key 分组
    groups: dict[tuple, list[Finding]] = {}
    for f in findings:
        key = (f.file_path or "", f.line_start or 0, f.vuln_type or "")
        groups.setdefault(key, []).append(f)

    deleted_count = 0
    for key, group in groups.items():
        if len(group) <= 1:
            continue
        # 按 confidence 降序排序，保留第一个
        group.sort(key=lambda x: x.confidence or 0, reverse=True)
        for f in group[1:]:
            await db.delete(f)
            deleted_count += 1

    if deleted_count:
        await db.flush()
        logger.info(
            "[finding_service] Merged %d duplicate findings for task=%s",
            deleted_count,
            task_id,
        )

    return deleted_count
