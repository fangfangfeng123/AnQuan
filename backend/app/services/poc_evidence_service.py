"""PoC 证据持久化服务模块。

将探针执行结果和验证结论写入 poc_evidence 表，支持同一 finding 多条证据。
本模块是 poc/ 包与业务层的桥梁——所有 DB 写入都集中在 services/ 层，
poc/ 包内仅保留无状态工具（payloads / executor / verifier）。
"""

import logging
from datetime import datetime, timezone
from typing import Any

from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import PocEvidence
from app.utils import generate_id
from app.websockets.publisher import EventPublisher

logger = logging.getLogger(__name__)


async def save_evidence(
    db: AsyncSession,
    redis: Redis,
    task_id: str,
    finding_id: str,
    probe_result: dict[str, Any],
    verification_result: dict[str, Any] | None = None,
) -> PocEvidence:
    """保存单条 PoC 证据记录。

    将探针的请求/响应报文和验证结论写入 poc_evidence 表，
    并发布 poc_evidence_saved WebSocket 事件。

    Args:
        db: 数据库会话
        redis: Redis 连接
        task_id: 任务 ID
        finding_id: 漏洞 ID
        probe_result: 探针执行结果（name/request_method/request_url/...）
        verification_result: 验证结果（matched/validation_status/expected/actual/reason）

    Returns:
        保存后的 PocEvidence ORM 对象
    """
    vr = verification_result or {}

    evidence = PocEvidence(
        id=generate_id(),
        finding_id=finding_id,
        task_id=task_id,
        poc_type="http",
        request_method=probe_result.get("request_method"),
        request_url=probe_result.get("request_url"),
        request_headers=probe_result.get("request_headers"),
        request_body=probe_result.get("request_body"),
        response_status=probe_result.get("response_status"),
        response_headers=probe_result.get("response_headers"),
        response_body=probe_result.get("response_body"),
        expected_feature=vr.get("expected_feature"),
        actual_feature=vr.get("actual_feature"),
        matched=bool(vr.get("matched", False)),
        validation_status=vr.get("validation_status", "pending"),
        error_message=probe_result.get("error"),
        executed_at=datetime.fromisoformat(
            probe_result.get("executed_at", datetime.now(timezone.utc).isoformat())
        )
        if probe_result.get("executed_at")
        else datetime.now(timezone.utc),
        verified_at=datetime.now(timezone.utc)
        if vr.get("validation_status") in ("passed", "failed")
        else None,
    )

    db.add(evidence)
    await db.flush()

    # 发布 WS 事件
    await EventPublisher.publish(
        redis,
        task_id,
        "poc_evidence_saved",
        {
            "evidence_id": evidence.id,
            "finding_id": finding_id,
            "probe_name": probe_result.get("name"),
            "matched": evidence.matched,
            "validation_status": evidence.validation_status,
        },
    )

    logger.info(
        "[poc_evidence_service] Saved evidence %s for finding %s (matched=%s)",
        evidence.id,
        finding_id,
        evidence.matched,
    )

    return evidence


async def get_evidences_by_finding(
    db: AsyncSession,
    finding_id: str,
) -> list[PocEvidence]:
    """获取某个漏洞的所有 PoC 证据。

    Args:
        db: 数据库会话
        finding_id: 漏洞 ID

    Returns:
        PocEvidence ORM 对象列表，按创建时间排序
    """
    result = await db.execute(
        select(PocEvidence)
        .where(PocEvidence.finding_id == finding_id)
        .order_by(PocEvidence.created_at)
    )
    return list(result.scalars().all())


async def get_evidences_by_task(
    db: AsyncSession,
    task_id: str,
) -> list[PocEvidence]:
    """获取任务下所有 PoC 证据。

    Args:
        db: 数据库会话
        task_id: 任务 ID

    Returns:
        PocEvidence ORM 对象列表
    """
    result = await db.execute(
        select(PocEvidence)
        .where(PocEvidence.task_id == task_id)
        .order_by(PocEvidence.created_at)
    )
    return list(result.scalars().all())