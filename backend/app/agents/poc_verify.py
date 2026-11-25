"""PoC 验证 Agent（阶段三）。

薄编排层（对照 recon_agent 的设计）：
- 发布 phase_started / phase_completed / phase_failed 事件
- 调用 services/poc_service.run_poc_verify 执行实际业务
- 捕获异常并发布失败事件 + 写日志

所有业务逻辑（启动目标服务 / 执行探针 / 比对 / 存证据 / 更新 finding）
都在 services/poc_service.py 里。
"""

import logging
from dataclasses import dataclass
from typing import Any

from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import SandboxError
from app.services.poc_service import (
    POC_AGENT,
    POC_PHASE,
    PocVerifyResult,
    run_poc_verify,
)
from app.utils import append_task_log
from app.websockets.publisher import EventPublisher

logger = logging.getLogger(__name__)


@dataclass
class AgentResult:
    """PoC Agent 对外返回结果。

    Attributes:
        success: 是否成功（流程跑完即便没找到漏洞也算 success=True）
        verified_count: 已验证漏洞数
        latent_count: 潜在隐患数
        skipped_count: 跳过验证数
        evidence_count: 保存的证据条数
        target_started: 是否成功启动目标服务
        error: 失败时的错误信息
        results: 每条 finding 的验证摘要
    """

    success: bool = False
    verified_count: int = 0
    latent_count: int = 0
    skipped_count: int = 0
    evidence_count: int = 0
    target_started: bool = False
    error: str | None = None
    results: list[dict[str, Any]] | None = None


async def execute(
    db: AsyncSession,
    redis: Redis,
    task_id: str,
) -> AgentResult:
    """执行 PoC 验证 Agent。

    这是 Agent 的主入口，由 task_executor 在 poc_verify 阶段调用。

    Args:
        db: 数据库会话
        redis: Redis 连接
        task_id: 任务 ID

    Returns:
        AgentResult：执行结果摘要
    """
    # ── 1. 发布 phase_started ──
    await EventPublisher.publish(
        redis,
        task_id,
        "phase_started",
        {
            "phase": POC_PHASE,
            "agent": POC_AGENT,
            "message": "PoC 验证开始",
        },
    )
    await append_task_log(
        db,
        task_id,
        POC_PHASE,
        POC_AGENT,
        "info",
        "PoC 验证阶段开始",
    )

    try:
        # ── 2. 调用 service 执行验证 ──
        result: PocVerifyResult = await run_poc_verify(db, redis, task_id)

        # ── 3. 发布 phase_completed ──
        await EventPublisher.publish(
            redis,
            task_id,
            "phase_completed",
            {
                "phase": POC_PHASE,
                "agent": POC_AGENT,
                "success": True,
                "verified_count": result.verified_count,
                "latent_count": result.latent_count,
                "skipped_count": result.skipped_count,
                "evidence_count": result.evidence_count,
                "target_started": result.target_started,
                "results": result.results,
            },
        )

        logger.info(
            "[poc_verify_agent] 完成: task=%s verified=%d latent=%d skipped=%d evidences=%d",
            task_id,
            result.verified_count,
            result.latent_count,
            result.skipped_count,
            result.evidence_count,
        )

        return AgentResult(
            success=True,
            verified_count=result.verified_count,
            latent_count=result.latent_count,
            skipped_count=result.skipped_count,
            evidence_count=result.evidence_count,
            target_started=result.target_started,
            results=result.results,
        )

    except SandboxError as e:
        error_msg = f"PoC 验证失败（沙箱错误）: {e}"
        logger.error(error_msg)

        await append_task_log(
            db,
            task_id,
            POC_PHASE,
            POC_AGENT,
            "error",
            error_msg,
            detail={"error_type": "sandbox_error", "error": str(e)},
        )

        await EventPublisher.publish(
            redis,
            task_id,
            "phase_failed",
            {
                "phase": POC_PHASE,
                "agent": POC_AGENT,
                "success": False,
                "error": str(e),
            },
        )

        return AgentResult(success=False, error=error_msg)

    except Exception as e:
        error_msg = f"PoC 验证失败（未预期错误）: {e}"
        logger.exception(error_msg)

        await append_task_log(
            db,
            task_id,
            POC_PHASE,
            POC_AGENT,
            "error",
            error_msg,
            detail={"error_type": "unexpected", "error": str(e)},
        )

        await EventPublisher.publish(
            redis,
            task_id,
            "phase_failed",
            {
                "phase": POC_PHASE,
                "agent": POC_AGENT,
                "success": False,
                "error": str(e),
            },
        )

        return AgentResult(success=False, error=error_msg)