"""报告生成 Agent（阶段五）。

薄编排层（参照 exploit_chain_agent 的设计）：
- 发布 phase_started / phase_completed / phase_failed 事件
- 调用 services/report_service.generate_report 执行实际业务
- 捕获异常并发布失败事件 + 写日志

所有业务逻辑（聚合数据 / 渲染模板 / 写文件 / 入库 / 发 WS）
都在 services/report_service.py 里。
"""

import logging
from dataclasses import dataclass

from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.enums import PhaseName
from app.services.report_service import (
    REPORT_AGENT,
    ReportSummary,
    generate_report,
)
from app.utils import append_task_log
from app.websockets.publisher import EventPublisher

logger = logging.getLogger(__name__)

_REPORT_PHASE = PhaseName.REPORT_GEN.value


@dataclass
class AgentResult:
    """Report Agent 对外返回结果。"""

    success: bool = False
    report_id: str | None = None
    version: int = 0
    overall_risk: str = "secure"
    total_findings: int = 0
    markdown_path: str | None = None
    html_path: str | None = None
    error: str | None = None


async def execute(
    db: AsyncSession,
    redis: Redis,
    task_id: str,
) -> AgentResult:
    """执行报告生成 Agent。

    由 task_executor 在 report_gen 阶段调用。

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
            "phase": _REPORT_PHASE,
            "agent": REPORT_AGENT,
            "message": "报告生成开始",
        },
    )
    await append_task_log(
        db,
        task_id,
        _REPORT_PHASE,
        REPORT_AGENT,
        "info",
        "报告生成阶段开始",
    )

    try:
        # ── 2. 调用 service 生成报告 ──
        result: ReportSummary = await generate_report(db, redis, task_id)

        if not result.success:
            await EventPublisher.publish(
                redis,
                task_id,
                "phase_failed",
                {
                    "phase": _REPORT_PHASE,
                    "agent": REPORT_AGENT,
                    "success": False,
                    "error": result.error or "报告生成失败",
                    "message": "报告生成失败",
                },
            )
            return AgentResult(
                success=False,
                error=result.error,
            )

        # ── 3. 发布 phase_completed ──
        await EventPublisher.publish(
            redis,
            task_id,
            "phase_completed",
            {
                "phase": _REPORT_PHASE,
                "agent": REPORT_AGENT,
                "success": True,
                "report_id": result.report_id,
                "version": result.version,
                "overall_risk": result.overall_risk,
                "total_findings": result.total_findings,
                "message": (
                    f"报告生成完成 (v{result.version}): "
                    f"{result.total_findings} 漏洞, "
                    f"风险={result.overall_risk}"
                ),
            },
        )

        logger.info(
            "[report_gen_agent] task=%s: report v%d, risk=%s, findings=%d",
            task_id,
            result.version,
            result.overall_risk,
            result.total_findings,
        )

        return AgentResult(
            success=True,
            report_id=result.report_id,
            version=result.version,
            overall_risk=result.overall_risk,
            total_findings=result.total_findings,
            markdown_path=result.markdown_path,
            html_path=result.html_path,
        )

    except Exception as e:
        error_msg = f"报告生成失败（未预期错误）: {e}"
        logger.exception(error_msg)

        await append_task_log(
            db,
            task_id,
            _REPORT_PHASE,
            REPORT_AGENT,
            "error",
            error_msg,
            detail={"error_type": "unexpected", "error": str(e)},
        )

        await EventPublisher.publish(
            redis,
            task_id,
            "phase_failed",
            {
                "phase": _REPORT_PHASE,
                "agent": REPORT_AGENT,
                "success": False,
                "error": str(e),
                "message": "报告生成失败",
            },
        )

        return AgentResult(success=False, error=error_msg)
