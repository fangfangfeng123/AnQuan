"""代码审计 Agent 模块（阶段二）。

本 Agent 负责静态代码审计，是评估流水线的第二步：
- 在沙箱内执行 Semgrep / Bandit 静态扫描
- 对扫描结果做 Source/Sink 污点追踪分析
- 计算 CWE / OWASP / CVSS 评分
- 生成 Finding 记录（status=unverified）并写入数据库
- 发布 WebSocket 事件让前端实时展示漏洞列表

Agent 只做编排和决策，不直接操作 DB 或沙箱——所有操作通过
code_audit_service 层完成。

输入：task_id + 沙箱容器（已创建并挂载源码）+ runtimeProfile（来自 recon）
输出：finding 列表（全部 status=unverified）+ Code Audit 阶段 completed
"""

import logging
from dataclasses import dataclass

from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import SandboxError
from app.services.code_audit_service import run_code_audit as _run_audit_service
from app.utils import append_task_log
from app.websockets.publisher import EventPublisher

logger = logging.getLogger(__name__)

# Agent 标识
AGENT_NAME = "code_audit_agent"
PHASE_NAME = "code_audit"


@dataclass
class CodeAuditResult:
    """Code Audit Agent 执行结果。

    Attributes:
        success: 是否成功
        finding_count: 发现的漏洞总数
        by_severity: 按严重等级统计 {critical, high, medium, low, info}
        by_type: 按漏洞类型统计
        language: 扫描的源码语言
        framework: 扫描的源码框架
        scanner_finding_count: 扫描器原始发现数
        taint_finding_count: 污点分析产出数
        merged_finding_count: 合并后总数
        saved_finding_count: 实际保存到数据库的数量
        error: 失败时的错误信息
    """

    success: bool = False
    finding_count: int = 0
    by_severity: dict[str, int] | None = None
    by_type: dict[str, int] | None = None
    language: str = "unknown"
    framework: str = "unknown"
    scanner_finding_count: int = 0
    taint_finding_count: int = 0
    merged_finding_count: int = 0
    saved_finding_count: int = 0
    error: str | None = None


async def execute(
    db: AsyncSession,
    redis: Redis,
    task_id: str,
) -> CodeAuditResult:
    """执行代码审计流程。

    这是 Code Audit Agent 的主入口，由 task_executor 在 code_audit 阶段调用。
    Agent 编排流程：
    1. 发布阶段开始事件
    2. 调用 code_audit_service.run_code_audit 执行实际审计
    3. 根据结果构造 CodeAuditResult 返回
    4. 失败时写日志并发布错误事件

    Args:
        db: 数据库会话
        redis: Redis 连接
        task_id: 任务 ID

    Returns:
        CodeAuditResult: 包含成功标志、finding 摘要和统计信息
    """
    # ── 1. 发布阶段开始事件 ──
    await EventPublisher.publish(
        redis,
        task_id,
        "phase_started",
        {
            "phase": PHASE_NAME,
            "agent": AGENT_NAME,
            "message": "代码审计 Agent 启动，正在执行静态安全扫描...",
        },
    )

    try:
        # ── 2. 调用 code_audit_service 执行审计 ──
        summary = await _run_audit_service(db, redis, task_id)

        # ── 3. 构造结果 ──
        result = CodeAuditResult(
            success=True,
            finding_count=summary.get("merged_finding_count", 0),
            by_severity=summary.get("by_severity", {}),
            by_type=summary.get("by_type", {}),
            language=summary.get("language", "unknown"),
            framework=summary.get("framework", "unknown"),
            scanner_finding_count=summary.get("scanner_finding_count", 0),
            taint_finding_count=summary.get("taint_finding_count", 0),
            merged_finding_count=summary.get("merged_finding_count", 0),
            saved_finding_count=summary.get("saved_finding_count", 0),
        )

        # ── 4. 发布阶段完成事件 ──
        await EventPublisher.publish(
            redis,
            task_id,
            "phase_completed",
            {
                "phase": PHASE_NAME,
                "agent": AGENT_NAME,
                "success": True,
                "summary": {
                    "language": result.language,
                    "framework": result.framework,
                    "finding_count": result.finding_count,
                    "by_severity": result.by_severity,
                    "by_type": result.by_type,
                    "scanner_finding_count": result.scanner_finding_count,
                    "taint_finding_count": result.taint_finding_count,
                    "merged_finding_count": result.merged_finding_count,
                    "saved_finding_count": result.saved_finding_count,
                    "scanners_used": summary.get("scanners_used", []),
                },
            },
        )

        logger.info(
            "Code Audit Agent 完成: task=%s, findings=%d, by_severity=%s",
            task_id,
            result.finding_count,
            result.by_severity,
        )

        return result

    except SandboxError as e:
        # 沙箱执行失败
        error_msg = f"代码审计失败（沙箱错误）: {e}"
        logger.error(error_msg)

        await append_task_log(
            db,
            task_id,
            PHASE_NAME,
            AGENT_NAME,
            "error",
            error_msg,
            detail={"error_type": "sandbox_error", "error": str(e)},
        )

        await EventPublisher.publish(
            redis,
            task_id,
            "phase_failed",
            {
                "phase": PHASE_NAME,
                "agent": AGENT_NAME,
                "success": False,
                "error": str(e),
            },
        )

        return CodeAuditResult(success=False, error=error_msg)

    except Exception as e:
        # 其他未预期错误
        error_msg = f"代码审计失败（未预期错误）: {e}"
        logger.exception(error_msg)

        await append_task_log(
            db,
            task_id,
            PHASE_NAME,
            AGENT_NAME,
            "error",
            error_msg,
            detail={"error_type": "unexpected", "error": str(e)},
        )

        await EventPublisher.publish(
            redis,
            task_id,
            "phase_failed",
            {
                "phase": PHASE_NAME,
                "agent": AGENT_NAME,
                "success": False,
                "error": str(e),
            },
        )

        return CodeAuditResult(success=False, error=error_msg)
