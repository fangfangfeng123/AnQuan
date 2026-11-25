"""环境侦察 Agent 模块（阶段一）。

本 Agent 负责环境侦察，是评估流水线的第一步：
- 扫描源码目录结构
- 识别编程语言和框架（通过依赖清单和文件类型分布）
- 提取依赖清单（requirements.txt / package.json / pom.xml 等）
- 识别入口文件和暴露端口
- 识别数据库类型和路由接口
- 生成 RuntimeProfile 并持久化
- 产出数据供后续阶段（code_audit）使用

Agent 只做编排和决策，不直接操作 DB 或沙箱——所有操作通过 recon_service 层完成。
"""

import logging
from dataclasses import dataclass, field

from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import SandboxError
from app.models import RuntimeProfile
from app.services.recon_service import run_recon as _run_recon_service
from app.utils import append_task_log
from app.websockets.publisher import EventPublisher

logger = logging.getLogger(__name__)

# Agent 标识
AGENT_NAME = "recon_agent"
PHASE_NAME = "recon"


@dataclass
class ReconResult:
    """Recon Agent 执行结果。

    Attributes:
        success: 是否成功
        runtime_profile: 生成的 RuntimeProfile 对象（失败时为 None）
        language: 识别到的主语言
        framework: 识别到的主框架
        dependency_count: 依赖数量
        route_count: 路由数量
        entry_point_count: 入口文件数量
        error: 失败时的错误信息
    """

    success: bool = False
    runtime_profile: RuntimeProfile | None = None
    language: str = "unknown"
    framework: str = "unknown"
    dependency_count: int = 0
    file_count: int = 0
    route_count: int = 0
    entry_point_count: int = 0
    error: str | None = None


async def execute(
    db: AsyncSession,
    redis: Redis,
    task_id: str,
) -> ReconResult:
    """执行环境侦察流程。

    这是 Recon Agent 的主入口，由 task_executor 在 recon 阶段调用。
    Agent 编排流程：
    1. 发布阶段开始事件
    2. 调用 recon_service.run_recon 执行实际侦察
    3. 根据结果构造 ReconResult 返回
    4. 失败时写日志并发布错误事件

    Args:
        db: 数据库会话
        redis: Redis 连接
        task_id: 任务 ID

    Returns:
        ReconResult: 包含成功标志、runtime_profile 和摘要信息
    """
    # ── 1. 发布阶段开始事件 ──
    await EventPublisher.publish(
        redis,
        task_id,
        "phase_started",
        {
            "phase": PHASE_NAME,
            "agent": AGENT_NAME,
            "message": "环境侦察 Agent 启动，正在分析项目技术栈...",
        },
    )

    try:
        # ── 2. 调用 recon_service 执行侦察 ──
        profile = await _run_recon_service(db, redis, task_id)

        # ── 3. 构造结果 ──
        dep_count = len(profile.dependencies) if profile.dependencies else 0
        entry_count = len(profile.entry_points) if profile.entry_points else 0
        file_count = 0
        if profile.raw_result:
            file_count = profile.raw_result.get("file_count", 0)
        route_count = 0
        if profile.raw_result and "route_summary" in profile.raw_result:
            route_count = profile.raw_result["route_summary"].get("total", 0)

        result = ReconResult(
            success=True,
            runtime_profile=profile,
            language=profile.language,
            framework=profile.framework,
            dependency_count=dep_count,
            file_count=file_count,
            route_count=route_count,
            entry_point_count=entry_count,
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
                    "language": profile.language,
                    "framework": profile.framework,
                    "dependency_count": dep_count,
                    "file_count": file_count,
                    "entry_point_count": entry_count,
                    "route_count": route_count,
                    "db_type": profile.db_type,
                    "run_command": profile.run_command,
                },
                "runtime_profile_id": profile.id,
            },
        )

        logger.info(
            f"Recon Agent 完成: task={task_id}, "
            f"lang={profile.language}, fw={profile.framework}, "
            f"deps={dep_count}, files={file_count}, routes={route_count}"
        )

        return result

    except SandboxError as e:
        # 沙箱执行失败
        error_msg = f"环境侦察失败（沙箱错误）: {e}"
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

        return ReconResult(success=False, error=error_msg)

    except Exception as e:
        # 其他未预期错误
        error_msg = f"环境侦察失败（未预期错误）: {e}"
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

        return ReconResult(success=False, error=error_msg)
