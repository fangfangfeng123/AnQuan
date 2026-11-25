"""任务执行器模块。

本模块是五阶段编排流水线的实际执行者，使用真实 Docker 沙箱容器：
- run(task_id)：执行完整评估流程
  0. 创建沙箱容器（sandbox_service.create_sandbox）
  1. 阶段一 recon：环境侦察（调用 Recon Agent → recon_service → scanners）
  2. 阶段二 code_audit：静态代码审计（调用 Code Audit Agent → code_audit_service
     → Semgrep/Bandit 扫描 + TaintFacade 污点追踪 + CVSS 评分 + finding_service 保存）
  3. 阶段三 poc_verify：PoC 验证（占位，暂不执行实际 PoC）
  4. 阶段四 exploit_chain：攻击链推演（exploit_chain Agent -> chain/builder.py -> DAG 拓扑 + 持久化）
  5. 阶段五 report_gen：报告生成（汇总漏洞结果写入日志）
  6. 销毁沙箱容器（sandbox_service.destroy_sandbox）
- 每个阶段完成后更新 phase_status 并广播 WebSocket 事件
- 支持中途取消（检查 Redis stop flag）
- 沙箱在任务完成/失败/停止时始终被销毁，但 task_logs 和 findings 数据保留
"""

import logging
from datetime import datetime, timezone

from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.agents import code_audit as code_audit_agent
from app.agents import exploit_chain as exploit_chain_agent
from app.agents import poc_verify as poc_verify_agent
from app.agents import recon as recon_agent
from app.agents import report_gen as report_agent
from app.core.database import AsyncSessionLocal
from app.core.errors import SandboxError
from app.core.redis import get_redis_sync
from app.enums import PhaseName, PhaseStatus, TaskStatus
from app.models import Task
from app.services.sandbox_service import (
    create_sandbox,
    destroy_sandbox,
)
from app.utils import append_task_log, update_task_phase
from app.websockets.publisher import EventPublisher

logger = logging.getLogger(__name__)

# 停止信号 Redis key 前缀
STOP_KEY_PREFIX = "task:stop:"


async def _check_stop_flag(redis: Redis, task_id: str) -> bool:
    """检查 Redis 中是否存在停止标志。"""
    return await redis.exists(f"{STOP_KEY_PREFIX}{task_id}")


async def _publish_event(
    redis: Redis,
    task_id: str,
    event_type: str,
    payload: dict,
) -> None:
    """广播 WebSocket 事件。"""
    await EventPublisher.publish(redis, task_id, event_type, payload)


# ── 阶段执行函数 ──


async def _execute_recon(
    db: AsyncSession,
    redis: Redis,
    task: Task,
) -> dict:
    """阶段一：环境侦察。

    调用 Recon Agent 执行完整侦察流程：
    - Agent 编排 → recon_service 在沙箱内执行命令 → scanners 解析
    - 识别语言/框架/依赖/入口/端口/数据库/路由
    - 写入 runtime_profiles 表
    - 发布 WS 事件 + 写日志

    Returns:
        侦察摘要字典，包含 language/framework/dependency_count 等
    """
    task_id = task.id

    # 调用 Recon Agent（agent 内部调用 recon_service，不再内联沙箱命令）
    result = await recon_agent.execute(db, redis, task_id)

    if not result.success:
        raise SandboxError(
            f"环境侦察失败: {result.error}",
            detail={"task_id": task_id, "phase": "recon"},
        )

    # 返回摘要供后续阶段使用
    return {
        "language": result.language,
        "framework": result.framework,
        "dependency_count": result.dependency_count,
        "file_count": result.file_count,
        "route_count": result.route_count,
        "entry_point_count": result.entry_point_count,
        "runtime_profile_id": result.runtime_profile.id
        if result.runtime_profile
        else None,
        "runtime_profile": result.runtime_profile,
    }


async def _execute_code_audit(
    db: AsyncSession,
    redis: Redis,
    task: Task,
    recon_info: dict,
) -> dict:
    """阶段二：静态代码审计。

    调用 Code Audit Agent 执行完整审计流程：
    - Agent 编排 → code_audit_service 在沙箱内运行 Semgrep/Bandit
    - 调用 TaintFacade 做 Source/Sink 污点追踪
    - 调用 CVSS 评分模块计算严重等级
    - 通过 finding_service 保存漏洞到数据库
    - 发布 WS 事件（finding_new / phase_completed）+ 写日志

    Returns:
        审计摘要字典，包含 finding_count / by_severity / by_type 等
    """
    task_id = task.id

    # 调用 Code Audit Agent（agent 内部调用 code_audit_service）
    result = await code_audit_agent.execute(db, redis, task_id)

    if not result.success:
        raise SandboxError(
            f"代码审计失败: {result.error}",
            detail={"task_id": task_id, "phase": "code_audit"},
        )

    # 返回摘要供后续阶段使用
    return {
        "finding_count": result.finding_count,
        "by_severity": result.by_severity or {},
        "by_type": result.by_type or {},
        "language": result.language,
        "framework": result.framework,
        "scanner_finding_count": result.scanner_finding_count,
        "taint_finding_count": result.taint_finding_count,
        "merged_finding_count": result.merged_finding_count,
        "saved_finding_count": result.saved_finding_count,
    }


async def _execute_poc_verify(
    db: AsyncSession,
    redis: Redis,
    task: Task,
    audit_info: dict,
) -> dict:
    """阶段三：PoC 动态验证。

    调用 PoC Verify Agent 执行完整验证流程：
    - 读取 unverified findings
    - 过滤可验证漏洞（不可验证的标记为 latent）
    - 在沙箱内启动临时目标服务
    - 针对每个漏洞执行无害探针
    - 比对预期特征，保存证据
    - 更新 finding 状态为 verified 或 latent
    - 发布 WS 事件 poc_verified / poc_failed

    Returns:
        PoC 验证摘要字典
    """
    result = await poc_verify_agent.execute(db, redis, task.id)

    return {
        "verified_count": result.verified_count,
        "latent_count": result.latent_count,
        "skipped_count": result.skipped_count,
        "evidence_count": result.evidence_count,
        "target_started": result.target_started,
        "results": result.results,
        "skipped": False,
    }


async def _execute_exploit_chain(
    db: AsyncSession,
    redis: Redis,
    task: Task,
    poc_info: dict,
) -> dict:
    """阶段四：攻击链推演。

    调用 exploit_chain Agent 执行完整推演流程：
    - 读取 verified findings -> 构建节点 -> 串联边 -> DAG 校验 -> 保存 DB
    - 发布 attack_chain_generated 事件
    - 单个高危漏洞也生成单节点攻击链
    """
    from app.agents import exploit_chain as exploit_chain_agent

    task_id = task.id
    result = await exploit_chain_agent.execute(db, redis, task_id)

    chain_result = {
        "success": result.success,
        "chain_count": result.chain_count,
        "total_nodes": result.total_nodes,
        "total_edges": result.total_edges,
        "single_node_chains": result.single_node_chains,
        "multi_step_chains": result.multi_step_chains,
        "max_severity": result.max_severity,
        "max_cvss": result.max_cvss,
        "final_impacts": result.final_impacts,
        "error": result.error,
    }
    return chain_result


async def _execute_report_gen(
    db: AsyncSession,
    redis: Redis,
    task: Task,
    chain_info: dict,
    audit_info: dict | None = None,
    poc_info: dict | None = None,
) -> dict:
    """阶段五：报告生成（汇总）。

    委托给 agents.report_gen.execute 执行实际报告生成，
    agent 内部会发布 phase_started / phase_completed / report_ready 事件，
    service 层负责聚合数据、渲染模板、写文件、入库。
    """
    task_id = task.id
    result = await report_agent.execute(db, redis, task_id)

    if not result.success:
        return {
            "report_path": None,
            "summary": f"报告生成失败: {result.error}",
            "overall_risk": "secure",
            "finding_count": 0,
            "verified_count": 0,
            "by_severity": {},
            "error": result.error,
        }

    # 更新任务整体风险等级
    task.overall_risk = result.overall_risk

    # 从 audit_info / poc_info 提取调用方期望的统计字段
    by_severity = audit_info.get("by_severity", {}) if audit_info else {}
    verified_count = poc_info.get("verified_count", 0) if poc_info else 0

    return {
        "report_path": result.markdown_path,
        "report_id": result.report_id,
        "version": result.version,
        "summary": (
            f"评估完成，发现 {result.total_findings} 条漏洞"
            f"（已验证 {verified_count} 条），"
            f"整体风险等级: {result.overall_risk}"
        ),
        "overall_risk": result.overall_risk,
        "finding_count": result.total_findings,
        "verified_count": verified_count,
        "by_severity": by_severity,
    }


async def _handle_stopped(
    db: AsyncSession,
    redis: Redis,
    task_id: str,
) -> None:
    """处理任务被停止的情况：销毁沙箱 + 保留数据。"""
    # 销毁沙箱（数据保留）
    try:
        await destroy_sandbox(db, redis, task_id)
    except Exception as e:
        logger.error(f"停止任务时销毁沙箱失败: {e}")

    result = await db.execute(select(Task).where(Task.id == task_id))
    task = result.scalar_one_or_none()
    if task:
        task.status = TaskStatus.STOPPED.value
        task.ended_at = datetime.now(timezone.utc)
        await db.commit()

    await redis.delete(f"{STOP_KEY_PREFIX}{task_id}")

    await _publish_event(
        redis,
        task_id,
        "task_stopped",
        {"task_id": task_id, "message": "任务已被用户停止，沙箱已销毁，数据已保留"},
    )

    logger.info(f"任务 {task_id} 已被用户停止")


async def run(task_id: str, redis: Redis | None = None) -> None:
    """执行完整五阶段评估流程（真实沙箱版）。

    流程：
    1. 加载 Task + SourceSnapshot
    2. 创建 Docker 沙箱容器（sandbox_service.create_sandbox）
    3. 在沙箱内依次执行五个阶段
    4. 每个阶段间检查停止信号
    5. 完成后销毁沙箱（sandbox_service.destroy_sandbox）
    6. 更新任务状态为 completed

    Args:
        task_id: 任务 ID
        redis: Redis 连接（不传则自建）
    """
    own_redis = False
    if redis is None:
        redis = get_redis_sync()
        own_redis = True

    if redis is None:
        logger.error("无法获取 Redis 连接")
        return

    sandbox_created = False

    try:
        async with AsyncSessionLocal() as db:
            # ── 加载任务 ──
            result = await db.execute(
                select(Task)
                .options(
                    selectinload(Task.project),
                    selectinload(Task.source_snapshot),
                )
                .where(Task.id == task_id)
            )
            task = result.scalar_one_or_none()
            if task is None:
                logger.error(f"任务不存在: {task_id}")
                return

            if await _check_stop_flag(redis, task_id):
                logger.info(f"任务 {task_id} 已被停止，跳过执行")
                await _handle_stopped(db, redis, task_id)
                return

            # ── 创建沙箱容器 ──
            await _publish_event(
                redis,
                task_id,
                "task_started",
                {"task_id": task_id, "message": "任务开始执行，正在创建沙箱..."},
            )

            try:
                await create_sandbox(db, redis, task_id)
                sandbox_created = True
                logger.info(f"沙箱已创建: task={task_id}")
            except SandboxError as e:
                logger.error(f"沙箱创建失败，任务终止: {e}")
                task.status = TaskStatus.FAILED.value
                task.ended_at = datetime.now(timezone.utc)
                task.error_message = str(e)[:2000]
                await db.commit()
                await _publish_event(
                    redis,
                    task_id,
                    "error",
                    {"task_id": task_id, "message": f"沙箱创建失败: {e}"},
                )
                return

            if await _check_stop_flag(redis, task_id):
                await _handle_stopped(db, redis, task_id)
                return

            # ── 阶段一：recon ──
            # phase_started 事件由 Recon Agent 内部发布，此处不重复
            await update_task_phase(
                db, task_id, PhaseName.RECON.value, PhaseStatus.RUNNING.value
            )
            recon_info = await _execute_recon(db, redis, task)
            await update_task_phase(
                db, task_id, PhaseName.RECON.value, PhaseStatus.COMPLETED.value
            )
            await db.commit()

            if await _check_stop_flag(redis, task_id):
                await _handle_stopped(db, redis, task_id)
                return

            # ── 阶段二：code_audit ──
            await update_task_phase(
                db, task_id, PhaseName.CODE_AUDIT.value, PhaseStatus.RUNNING.value
            )
            audit_info = await _execute_code_audit(db, redis, task, recon_info)
            await update_task_phase(
                db, task_id, PhaseName.CODE_AUDIT.value, PhaseStatus.COMPLETED.value
            )
            await db.commit()

            if await _check_stop_flag(redis, task_id):
                await _handle_stopped(db, redis, task_id)
                return

            # ── 阶段三：poc_verify ──
            await update_task_phase(
                db, task_id, PhaseName.POC_VERIFY.value, PhaseStatus.RUNNING.value
            )
            poc_info = await _execute_poc_verify(db, redis, task, audit_info)
            await update_task_phase(
                db, task_id, PhaseName.POC_VERIFY.value, PhaseStatus.COMPLETED.value
            )
            await db.commit()

            if await _check_stop_flag(redis, task_id):
                await _handle_stopped(db, redis, task_id)
                return

            # ── 阶段四：exploit_chain ──
            await update_task_phase(
                db, task_id, PhaseName.EXPLOIT_CHAIN.value, PhaseStatus.RUNNING.value
            )
            chain_info = await _execute_exploit_chain(db, redis, task, poc_info)
            await update_task_phase(
                db, task_id, PhaseName.EXPLOIT_CHAIN.value, PhaseStatus.COMPLETED.value
            )
            await db.commit()

            if await _check_stop_flag(redis, task_id):
                await _handle_stopped(db, redis, task_id)
                return

            # 先写入最终时间，报告聚合时才能读到真实的评估起止时间。
            task.ended_at = datetime.now(timezone.utc)
            await db.commit()

            # ── 阶段五：report_gen ──
            await update_task_phase(
                db, task_id, PhaseName.REPORT_GEN.value, PhaseStatus.RUNNING.value
            )
            report_info = await _execute_report_gen(
                db, redis, task, chain_info, audit_info, poc_info
            )
            await update_task_phase(
                db, task_id, PhaseName.REPORT_GEN.value, PhaseStatus.COMPLETED.value
            )
            await db.commit()

            # ── 任务完成 ──
            task.status = TaskStatus.COMPLETED.value
            task.current_phase = PhaseName.REPORT_GEN.value
            await db.commit()

            await _publish_event(
                redis,
                task_id,
                "task_completed",
                {
                    "task_id": task_id,
                    "overall_risk": report_info.get("overall_risk", "secure"),
                    "message": "任务执行完成",
                },
            )

            logger.info(f"任务 {task_id} 执行完成")

    except Exception as e:
        logger.exception(f"任务 {task_id} 执行失败: {e}")
        try:
            async with AsyncSessionLocal() as db:
                result = await db.execute(select(Task).where(Task.id == task_id))
                task = result.scalar_one_or_none()
                if task:
                    if task.status == TaskStatus.STOPPED.value:
                        logger.info(f"任务 {task_id} 已被停止，不再标记为失败")
                        await _publish_event(
                            redis,
                            task_id,
                            "task_stopped",
                            {"task_id": task_id, "message": "任务已停止"},
                        )
                        return
                    task.status = TaskStatus.FAILED.value
                    task.ended_at = datetime.now(timezone.utc)
                    task.error_message = str(e)[:2000]
                    await db.commit()

                await _publish_event(
                    redis,
                    task_id,
                    "error",
                    {"task_id": task_id, "message": f"任务执行失败: {e}"},
                )
        except Exception:
            logger.exception("标记任务失败状态时出错")

    finally:
        # ── 无论成功/失败/停止，都销毁沙箱 ──
        if sandbox_created:
            try:
                async with AsyncSessionLocal() as db:
                    await destroy_sandbox(db, redis, task_id)
                    logger.info(f"沙箱已销毁（finally）: task={task_id}")
            except Exception as e:
                logger.error(f"finally 中销毁沙箱失败: {e}")

        if own_redis:
            await redis.aclose()
