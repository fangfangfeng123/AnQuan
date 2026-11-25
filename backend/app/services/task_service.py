"""任务生命周期服务模块。

本模块管理安全评估任务的全生命周期。
"""

import json
import logging
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.errors import (
    ProjectNotFoundError,
    SnapshotNotFoundError,
    TaskAlreadyRunningError,
    TaskNotFoundError,
    ValidationError,
)
from app.enums import PhaseName, PhaseStatus, TaskStatus
from app.models import Project, SourceSnapshot, Task, TaskLog
from app.services.audit_service import log_action
from app.services.data_cleanup_service import purge_task_data
from app.utils import (
    append_task_log,
    calculate_overall_progress,
    generate_id,
    paginate,
    update_task_phase,
)
from app.websockets.publisher import EventPublisher

settings = get_settings()
logger = logging.getLogger(__name__)

# Redis 任务队列名
TASK_QUEUE = "task:queue"


async def create_task(
    db: AsyncSession,
    project_id: str,
    source_snapshot_id: str | None = None,
    sandbox_image: str | None = None,
    network_mode: str = "restricted",
    timeout_secs: int = 1800,
    llm_mode: str = "demo",
    max_concurrent: int = 3,
    operator: str = "admin",
) -> Task:
    """为项目创建评估任务。"""
    project = await db.get(Project, project_id)
    if project is None:
        raise ProjectNotFoundError(project_id)

    snapshot_id = source_snapshot_id
    if snapshot_id:
        snapshot = await db.get(SourceSnapshot, snapshot_id)
        if snapshot is None or snapshot.project_id != project_id:
            raise SnapshotNotFoundError(snapshot_id)
    else:
        snapshot_result = await db.execute(
            select(SourceSnapshot)
            .where(SourceSnapshot.project_id == project_id)
            .order_by(SourceSnapshot.created_at.desc())
            .limit(1)
        )
        snapshot = snapshot_result.scalar_one_or_none()
        if snapshot is None:
            raise ValidationError("创建任务前请先上传源码或克隆 Git 仓库")
        snapshot_id = snapshot.id

    task = Task(
        id=generate_id(),
        project_id=project_id,
        source_snapshot_id=snapshot_id,
        status=TaskStatus.CREATED.value,
        current_phase=None,
        phase_status={
            PhaseName.RECON.value: PhaseStatus.PENDING.value,
            PhaseName.CODE_AUDIT.value: PhaseStatus.PENDING.value,
            PhaseName.POC_VERIFY.value: PhaseStatus.PENDING.value,
            PhaseName.EXPLOIT_CHAIN.value: PhaseStatus.PENDING.value,
            PhaseName.REPORT_GEN.value: PhaseStatus.PENDING.value,
        },
        sandbox_image=sandbox_image or settings.SANDBOX_IMAGE_DEFAULT,
        network_mode=network_mode,
        timeout_secs=timeout_secs,
        llm_mode=llm_mode,
        max_concurrent=max_concurrent,
    )
    db.add(task)
    await db.flush()

    await log_action(
        db,
        action="create",
        operator=operator,
        target_type="task",
        target_id=task.id,
        project_id=project_id,
        detail={"sandbox_image": sandbox_image, "llm_mode": llm_mode},
    )
    await db.commit()
    return task


async def get_task(db: AsyncSession, task_id: str) -> Task | None:
    """获取任务详情。"""
    result = await db.execute(select(Task).where(Task.id == task_id))
    return result.scalar_one_or_none()


async def list_tasks(
    db: AsyncSession,
    status: str | None = None,
    project_id: str | None = None,
    page: int = 1,
    size: int = 20,
) -> dict:
    """分页查询任务列表。"""
    stmt = select(Task).order_by(Task.created_at.desc())
    if status:
        stmt = stmt.where(Task.status == status)
    if project_id:
        stmt = stmt.where(Task.project_id == project_id)
    return await paginate(db, stmt, page, size)


async def start_task(
    db: AsyncSession,
    task_id: str,
    redis=None,
    operator: str = "admin",
) -> Task:
    """将任务入队 Redis，由 worker 消费执行。"""
    task = await get_task(db, task_id)
    if task is None:
        raise TaskNotFoundError(task_id)

    if task.status == TaskStatus.RUNNING.value:
        raise TaskAlreadyRunningError(task_id)

    if task.status not in (TaskStatus.CREATED.value, TaskStatus.STOPPED.value):
        raise TaskAlreadyRunningError(task_id)

    if task.source_snapshot_id is None:
        raise ValidationError("任务没有关联源码快照，无法启动")

    task.status = TaskStatus.RUNNING.value
    task.current_phase = PhaseName.RECON.value
    task.phase_status = {
        PhaseName.RECON.value: PhaseStatus.RUNNING.value,
        PhaseName.CODE_AUDIT.value: PhaseStatus.PENDING.value,
        PhaseName.POC_VERIFY.value: PhaseStatus.PENDING.value,
        PhaseName.EXPLOIT_CHAIN.value: PhaseStatus.PENDING.value,
        PhaseName.REPORT_GEN.value: PhaseStatus.PENDING.value,
    }
    task.overall_progress = calculate_overall_progress(task.phase_status)
    task.started_at = datetime.now(timezone.utc)

    await log_action(
        db,
        action="start",
        operator=operator,
        target_type="task",
        target_id=task_id,
        project_id=task.project_id,
        detail={"message": "任务已进入 running 状态"},
    )
    await db.commit()

    # 开始时间必须先提交再入队，避免 Worker 早于 commit 读到空 started_at。
    if redis:
        await redis.lpush(TASK_QUEUE, json.dumps({"task_id": task_id}))

    return task


async def stop_task(
    db: AsyncSession,
    task_id: str,
    redis=None,
    operator: str = "admin",
) -> Task:
    """停止运行中的任务（通知 worker 中断 + 立即销毁沙箱）。

    流程：
    1. 设置 Redis 停止信号（worker 在阶段间检查）
    2. 立即销毁沙箱容器（终止容器内进程 + 删除容器）
    3. 更新 Task 状态为 stopped
    4. 保留 task_logs、findings 等已持久化数据
    """
    task = await get_task(db, task_id)
    if task is None:
        raise TaskNotFoundError(task_id)

    if task.status != TaskStatus.RUNNING.value:
        raise ValidationError("只有运行中的任务可以停止")

    # 1. 设置 Redis 停止信号（worker 在阶段间检查此 key）
    if redis:
        await redis.set(f"task:stop:{task_id}", "1", ex=3600)

    # 2. 立即销毁沙箱容器（不等 worker 检测 stop key）
    #    先终止容器内进程，再删除容器，但 DB 日志/漏洞数据不删
    from app.services.sandbox_service import destroy_sandbox

    try:
        await destroy_sandbox(db, redis, task_id, force=True)
    except Exception as e:
        # 沙箱销毁失败不应阻塞停止任务的操作
        import logging

        logging.getLogger(__name__).warning(
            f"停止任务时销毁沙箱失败（不影响停止流程）: {e}"
        )

    # 3. 更新 Task 状态
    task.status = TaskStatus.STOPPED.value
    task.ended_at = datetime.now(timezone.utc)

    await log_action(
        db,
        action="stop",
        operator=operator,
        target_type="task",
        target_id=task_id,
        project_id=task.project_id,
    )
    await db.commit()
    return task


async def archive_task(
    db: AsyncSession,
    task_id: str,
    operator: str = "admin",
) -> Task | None:
    """归档任务。"""
    task = await get_task(db, task_id)
    if task is None:
        return None

    task.is_archived = True
    await log_action(
        db,
        action="archive",
        operator=operator,
        target_type="task",
        target_id=task_id,
        project_id=task.project_id,
    )
    await db.commit()
    return task


async def purge_task(
    db: AsyncSession,
    task_id: str,
    operator: str = "admin",
) -> Task | None:
    """彻底删除任务及其漏洞、攻击链、日志、报告文件。"""
    task = await get_task(db, task_id)
    if task is None:
        return None
    if task.status == TaskStatus.RUNNING.value:
        raise ValidationError("运行中的任务不能直接删除，请先停止任务")

    await log_action(
        db,
        action="delete",
        operator=operator,
        target_type="task",
        target_id=task_id,
        project_id=task.project_id,
        detail={
            "mode": "purge",
            "task_status": task.status,
            "current_phase": task.current_phase,
        },
    )
    deleted_files = await purge_task_data(db, task_id)
    await db.commit()

    logger.info(
        "Task purged: %s, project=%s, report_files=%d",
        task_id,
        task.project_id,
        deleted_files,
    )
    return task


async def list_task_logs(
    db: AsyncSession,
    task_id: str,
    page: int = 1,
    size: int = 50,
) -> dict:
    """获取任务日志（分页）。"""
    stmt = (
        select(TaskLog)
        .where(TaskLog.task_id == task_id)
        .order_by(TaskLog.created_at.asc())
    )
    return await paginate(db, stmt, page, size)
