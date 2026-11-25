"""项目管理服务模块。

本模块封装项目的全部业务逻辑。
"""

import logging

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import ValidationError
from app.enums import ProjectStatus
from app.models import AuditLog, Project, SourceSnapshot, Task
from app.services.audit_service import log_action
from app.services.data_cleanup_service import (
    delete_snapshot_files,
    purge_task_data,
)
from app.utils import generate_id, paginate

logger = logging.getLogger(__name__)


async def create_project(
    db: AsyncSession,
    project_name: str,
    source_type: str,
    source_input: str,
    source_ref: str | None = None,
    operator: str = "admin",
) -> Project:
    """创建项目。"""
    project = Project(
        id=generate_id(),
        project_name=project_name,
        source_type=source_type,
        source_input=source_input,
        source_ref=source_ref,
        status=ProjectStatus.ACTIVE.value,
    )
    db.add(project)
    await db.flush()

    await log_action(
        db,
        action="create",
        operator=operator,
        target_type="project",
        target_id=project.id,
        detail={"project_name": project_name, "source_type": source_type},
    )
    await db.commit()
    return project


async def get_project(db: AsyncSession, project_id: str) -> Project | None:
    """获取项目详情。"""
    result = await db.execute(select(Project).where(Project.id == project_id))
    return result.scalar_one_or_none()


async def list_projects(
    db: AsyncSession,
    status: str | None = None,
    page: int = 1,
    size: int = 20,
) -> dict:
    """分页查询项目列表。"""
    stmt = select(Project).order_by(Project.created_at.desc())
    if status:
        stmt = stmt.where(Project.status == status)
    return await paginate(db, stmt, page, size)


async def update_project(
    db: AsyncSession,
    project_id: str,
    data: dict,
    operator: str = "admin",
) -> Project | None:
    """更新项目信息。"""
    project = await get_project(db, project_id)
    if project is None:
        return None

    for key, value in data.items():
        if hasattr(project, key) and value is not None:
            setattr(project, key, value)

    await log_action(
        db,
        action="config_update",
        operator=operator,
        target_type="project",
        target_id=project_id,
        detail=data,
    )
    await db.commit()
    return project


async def archive_project(
    db: AsyncSession,
    project_id: str,
    operator: str = "admin",
) -> Project | None:
    """归档项目（软删除，不物理删除）。"""
    project = await get_project(db, project_id)
    if project is None:
        return None

    project.status = ProjectStatus.ARCHIVED.value
    await log_action(
        db,
        action="archive",
        operator=operator,
        target_type="project",
        target_id=project_id,
    )
    await db.commit()
    return project


async def restore_project(
    db: AsyncSession,
    project_id: str,
    operator: str = "admin",
) -> Project | None:
    """恢复已归档项目。"""
    project = await get_project(db, project_id)
    if project is None:
        return None

    project.status = ProjectStatus.ACTIVE.value
    await log_action(
        db,
        action="restore",
        operator=operator,
        target_type="project",
        target_id=project_id,
    )
    await db.commit()
    return project


async def purge_project(
    db: AsyncSession,
    project_id: str,
    operator: str = "admin",
) -> Project | None:
    """彻底删除项目及其任务、源码快照目录和报告文件。"""
    project = await get_project(db, project_id)
    if project is None:
        return None

    tasks = (
        await db.execute(select(Task).where(Task.project_id == project_id))
    ).scalars().all()
    if any(task.status == "running" for task in tasks):
        raise ValidationError("项目中存在运行中的任务，请先停止后再删除项目")

    snapshots = (
        await db.execute(
            select(SourceSnapshot).where(SourceSnapshot.project_id == project_id)
        )
    ).scalars().all()

    await log_action(
        db,
        action="delete",
        operator=operator,
        target_type="project",
        target_id=project_id,
        project_id=project_id,
        detail={
            "mode": "purge",
            "project_name": project.project_name,
            "task_count": len(tasks),
            "snapshot_count": len(snapshots),
        },
    )

    for task in tasks:
        await purge_task_data(db, task.id)

    snapshot_removed = 0
    for snapshot in snapshots:
        snapshot_removed += delete_snapshot_files(snapshot)
        await db.execute(
            delete(SourceSnapshot).where(SourceSnapshot.id == snapshot.id)
        )

    await db.execute(
        update(AuditLog).where(AuditLog.project_id == project_id).values(project_id=None)
    )
    await db.execute(delete(Project).where(Project.id == project_id))
    await db.commit()

    logger.info(
        "Project purged: %s, snapshots=%d, files_removed=%s",
        project_id,
        snapshot_removed,
        "yes" if snapshot_removed else "no",
    )
    return project
