"""审计日志服务模块。

本模块封装审计日志的业务逻辑。

增强功能（子模块4）：
- 按 target_id 过滤
- 按 task_id 过滤（查看任务全生命周期审计记录）
- 按 project_id 过滤
- 按时间范围过滤（start_date / end_date）
"""

from datetime import datetime

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AuditLog
from app.utils import paginate


async def log_action(
    db: AsyncSession,
    action: str,
    operator: str,
    target_type: str | None = None,
    target_id: str | None = None,
    task_id: str | None = None,
    project_id: str | None = None,
    detail: dict | None = None,
    ip_address: str | None = None,
) -> AuditLog:
    """记录审计日志。"""
    log = AuditLog(
        action=action,
        operator=operator,
        target_type=target_type,
        target_id=target_id,
        task_id=task_id,
        project_id=project_id,
        detail=detail,
        ip_address=ip_address,
    )
    db.add(log)
    await db.flush()
    return log


async def list_audit_logs(
    db: AsyncSession,
    action: str | None = None,
    operator: str | None = None,
    target_id: str | None = None,
    task_id: str | None = None,
    project_id: str | None = None,
    start_date: datetime | None = None,
    end_date: datetime | None = None,
    page: int = 1,
    size: int = 20,
) -> dict:
    """分页查询审计日志（支持多维度过滤）。

    Args:
        action: 按动作类型过滤
        operator: 按操作人过滤
        target_id: 按 target_id 过滤（精确匹配）
        task_id: 按 task_id 过滤（查看任务全生命周期审计记录）
        project_id: 按 project_id 过滤
        start_date: 起始时间（包含）
        end_date: 结束时间（包含）
        page: 页码
        size: 每页条数

    Returns:
        分页结果 dict
    """
    stmt = select(AuditLog).order_by(AuditLog.created_at.desc())

    if action:
        stmt = stmt.where(AuditLog.action == action)
    if operator:
        stmt = stmt.where(AuditLog.operator == operator)
    if target_id:
        stmt = stmt.where(AuditLog.target_id == target_id)
    if task_id:
        stmt = stmt.where(AuditLog.task_id == task_id)
    if project_id:
        stmt = stmt.where(AuditLog.project_id == project_id)
    if start_date:
        stmt = stmt.where(AuditLog.created_at >= start_date)
    if end_date:
        stmt = stmt.where(AuditLog.created_at <= end_date)

    return await paginate(db, stmt, page, size)


async def get_audit_log(db: AsyncSession, log_id: int) -> AuditLog | None:
    """获取单条审计日志详情。"""
    result = await db.execute(select(AuditLog).where(AuditLog.id == log_id))
    return result.scalar_one_or_none()


async def list_audit_logs_by_task(
    db: AsyncSession,
    task_id: str,
    page: int = 1,
    size: int = 20,
) -> dict:
    """按 task_id 查询所有审计记录（查看任务全生命周期）。

    这是 list_audit_logs(task_id=...) 的便捷封装。

    Args:
        task_id: 任务 ID
        page: 页码
        size: 每页条数

    Returns:
        分页结果 dict
    """
    return await list_audit_logs(
        db=db,
        task_id=task_id,
        page=page,
        size=size,
    )


async def delete_audit_log(db: AsyncSession, log_id: int) -> bool:
    """物理删除单条审计日志。"""
    log = await get_audit_log(db, log_id)
    if log is None:
        return False
    await db.delete(log)
    await db.commit()
    return True


async def clear_audit_logs(db: AsyncSession) -> int:
    """清空全部审计日志，返回删除条数。"""
    result = await db.execute(delete(AuditLog))
    await db.commit()
    return result.rowcount or 0
