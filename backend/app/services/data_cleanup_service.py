"""数据与文件物理清理服务。

本模块集中处理“彻底删除”时需要级联清理的数据，避免各路由分别写
重复的 SQL/文件删除逻辑。业务函数按调用方要求负责审计日志与提交，
这里只做底层清理：
- delete_report_files：删除某份报告对应的 Markdown/HTML/PDF 文件
- purge_task_data：删除一个任务关联的数据库记录和报告文件
- delete_snapshot_files：删除项目源码快照目录
"""

import logging
import shutil
from pathlib import Path

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.models import (
    AttackChain,
    AttackChainEdge,
    AttackChainNode,
    AuditLog,
    Finding,
    FixPatch,
    PocEvidence,
    Report,
    RuntimeProfile,
    SandboxInstance,
    SourceSnapshot,
    Task,
    TaskLog,
)

logger = logging.getLogger(__name__)
settings = get_settings()


def _managed_root(path_value: str) -> Path:
    """把配置里的相对目录解析为当前进程下的绝对目录。"""
    path = Path(path_value)
    return path.resolve()


def _remove_managed_path(path_value: str | None, root: Path) -> bool:
    """只删除受管理目录下的文件或目录，防止误删系统路径。"""
    if not path_value:
        return False
    path = Path(path_value)
    try:
        resolved = path.resolve()
        resolved_root = root.resolve()
    except OSError:
        return False
    if resolved == resolved_root or resolved_root not in resolved.parents:
        logger.warning("拒绝删除不受管理的路径: %s", path_value)
        return False
    try:
        if resolved.is_dir():
            shutil.rmtree(resolved, ignore_errors=True)
            return True
        if resolved.is_file():
            resolved.unlink(missing_ok=True)
            return True
    except OSError:
        logger.exception("清理路径失败: %s", resolved)
    return False


def delete_report_files(report: Report) -> int:
    """删除报告导出的 md/html/pdf 文件。"""
    root = _managed_root(settings.REPORT_OUTPUT_DIR)
    deleted = 0
    for field in ("markdown_path", "html_path", "pdf_path"):
        if _remove_managed_path(getattr(report, field), root):
            deleted += 1

    # 如果任务目录里已经没有其他版本文件，则顺带删除空目录。
    output_dir = Path(settings.REPORT_OUTPUT_DIR)
    task_dir = output_dir / report.task_id
    try:
        if task_dir.is_dir() and not any(task_dir.iterdir()):
            task_dir.rmdir()
    except OSError:
        pass
    return deleted


async def purge_task_data(db: AsyncSession, task_id: str) -> int:
    """删除任务关联的 DB 记录，并返回清理的报告文件数。"""
    report_rows = (
        await db.execute(select(Report).where(Report.task_id == task_id))
    ).scalars().all()
    deleted_files = 0
    for report in report_rows:
        deleted_files += delete_report_files(report)

    chain_rows = (
        await db.execute(select(AttackChain.id).where(AttackChain.task_id == task_id))
    ).scalars().all()
    chain_ids = list(chain_rows)
    if chain_ids:
        await db.execute(
            delete(AttackChainEdge).where(
                AttackChainEdge.attack_chain_id.in_(chain_ids)
            )
        )
        await db.execute(
            delete(AttackChainNode).where(
                AttackChainNode.attack_chain_id.in_(chain_ids)
            )
        )
        await db.execute(
            delete(AttackChain).where(AttackChain.id.in_(chain_ids))
        )

    await db.execute(delete(Report).where(Report.task_id == task_id))
    await db.execute(delete(FixPatch).where(FixPatch.task_id == task_id))
    await db.execute(delete(PocEvidence).where(PocEvidence.task_id == task_id))
    await db.execute(delete(Finding).where(Finding.task_id == task_id))
    await db.execute(delete(RuntimeProfile).where(RuntimeProfile.task_id == task_id))
    await db.execute(delete(SandboxInstance).where(SandboxInstance.task_id == task_id))
    await db.execute(delete(TaskLog).where(TaskLog.task_id == task_id))
    await db.execute(
        update(AuditLog).where(AuditLog.task_id == task_id).values(task_id=None)
    )
    await db.execute(delete(Task).where(Task.id == task_id))
    await db.flush()
    return deleted_files


def delete_snapshot_files(snapshot: SourceSnapshot) -> int:
    """删除源码快照目录，返回是否清理了目录。"""
    root = _managed_root(settings.SNAPSHOT_DIR)
    removed = 1 if _remove_managed_path(snapshot.snapshot_path, root) else 0
    outer_dir = root / snapshot.id
    try:
        if outer_dir.is_dir() and not any(outer_dir.iterdir()):
            outer_dir.rmdir()
    except OSError:
        pass
    return removed
