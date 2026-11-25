"""补丁持久化模块（纯 DB CRUD）。

本模块封装 FixPatch 表的所有数据库操作，不含业务逻辑：
- save_patch：新建补丁记录
- get_patch：按 ID 查询
- get_patch_by_finding：按漏洞 ID 查询（一对一）
- update_adopt_status：更新采纳状态
- update_validation_result：更新校验结果
- list_patches_by_task：按任务查询所有补丁
"""

import logging
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import FixPatch
from app.utils import generate_id

logger = logging.getLogger(__name__)


async def save_patch(
    db: AsyncSession,
    finding_id: str,
    task_id: str,
    original_code: str | None,
    patched_code: str | None,
    diff_content: str | None,
    description: str | None,
    llm_model: str | None = None,
    token_usage: int | None = None,
) -> FixPatch:
    """新建补丁记录。

    Args:
        db: 数据库会话
        finding_id: 关联漏洞 ID
        task_id: 任务 ID
        original_code: 原始漏洞代码
        patched_code: 修复后代码
        diff_content: 统一 Diff 内容
        description: AI 生成的修改说明
        llm_model: 生成此补丁的 LLM 模型名
        token_usage: 消耗的 token 数

    Returns:
        FixPatch ORM 对象
    """
    patch = FixPatch(
        id=generate_id(),
        finding_id=finding_id,
        task_id=task_id,
        original_code=original_code,
        patched_code=patched_code,
        diff_content=diff_content,
        description=description,
        adopt_status="pending",
        validated=0,
        validation_result=None,
        llm_model=llm_model,
        token_usage=token_usage,
    )
    db.add(patch)
    await db.flush()
    logger.info("[repository] Saved patch %s for finding %s", patch.id, finding_id)
    return patch


async def get_patch(db: AsyncSession, patch_id: str) -> FixPatch | None:
    """按 ID 查询补丁。"""
    stmt = select(FixPatch).where(FixPatch.id == patch_id)
    result = await db.execute(stmt)
    return result.scalar_one_or_none()


async def get_patch_by_finding(db: AsyncSession, finding_id: str) -> FixPatch | None:
    """按漏洞 ID 查询补丁（一对一）。"""
    stmt = select(FixPatch).where(FixPatch.finding_id == finding_id)
    result = await db.execute(stmt)
    return result.scalar_one_or_none()


async def update_adopt_status(
    db: AsyncSession,
    patch_id: str,
    status: str,
) -> FixPatch | None:
    """更新补丁采纳状态。

    Args:
        db: 数据库会话
        patch_id: 补丁 ID
        status: 新状态（pending / adopted / rejected / superseded）

    Returns:
        更新后的 FixPatch 对象，不存在则 None
    """
    patch = await get_patch(db, patch_id)
    if patch is None:
        return None
    patch.adopt_status = status
    await db.flush()
    logger.info("[repository] Updated patch %s adopt_status -> %s", patch_id, status)
    return patch


async def update_validation_result(
    db: AsyncSession,
    patch_id: str,
    validated: bool,
    validation_result: dict[str, Any],
) -> FixPatch | None:
    """更新补丁校验结果。

    Args:
        db: 数据库会话
        patch_id: 补丁 ID
        validated: 是否通过校验
        validation_result: 校验结果详情 JSONB

    Returns:
        更新后的 FixPatch 对象，不存在则 None
    """
    patch = await get_patch(db, patch_id)
    if patch is None:
        return None
    patch.validated = 1 if validated else 0
    patch.validation_result = validation_result
    await db.flush()
    logger.info("[repository] Updated patch %s validated=%s", patch_id, validated)
    return patch


async def list_patches_by_task(
    db: AsyncSession,
    task_id: str,
) -> list[FixPatch]:
    """查询任务下所有补丁。"""
    stmt = (
        select(FixPatch)
        .where(FixPatch.task_id == task_id)
        .order_by(FixPatch.created_at.desc())
    )
    result = await db.execute(stmt)
    return list(result.scalars().all())
