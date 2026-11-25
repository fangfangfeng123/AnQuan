"""攻击链路由模块。

提供攻击链完整 API：
- GET  /tasks/{task_id}/attack-chains：获取任务的攻击链列表
- GET  /attack-chains/{chain_id}：获取单条攻击链详情
- POST /tasks/{task_id}/attack-chains/regenerate：重新生成攻击链（删旧+重建）
- DELETE /tasks/{task_id}/attack-chains/{chain_id}：删除单条攻击链
- GET  /tasks/{task_id}/attack-chain-statistics：获取攻击链统计
"""

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.errors import AppError
from app.core.redis import get_redis
from app.core.security import get_current_user
from app.schemas.attack_chain import (
    AttackChainListResponse,
    AttackChainResponse,
)
from app.services.attack_chain_service import (
    delete_chain,
    get_attack_chain,
    get_attack_chains,
    get_chain_statistics,
    regenerate_chains_for_task,
)
from app.services.task_service import get_task

router = APIRouter(tags=["攻击链"])


# ──────────────────────────────────────────────────────
# 查询端点
# ──────────────────────────────────────────────────────


@router.get(
    "/tasks/{task_id}/attack-chains",
    response_model=AttackChainListResponse,
)
async def list_task_attack_chains(
    task_id: str,
    db: AsyncSession = Depends(get_db),
    operator: str = Depends(get_current_user),
) -> AttackChainListResponse:
    """获取任务下的攻击链列表（含节点和边，用于前端 DAG 可视化）。"""
    if await get_task(db, task_id) is None:
        raise AppError(
            status_code=404,
            code="task_not_found",
            message=f"Task {task_id} not found",
        )

    chains = await get_attack_chains(db, task_id)
    return AttackChainListResponse(
        items=[AttackChainResponse.model_validate(c) for c in chains],
        total=len(chains),
    )


@router.get(
    "/attack-chains/{chain_id}",
    response_model=AttackChainResponse,
)
async def attack_chain_detail(
    chain_id: str,
    db: AsyncSession = Depends(get_db),
    operator: str = Depends(get_current_user),
) -> AttackChainResponse:
    """获取单条攻击链详情。"""
    chain = await get_attack_chain(db, chain_id)
    if chain is None:
        raise AppError(
            status_code=404,
            code="attack_chain_not_found",
            message=f"Attack chain {chain_id} not found",
        )
    return AttackChainResponse.model_validate(chain)


# ──────────────────────────────────────────────────────
# 重新生成端点
# ──────────────────────────────────────────────────────


class RegenerateResponse(BaseModel):
    """重新生成攻击链的响应。"""

    success: bool
    chain_count: int
    single_node_chains: int
    multi_step_chains: int
    total_nodes: int
    total_edges: int
    max_severity: str
    message: str


@router.post(
    "/tasks/{task_id}/attack-chains/regenerate",
    response_model=RegenerateResponse,
)
async def regenerate_attack_chains(
    task_id: str,
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis),
    operator: str = Depends(get_current_user),
) -> RegenerateResponse:
    """重新生成攻击链（删除旧链 + 重新构建）。

    适用于 PoC 验证阶段有更新、用户想刷新攻击链的场景。
    实际业务逻辑在 attack_chain_service.regenerate_chains_for_task 里。
    """
    if await get_task(db, task_id) is None:
        raise AppError(
            status_code=404,
            code="task_not_found",
            message=f"Task {task_id} not found",
        )

    result = await regenerate_chains_for_task(db, redis, task_id)

    return RegenerateResponse(
        success=result.success,
        chain_count=result.chain_count,
        single_node_chains=result.single_node_chains,
        multi_step_chains=result.multi_step_chains,
        total_nodes=result.total_nodes,
        total_edges=result.total_edges,
        max_severity=result.max_severity,
        message=(
            f"重新生成完成: {result.chain_count} 条链"
            if result.success
            else f"重新生成失败: {result.error}"
        ),
    )


# ──────────────────────────────────────────────────────
# 删除端点
# ──────────────────────────────────────────────────────


class DeleteResponse(BaseModel):
    """删除攻击链的响应。"""

    success: bool
    message: str


@router.delete(
    "/tasks/{task_id}/attack-chains/{chain_id}",
    response_model=DeleteResponse,
)
async def delete_attack_chain(
    task_id: str,
    chain_id: str,
    db: AsyncSession = Depends(get_db),
    operator: str = Depends(get_current_user),
) -> DeleteResponse:
    """删除单条攻击链（级联删除节点和边）。

    用户可能在 UI 里删掉无意义的攻击链。
    task_id 在 path 里以保证归属校验生效。
    """
    deleted = await delete_chain(db, task_id, chain_id)
    if not deleted:
        raise AppError(
            status_code=404,
            code="attack_chain_not_found",
            message=f"Attack chain {chain_id} not found in task {task_id}",
        )

    return DeleteResponse(
        success=True,
        message=f"攻击链 {chain_id} 已删除",
    )


# ──────────────────────────────────────────────────────
# 统计端点
# ──────────────────────────────────────────────────────


@router.get(
    "/tasks/{task_id}/attack-chain-statistics",
)
async def get_task_chain_statistics(
    task_id: str,
    db: AsyncSession = Depends(get_db),
    operator: str = Depends(get_current_user),
) -> dict:
    """获取任务下攻击链的统计信息（给前端 Dashboard 用）。

    返回：链数 / 单节点数 / 多步数 / 总节点 / 总边 / 最高风险 / 风险分布。
    """
    if await get_task(db, task_id) is None:
        raise AppError(
            status_code=404,
            code="task_not_found",
            message=f"Task {task_id} not found",
        )

    stats = await get_chain_statistics(db, task_id)
    return stats
