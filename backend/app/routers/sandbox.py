"""沙箱管理路由模块。

本模块定义沙箱容器的 HTTP 接口，提供状态查询、资源监控、
容器日志、手动销毁与命令执行等能力。
"""

from fastapi import APIRouter, Depends, Query
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.errors import SandboxError, TaskNotFoundError
from app.core.redis import get_redis
from app.core.security import get_current_user
from app.schemas.common import SuccessResponse
from app.schemas.sandbox import (
    SandboxResponse,
    SandboxStatsResponse,
    SandboxStatusResponse,
)
from app.services.sandbox_service import (
    destroy_sandbox,
    get_sandbox_by_task,
    get_sandbox_logs,
    get_sandbox_stats,
    get_sandbox_status,
)

router = APIRouter(prefix="/tasks/{task_id}/sandbox", tags=["沙箱管理"])


@router.get("/status", response_model=SandboxStatusResponse)
async def get_sandbox_status_endpoint(
    task_id: str,
    db: AsyncSession = Depends(get_db),
    operator: str = Depends(get_current_user),
) -> SandboxStatusResponse:
    """获取沙箱运行状态（DB 状态 + Docker 实时状态）。"""
    status = await get_sandbox_status(db, task_id)
    return SandboxStatusResponse(**status)


@router.get("/stats", response_model=SandboxStatsResponse)
async def get_sandbox_stats_endpoint(
    task_id: str,
    db: AsyncSession = Depends(get_db),
    operator: str = Depends(get_current_user),
) -> SandboxStatsResponse:
    """获取沙箱资源使用统计（CPU、内存、PID）。"""
    stats = await get_sandbox_stats(db, task_id)
    return SandboxStatsResponse(**stats)


@router.get("/logs", response_model=str)
async def get_sandbox_logs_endpoint(
    task_id: str,
    tail: int = Query(200, ge=1, le=2000, description="尾部行数"),
    db: AsyncSession = Depends(get_db),
    operator: str = Depends(get_current_user),
) -> str:
    """获取沙箱容器日志（Docker stdout/stderr）。"""
    logs = await get_sandbox_logs(db, task_id, tail=tail)
    return logs


@router.get("", response_model=SandboxResponse | None)
async def get_sandbox_endpoint(
    task_id: str,
    db: AsyncSession = Depends(get_db),
    operator: str = Depends(get_current_user),
) -> SandboxResponse | None:
    """获取沙箱实例详情。"""
    instance = await get_sandbox_by_task(db, task_id)
    if instance is None:
        return None
    return SandboxResponse.model_validate(instance)


@router.post("/destroy", response_model=SuccessResponse)
async def destroy_sandbox_endpoint(
    task_id: str,
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis),
    operator: str = Depends(get_current_user),
) -> SuccessResponse:
    """手动销毁沙箱容器（保留任务数据）。"""
    instance = await destroy_sandbox(db, redis, task_id)
    if instance is None:
        raise SandboxError(f"任务 {task_id} 没有关联的沙箱容器")
    return SuccessResponse(message=f"沙箱已销毁: {instance.id}")

