"""评估任务路由模块。

本模块定义安全评估任务的 HTTP 接口。
"""

from fastapi import APIRouter, Depends, Query, Request
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.errors import TaskNotFoundError
from app.core.redis import get_redis
from app.core.security import get_current_user
from app.schemas.common import PaginatedResponse, SuccessResponse
from app.schemas.task import TaskListItem, TaskLogResponse, TaskResponse
from app.services.task_service import (
    archive_task,
    get_task,
    list_task_logs,
    list_tasks,
    purge_task,
    start_task,
    stop_task,
)

router = APIRouter(prefix="/tasks", tags=["评估任务"])


@router.post("/{task_id}/start", response_model=TaskResponse)
async def start_task_endpoint(
    task_id: str,
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis),
    operator: str = Depends(get_current_user),
) -> TaskResponse:
    """启动任务（入队 Redis，由 worker 消费）。"""
    task = await start_task(db, task_id, redis, operator)
    return TaskResponse.model_validate(task)


@router.post("/{task_id}/stop", response_model=TaskResponse)
async def stop_task_endpoint(
    task_id: str,
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis),
    operator: str = Depends(get_current_user),
) -> TaskResponse:
    """停止运行中的任务。"""
    task = await stop_task(db, task_id, redis, operator)
    return TaskResponse.model_validate(task)


@router.get("/{task_id}", response_model=TaskResponse)
async def get_task_endpoint(
    task_id: str,
    db: AsyncSession = Depends(get_db),
    operator: str = Depends(get_current_user),
) -> TaskResponse:
    """获取任务详情。"""
    task = await get_task(db, task_id)
    if task is None:
        raise TaskNotFoundError(task_id)
    return TaskResponse.model_validate(task)


@router.get("", response_model=PaginatedResponse[TaskListItem])
async def list_tasks_endpoint(
    status: str | None = Query(None, description="按状态过滤"),
    project_id: str | None = Query(None, description="按项目过滤"),
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    operator: str = Depends(get_current_user),
) -> dict:
    """获取任务列表（分页、过滤状态）。"""
    result = await list_tasks(
        db=db, status=status, project_id=project_id, page=page, size=size
    )
    return {
        "items": [TaskListItem.model_validate(t) for t in result["items"]],
        "total": result["total"],
        "page": result["page"],
        "size": result["size"],
        "pages": result["pages"],
    }


@router.get("/{task_id}/logs", response_model=PaginatedResponse[TaskLogResponse])
async def list_task_logs_endpoint(
    task_id: str,
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    operator: str = Depends(get_current_user),
) -> dict:
    """获取任务日志（分页）。"""
    result = await list_task_logs(db=db, task_id=task_id, page=page, size=size)
    return {
        "items": [TaskLogResponse.model_validate(log) for log in result["items"]],
        "total": result["total"],
        "page": result["page"],
        "size": result["size"],
        "pages": result["pages"],
    }


@router.delete("/{task_id}", response_model=SuccessResponse)
async def archive_task_endpoint(
    task_id: str,
    db: AsyncSession = Depends(get_db),
    operator: str = Depends(get_current_user),
) -> SuccessResponse:
    """归档任务。"""
    task = await archive_task(db, task_id, operator)
    if task is None:
        raise TaskNotFoundError(task_id)
    return SuccessResponse(message=f"任务已归档: {task_id}")


@router.delete("/{task_id}/purge", response_model=SuccessResponse)
async def purge_task_endpoint(
    task_id: str,
    db: AsyncSession = Depends(get_db),
    operator: str = Depends(get_current_user),
) -> SuccessResponse:
    """彻底删除任务及其漏洞、攻击链、日志与报告文件。"""
    task = await purge_task(db, task_id, operator)
    if task is None:
        raise TaskNotFoundError(task_id)
    return SuccessResponse(message=f"任务已彻底删除: {task_id}")
