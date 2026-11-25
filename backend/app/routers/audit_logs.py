"""审计日志路由模块。

本模块定义审计日志查询的 HTTP 接口。

增强功能（子模块4）：
- 按 target_id 过滤
- 按 task_id 过滤（查看任务全生命周期审计记录）
- 按 project_id 过滤
- 按时间范围过滤（start_date / end_date，ISO 8601 格式）
"""

from datetime import datetime

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.errors import AppError
from app.core.security import get_current_user
from app.schemas.audit_log import AuditLogResponse
from app.schemas.common import PaginatedResponse, SuccessResponse
from app.services.audit_service import (
    clear_audit_logs,
    delete_audit_log,
    get_audit_log,
    list_audit_logs,
)

router = APIRouter(prefix="/audit-logs", tags=["审计日志"])


@router.get("", response_model=PaginatedResponse[AuditLogResponse])
async def list_audit_logs_endpoint(
    action: str | None = Query(None, description="按动作过滤"),
    operator_name: str | None = Query(
        None, description="按操作人过滤", alias="operator"
    ),
    target_id: str | None = Query(None, description="按 target_id 过滤"),
    task_id: str | None = Query(
        None, description="按 task_id 过滤（查看任务全生命周期审计记录）"
    ),
    project_id: str | None = Query(None, description="按 project_id 过滤"),
    start_date: datetime | None = Query(None, description="起始时间（包含，ISO 8601）"),
    end_date: datetime | None = Query(None, description="结束时间（包含，ISO 8601）"),
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    _operator: str = Depends(get_current_user),
) -> dict:
    """获取审计日志列表（分页、多维度过滤）。

    支持的过滤条件：
    - action：按动作类型（create / start / stop / config_update 等）
    - operator：按操作人
    - target_id：按 target_id 精确匹配
    - task_id：按 task_id 过滤（查看任务全生命周期审计记录）
    - project_id：按 project_id 过滤
    - start_date / end_date：按时间范围过滤
    """
    result = await list_audit_logs(
        db=db,
        action=action,
        operator=operator_name,
        target_id=target_id,
        task_id=task_id,
        project_id=project_id,
        start_date=start_date,
        end_date=end_date,
        page=page,
        size=size,
    )
    return {
        "items": [AuditLogResponse.model_validate(log) for log in result["items"]],
        "total": result["total"],
        "page": result["page"],
        "size": result["size"],
        "pages": result["pages"],
    }


@router.delete("", response_model=SuccessResponse)
async def clear_audit_logs_endpoint(
    db: AsyncSession = Depends(get_db),
    _operator: str = Depends(get_current_user),
) -> SuccessResponse:
    """清空全部审计日志。"""
    count = await clear_audit_logs(db)
    return SuccessResponse(message=f"已清空审计日志: {count} 条")


@router.delete("/{log_id}", response_model=SuccessResponse)
async def delete_audit_log_endpoint(
    log_id: int,
    db: AsyncSession = Depends(get_db),
    _operator: str = Depends(get_current_user),
) -> SuccessResponse:
    """删除单条审计日志。"""
    deleted = await delete_audit_log(db, log_id)
    if not deleted:
        raise AppError(
            status_code=404,
            code="not_found",
            message=f"审计日志不存在: {log_id}",
        )
    return SuccessResponse(message=f"审计日志已删除: {log_id}")


@router.get("/{log_id}", response_model=AuditLogResponse)
async def get_audit_log_endpoint(
    log_id: int,
    db: AsyncSession = Depends(get_db),
    _operator: str = Depends(get_current_user),
) -> AuditLogResponse:
    """获取单条审计日志详情。"""
    log = await get_audit_log(db, log_id)
    if log is None:
        raise AppError(
            status_code=404, code="not_found", message=f"审计日志不存在: {log_id}"
        )
    return AuditLogResponse.model_validate(log)
