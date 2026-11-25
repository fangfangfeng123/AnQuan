"""环境侦察路由模块。

本模块定义环境侦察阶段的 HTTP 接口：
- GET /tasks/{task_id}/recon：获取完整 runtime_profile 详情
- GET /tasks/{task_id}/recon/summary：获取精简摘要（供工作台快速展示）
"""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.errors import TaskNotFoundError
from app.core.security import get_current_user
from app.schemas.common import SuccessResponse
from app.schemas.recon import ReconSummaryResponse, RuntimeProfileResponse
from app.services.recon_service import get_runtime_profile

router = APIRouter(prefix="/tasks", tags=["环境侦察"])


@router.get("/{task_id}/recon", response_model=RuntimeProfileResponse)
async def get_recon_profile(
    task_id: str,
    db: AsyncSession = Depends(get_db),
    operator: str = Depends(get_current_user),
) -> RuntimeProfileResponse:
    """获取任务的环境侦察结果（完整 runtime_profile）。

    返回语言、框架、依赖清单、入口文件、端口、数据库类型等完整信息。
    如果 Recon 阶段尚未执行，返回 404。
    """
    profile = await get_runtime_profile(db, task_id)
    if profile is None:
        raise TaskNotFoundError(task_id)
    return RuntimeProfileResponse.model_validate(profile)


@router.get("/{task_id}/recon/summary", response_model=ReconSummaryResponse)
async def get_recon_summary(
    task_id: str,
    db: AsyncSession = Depends(get_db),
    operator: str = Depends(get_current_user),
) -> ReconSummaryResponse:
    """获取任务的环境侦察精简摘要。

    供工作台前端快速展示：语言、框架、依赖数、入口数、端口列表、数据库类型、启动命令。
    """
    profile = await get_runtime_profile(db, task_id)
    if profile is None:
        raise TaskNotFoundError(task_id)

    # 构造摘要
    dep_count = len(profile.dependencies) if profile.dependencies else 0
    entry_count = len(profile.entry_points) if profile.entry_points else 0
    ports = []
    if profile.service_ports:
        for p in profile.service_ports:
            if isinstance(p, dict):
                ports.append(p.get("port", 0))
            elif isinstance(p, int):
                ports.append(p)

    return ReconSummaryResponse(
        language=profile.language,
        framework=profile.framework,
        dependency_count=dep_count,
        entry_point_count=entry_count,
        service_ports=ports if ports else None,
        db_type=profile.db_type,
        run_command=profile.run_command,
    )
