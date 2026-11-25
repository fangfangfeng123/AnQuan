"""大盘统计路由模块。

本模块定义仪表盘统计的 HTTP 接口：
- GET /dashboard/stats：获取聚合统计数据
- GET /dashboard/severity-distribution：获取漏洞严重等级分布
- GET /dashboard/trend?days=30：获取趋势数据
- GET /dashboard/recent-tasks?limit=10：获取最近任务列表

所有端点都需要 get_current_user 鉴权（任何登录用户都能看）。
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import get_current_user
from app.schemas.dashboard import (
    DashboardStatsResponse,
    RecentTaskItem,
    RecentTasksResponse,
    SeverityDistributionItem,
    SeverityDistributionResponse,
    TrendDataPoint,
    TrendResponse,
)
from app.services import dashboard_service

router = APIRouter(prefix="/dashboard", tags=["大盘统计"])


@router.get("/stats", response_model=DashboardStatsResponse)
async def get_stats(
    db: AsyncSession = Depends(get_db),
    operator: str = Depends(get_current_user),
) -> DashboardStatsResponse:
    """获取大盘总览统计数据。"""
    data = await dashboard_service.get_dashboard_stats(db)
    return DashboardStatsResponse(**data)


@router.get("/severity-distribution", response_model=SeverityDistributionResponse)
async def get_severity_distribution(
    db: AsyncSession = Depends(get_db),
    operator: str = Depends(get_current_user),
) -> SeverityDistributionResponse:
    """获取漏洞严重等级分布（饼图数据）。"""
    data = await dashboard_service.get_severity_distribution(db)
    items = [SeverityDistributionItem(**item) for item in data["items"]]
    return SeverityDistributionResponse(
        items=items,
        total=data["total"],
    )


@router.get("/trend", response_model=TrendResponse)
async def get_trend(
    days: int = Query(30, ge=1, le=365, description="查询天数范围"),
    db: AsyncSession = Depends(get_db),
    operator: str = Depends(get_current_user),
) -> TrendResponse:
    """获取近 N 天漏洞发现趋势。"""
    data = await dashboard_service.get_trend(db, days)
    data_points = [TrendDataPoint(**dp) for dp in data["data_points"]]
    return TrendResponse(
        days=data["days"],
        data_points=data_points,
    )


@router.get("/recent-tasks", response_model=RecentTasksResponse)
async def get_recent_tasks(
    limit: int = Query(10, ge=1, le=100, description="返回条数"),
    db: AsyncSession = Depends(get_db),
    operator: str = Depends(get_current_user),
) -> RecentTasksResponse:
    """获取最近任务列表。"""
    data = await dashboard_service.get_recent_tasks(db, limit)
    items = [RecentTaskItem(**item) for item in data["items"]]
    return RecentTasksResponse(
        items=items,
        total=data["total"],
    )
