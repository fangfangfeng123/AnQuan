"""大盘聚合统计服务模块。

本模块封装仪表盘的聚合查询逻辑：
- get_dashboard_stats()：获取总览统计
  （项目总数、任务总数、漏洞总数、运行中任务数、已验证漏洞数、攻击链数、最高 CVSS、风险分布）
- get_severity_distribution()：获取漏洞严重等级分布饼图数据
- get_trend(days=30)：获取近 N 天漏洞发现趋势（按天分组）
- get_recent_tasks(limit=10)：获取最近任务列表（JOIN project 拿项目名）

所有查询走只读聚合 SQL，不走 ORM 避免性能问题。
"""

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AttackChain, Finding, Project, Task

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────
# 总览统计
# ──────────────────────────────────────────────────────


async def get_dashboard_stats(db: AsyncSession) -> dict:
    """获取大盘总览统计。

    用单条 SQL 拿多个聚合，避免多次 round-trip。

    Returns:
        包含所有聚合指标的 dict
    """
    # 用子查询一次性拿多个聚合
    stmt = text(
        """
        SELECT
            (SELECT COUNT(*) FROM projects) AS total_projects,
            (SELECT COUNT(*) FROM tasks) AS total_tasks,
            (SELECT COUNT(*) FROM tasks WHERE status = 'running') AS running_tasks,
            (SELECT COUNT(*) FROM tasks WHERE status = 'completed') AS completed_tasks,
            (SELECT COUNT(*) FROM findings) AS total_findings,
            (SELECT COUNT(*) FROM findings WHERE status = 'verified') AS verified_findings,
            (SELECT COUNT(*) FROM attack_chains) AS total_chains,
            (SELECT MAX(cvss_score) FROM findings WHERE cvss_score IS NOT NULL) AS max_cvss
        """
    )
    result = await db.execute(stmt)
    row = result.one()

    # 按任务整体风险等级分组
    risk_stmt = (
        select(Task.overall_risk, func.count().label("count"))
        .where(Task.overall_risk.isnot(None))
        .group_by(Task.overall_risk)
    )
    risk_result = await db.execute(risk_stmt)
    risk_distribution = {row[0]: row[1] for row in risk_result if row[0] is not None}

    return {
        "total_projects": row.total_projects,
        "total_tasks": row.total_tasks,
        "running_tasks": row.running_tasks,
        "completed_tasks": row.completed_tasks,
        "total_findings": row.total_findings,
        "verified_findings": row.verified_findings,
        "total_chains": row.total_chains,
        "max_cvss": float(row.max_cvss) if row.max_cvss is not None else None,
        "overall_risk_distribution": risk_distribution,
    }


# ──────────────────────────────────────────────────────
# 严重等级分布
# ──────────────────────────────────────────────────────


async def get_severity_distribution(db: AsyncSession) -> dict:
    """获取漏洞严重等级分布（饼图数据）。

    Returns:
        {"items": [{"severity": "critical", "count": 5}, ...], "total": N}
    """
    stmt = (
        select(Finding.severity, func.count().label("count"))
        .group_by(Finding.severity)
        .order_by(
            # 按 critical > high > medium > low > info 排序
            text(
                "CASE severity "
                "WHEN 'critical' THEN 0 "
                "WHEN 'high' THEN 1 "
                "WHEN 'medium' THEN 2 "
                "WHEN 'low' THEN 3 "
                "WHEN 'info' THEN 4 "
                "ELSE 5 END"
            )
        )
    )
    result = await db.execute(stmt)
    rows = result.all()

    items = [{"severity": row[0], "count": row[1]} for row in rows]
    total = sum(item["count"] for item in items)

    return {"items": items, "total": total}


# ──────────────────────────────────────────────────────
# 趋势数据
# ──────────────────────────────────────────────────────


async def get_trend(db: AsyncSession, days: int = 30) -> dict:
    """获取近 N 天漏洞发现趋势（按天分组）。

    Args:
        days: 查询天数范围（最大 365）

    Returns:
        {"days": N, "data_points": [{"date": "2026-09-01", "count": 3}, ...]}
    """
    days = min(days, 365)
    start_date = datetime.now(timezone.utc) - timedelta(days=days)

    stmt = (
        select(
            func.to_char(Finding.created_at, "YYYY-MM-DD").label("date"),
            func.count().label("count"),
        )
        .where(Finding.created_at >= start_date)
        .group_by(text("date"))
        .order_by(text("date"))
    )
    result = await db.execute(stmt)
    rows = result.all()

    # 填充没有数据的日期为 0
    data_map = {row[0]: row[1] for row in rows}
    data_points = []
    for i in range(days):
        date = datetime.now(timezone.utc) - timedelta(days=days - 1 - i)
        date_str = date.strftime("%Y-%m-%d")
        data_points.append({"date": date_str, "count": data_map.get(date_str, 0)})

    return {"days": days, "data_points": data_points}


# ──────────────────────────────────────────────────────
# 最近任务
# ──────────────────────────────────────────────────────


async def get_recent_tasks(db: AsyncSession, limit: int = 10) -> dict:
    """获取最近任务列表（JOIN project 拿项目名）。

    Args:
        limit: 返回条数（最大 100）

    Returns:
        {"items": [task_summary_dict, ...], "total": limit}
    """
    limit = min(limit, 100)

    stmt = (
        select(
            Task.id,
            Task.status,
            Task.overall_risk,
            Task.current_phase,
            Task.created_at,
            Project.project_name,
        )
        .join(Project, Task.project_id == Project.id)
        .order_by(Task.created_at.desc())
        .limit(limit)
    )
    result = await db.execute(stmt)
    rows = result.all()

    items = [
        {
            "id": row[0],
            "status": row[1],
            "overall_risk": row[2],
            "current_phase": row[3],
            "created_at": row[4],
            "project_name": row[5],
        }
        for row in rows
    ]

    return {"items": items, "total": len(items)}
