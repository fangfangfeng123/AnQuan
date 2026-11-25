"""大盘统计响应模型。

定义仪表盘聚合查询的 Pydantic 响应模型：
- DashboardStatsResponse：总览统计
- SeverityDistributionResponse：各 severity 数量
- TrendDataPoint / TrendResponse：趋势数据
- RecentTaskItem / RecentTasksResponse：最近任务列表
"""

from datetime import datetime

from pydantic import BaseModel, Field


class DashboardStatsResponse(BaseModel):
    """大盘总览统计响应。"""

    total_projects: int = Field(0, description="项目总数")
    total_tasks: int = Field(0, description="任务总数")
    running_tasks: int = Field(0, description="运行中任务数")
    completed_tasks: int = Field(0, description="已完成任务数")
    total_findings: int = Field(0, description="漏洞总数")
    verified_findings: int = Field(0, description="已验证漏洞数")
    total_chains: int = Field(0, description="攻击链总数")
    max_cvss: float | None = Field(None, description="最高 CVSS 评分")
    overall_risk_distribution: dict = Field(
        default_factory=dict,
        description="按任务整体风险等级分布",
    )


class SeverityDistributionItem(BaseModel):
    """单个严重等级分布项。"""

    severity: str = Field(..., description="严重等级")
    count: int = Field(..., description="数量")


class SeverityDistributionResponse(BaseModel):
    """漏洞严重等级分布响应（饼图数据）。"""

    items: list[SeverityDistributionItem] = Field(
        default_factory=list, description="各等级分布"
    )
    total: int = Field(0, description="漏洞总数")


class TrendDataPoint(BaseModel):
    """单个趋势数据点。"""

    date: str = Field(..., description="日期 (YYYY-MM-DD)")
    count: int = Field(..., description="数量")


class TrendResponse(BaseModel):
    """趋势数据响应。"""

    days: int = Field(..., description="查询天数范围")
    data_points: list[TrendDataPoint] = Field(
        default_factory=list, description="趋势数据点列表"
    )


class RecentTaskItem(BaseModel):
    """单条任务摘要。"""

    id: str = Field(..., description="任务 ID")
    project_name: str = Field(..., description="项目名称")
    status: str = Field(..., description="任务状态")
    overall_risk: str | None = Field(None, description="整体风险等级")
    current_phase: str | None = Field(None, description="当前阶段")
    created_at: datetime | None = None


class RecentTasksResponse(BaseModel):
    """最近任务列表响应。"""

    items: list[RecentTaskItem] = Field(default_factory=list, description="任务列表")
    total: int = Field(0, description="总数")
