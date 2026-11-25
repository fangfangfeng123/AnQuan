"""报告请求/响应模型。

本模块定义报告的 API 请求与响应模型：
- ReportSummaryResponse：报告摘要（id / task_id / overall_risk / 各 severity 数量 / 文件路径 / 版本 / 创建时间）
- ReportSectionResponse：单章节（章节名 + 数据）
- ReportDetailResponse：完整报告（含 5 个章节的完整数据）
- ReportExportRequest：导出请求（format: markdown | html | pdf）
- ReportExportResponse：导出响应（file_path / download_url / message）
- PaginatedReportResponse：分页报告列表
"""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class ReportSummaryResponse(BaseModel):
    """报告摘要响应。"""

    id: str = Field(..., description="报告 ID")
    project_name: str | None = Field(None, description="项目名称")
    task_id: str = Field(..., description="任务 ID")
    project_id: str = Field(..., description="项目 ID")
    overall_risk: str = Field(..., description="整体风险等级")
    overall_cvss: float | None = Field(None, description="最高 CVSS 评分")
    total_findings: int = Field(0, description="漏洞总数")
    critical_count: int = Field(0, description="严重漏洞数")
    high_count: int = Field(0, description="高危漏洞数")
    medium_count: int = Field(0, description="中危漏洞数")
    low_count: int = Field(0, description="低危漏洞数")
    info_count: int = Field(0, description="信息漏洞数")
    markdown_path: str | None = Field(None, description="Markdown 文件路径")
    html_path: str | None = Field(None, description="HTML 文件路径")
    pdf_path: str | None = Field(None, description="PDF 文件路径")
    version: int = Field(1, description="版本号")
    created_at: datetime | None = None
    updated_at: datetime | None = None

    class Config:
        from_attributes = True


class ReportSectionResponse(BaseModel):
    """单章节响应。"""

    section_name: str = Field(..., description="章节名")
    section_data: Any = Field(None, description="章节数据（dict 或 list）")


class ReportDetailResponse(BaseModel):
    """报告完整详情响应。"""

    id: str = Field(..., description="报告 ID")
    task_id: str = Field(..., description="任务 ID")
    project_id: str = Field(..., description="项目 ID")
    overall_risk: str = Field(..., description="整体风险等级")
    overall_cvss: float | None = Field(None, description="最高 CVSS")
    total_findings: int = Field(0, description="漏洞总数")
    critical_count: int = Field(0, description="严重漏洞数")
    high_count: int = Field(0, description="高危漏洞数")
    medium_count: int = Field(0, description="中危漏洞数")
    low_count: int = Field(0, description="低危漏洞数")
    info_count: int = Field(0, description="信息漏洞数")
    sections: dict = Field(default_factory=dict, description="5 个章节的完整数据")
    markdown_path: str | None = Field(None, description="Markdown 文件路径")
    html_path: str | None = Field(None, description="HTML 文件路径")
    pdf_path: str | None = Field(None, description="PDF 文件路径")
    version: int = Field(1, description="版本号")
    created_at: datetime | None = None
    updated_at: datetime | None = None

    class Config:
        from_attributes = True


class ReportExportRequest(BaseModel):
    """报告导出请求。"""

    format: str = Field(
        "markdown",
        description="导出格式: markdown | html | pdf",
    )


class ReportExportResponse(BaseModel):
    """报告导出响应。"""

    file_path: str | None = Field(None, description="文件路径")
    format: str = Field(..., description="导出格式")
    download_url: str | None = Field(None, description="下载 URL")
    success: bool = Field(False, description="是否成功")
    message: str = Field("", description="消息")


class PaginatedReportResponse(BaseModel):
    """分页报告列表响应。"""

    items: list[ReportSummaryResponse] = Field(
        default_factory=list, description="报告列表"
    )
    total: int = Field(0, description="总数")
    page: int = Field(1, description="当前页")
    size: int = Field(20, description="每页数量")
