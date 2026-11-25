"""报告路由模块。

提供报告管理的完整 API：
- GET    /tasks/{task_id}/report              获取报告摘要
- POST   /tasks/{task_id}/report/regenerate    重新生成报告
- POST   /tasks/{task_id}/report/export        导出报告（markdown/html 同步，pdf 异步）
- GET    /reports/{report_id}                  获取完整详情
- DELETE /reports/{report_id}                  删除报告及导出文件
- GET    /reports/{report_id}/download/{format} 下载文件
- GET    /reports/{report_id}/sections/{name}  获取单章节数据
"""

from fastapi import APIRouter, Depends, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.errors import AppError
from app.core.redis import get_redis
from app.core.security import get_current_user
from app.schemas.report import (
    ReportDetailResponse,
    ReportExportRequest,
    ReportExportResponse,
    ReportSectionResponse,
    ReportSummaryResponse,
)
from app.schemas.common import SuccessResponse
from app.services.report_service import (
    delete_report,
    export_report,
    get_report_by_id,
    get_report_by_task,
    get_report_file_path,
    list_reports,
    regenerate_report,
)
from app.services.task_service import get_task

router = APIRouter(tags=["报告"])


@router.get("/reports")
async def list_all_reports(
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    operator: str = Depends(get_current_user),
) -> dict:
    """获取全部报告列表。"""
    return await list_reports(db, page=page, size=size)


# ──────────────────────────────────────────────────────
# 获取报告摘要
# ──────────────────────────────────────────────────────


@router.get(
    "/tasks/{task_id}/report",
    response_model=ReportSummaryResponse,
)
async def get_task_report(
    task_id: str,
    db: AsyncSession = Depends(get_db),
    operator: str = Depends(get_current_user),
) -> ReportSummaryResponse:
    """获取任务最新版报告摘要。"""
    if await get_task(db, task_id) is None:
        raise AppError(
            status_code=404,
            code="task_not_found",
            message=f"Task {task_id} not found",
        )

    report = await get_report_by_task(db, task_id)
    if report is None:
        raise AppError(
            status_code=404,
            code="report_not_found",
            message=f"Report for task {task_id} not yet generated",
        )
    return ReportSummaryResponse.model_validate(report)


# ──────────────────────────────────────────────────────
# 重新生成报告
# ──────────────────────────────────────────────────────


class RegenerateResponse(BaseModel):
    """重新生成报告的响应。"""

    success: bool
    report_id: str | None
    version: int
    overall_risk: str
    total_findings: int
    message: str


@router.post(
    "/tasks/{task_id}/report/regenerate",
    response_model=RegenerateResponse,
)
async def regenerate_task_report(
    task_id: str,
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis),
    operator: str = Depends(get_current_user),
) -> RegenerateResponse:
    """重新生成报告（version+1，不覆盖旧文件）。"""
    if await get_task(db, task_id) is None:
        raise AppError(
            status_code=404,
            code="task_not_found",
            message=f"Task {task_id} not found",
        )

    result = await regenerate_report(db, redis, task_id)

    return RegenerateResponse(
        success=result.success,
        report_id=result.report_id,
        version=result.version,
        overall_risk=result.overall_risk,
        total_findings=result.total_findings,
        message=(
            f"报告重新生成完成 (v{result.version})"
            if result.success
            else f"报告重新生成失败: {result.error}"
        ),
    )


# ──────────────────────────────────────────────────────
# 导出报告
# ──────────────────────────────────────────────────────


@router.post(
    "/tasks/{task_id}/report/export",
    response_model=ReportExportResponse,
)
async def export_task_report(
    task_id: str,
    request: ReportExportRequest,
    db: AsyncSession = Depends(get_db),
    operator: str = Depends(get_current_user),
) -> ReportExportResponse:
    """导出报告（markdown/html 同步返回路径，pdf 异步占位）。

    用户指定 format=markdown|html|pdf：
    - markdown/html：返回文件路径和下载 URL
    - pdf：当前返回未实现提示（下一阶段异步队列实现）
    """
    if await get_task(db, task_id) is None:
        raise AppError(
            status_code=404,
            code="task_not_found",
            message=f"Task {task_id} not found",
        )

    fmt = request.format
    result = await export_report(db, task_id, fmt)

    report = await get_report_by_task(db, task_id)
    download_url = (
        f"/api/v1/reports/{report.id}/download/{fmt}"
        if report and result["success"]
        else None
    )

    return ReportExportResponse(
        file_path=result.get("file_path"),
        format=fmt,
        download_url=download_url,
        success=result.get("success", False),
        message=result.get("message", ""),
    )


# ──────────────────────────────────────────────────────
# 获取完整详情
# ──────────────────────────────────────────────────────


@router.get(
    "/reports/{report_id}",
    response_model=ReportDetailResponse,
)
async def get_report_detail(
    report_id: str,
    db: AsyncSession = Depends(get_db),
    operator: str = Depends(get_current_user),
) -> ReportDetailResponse:
    """获取报告完整详情（含 5 个章节的完整数据）。"""
    report = await get_report_by_id(db, report_id)
    if report is None:
        raise AppError(
            status_code=404,
            code="report_not_found",
            message=f"Report {report_id} not found",
        )
    return ReportDetailResponse.model_validate(report)


@router.delete("/reports/{report_id}", response_model=SuccessResponse)
async def delete_report_endpoint(
    report_id: str,
    db: AsyncSession = Depends(get_db),
    operator: str = Depends(get_current_user),
) -> SuccessResponse:
    """删除报告记录及其导出的 Markdown/HTML/PDF 文件。"""
    report = await delete_report(db, report_id, operator)
    if report is None:
        raise AppError(
            status_code=404,
            code="report_not_found",
            message=f"报告不存在: {report_id}",
        )
    return SuccessResponse(message=f"报告已删除: {report_id}")


# ──────────────────────────────────────────────────────
# 下载文件
# ──────────────────────────────────────────────────────


@router.get(
    "/reports/{report_id}/download/{format}",
)
async def download_report_file(
    report_id: str,
    format: str,
    db: AsyncSession = Depends(get_db),
    operator: str = Depends(get_current_user),
) -> FileResponse:
    """下载报告文件（markdown / html / pdf）。

    返回 FileResponse，设置 Content-Disposition: attachment。
    """
    if format not in ("markdown", "html", "pdf"):
        raise AppError(
            status_code=400,
            code="invalid_format",
            message=f"Unsupported format: {format}. Use markdown, html, or pdf.",
        )

    file_path = await get_report_file_path(db, report_id, format)
    if file_path is None:
        raise AppError(
            status_code=404,
            code="file_not_found",
            message=f"Report file not found: report_id={report_id}, format={format}",
        )

    # 确定文件名和 media_type
    ext_map = {
        "markdown": ("md", "text/markdown"),
        "html": ("html", "text/html"),
        "pdf": ("pdf", "application/pdf"),
    }
    ext, media_type = ext_map.get(format, ("txt", "text/plain"))

    return FileResponse(
        path=str(file_path),
        media_type=media_type,
        filename=f"report.{ext}",
    )


# ──────────────────────────────────────────────────────
# 获取单章节数据
# ──────────────────────────────────────────────────────


@router.get(
    "/reports/{report_id}/sections/{name}",
    response_model=ReportSectionResponse,
)
async def get_report_section(
    report_id: str,
    name: str,
    db: AsyncSession = Depends(get_db),
    operator: str = Depends(get_current_user),
) -> ReportSectionResponse:
    """获取报告的单章节数据。

    章节名：executive_summary / scope / findings / attack_chains / remediation
    """
    valid_sections = {
        "executive_summary",
        "scope",
        "findings",
        "attack_chains",
        "remediation",
    }
    if name not in valid_sections:
        raise AppError(
            status_code=400,
            code="invalid_section",
            message=(
                f"Invalid section name: {name}. "
                f"Valid: {', '.join(sorted(valid_sections))}"
            ),
        )

    report = await get_report_by_id(db, report_id)
    if report is None:
        raise AppError(
            status_code=404,
            code="report_not_found",
            message=f"Report {report_id} not found",
        )

    sections = report.sections or {}
    section_data = sections.get(name)

    return ReportSectionResponse(
        section_name=name,
        section_data=section_data,
    )
