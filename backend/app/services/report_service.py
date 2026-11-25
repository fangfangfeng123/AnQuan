"""报告服务模块。

本模块封装报告生成和导出的业务逻辑，作为 Agent 和 Router 的统一门面：
- generate_report(db, redis, task_id)：主流程——聚合数据 -> 渲染模板 -> 写文件 -> 入库 -> 发WS
- get_report_by_task(db, task_id)：查询最新版报告
- get_report_file_path(db, report_id, format)：获取报告文件路径
- regenerate_report(db, redis, task_id)：强制重新生成（version+1）
- export_report(db, task_id, format)：导出报告（markdown/html 同步，pdf 异步）

架构：参照 poc_service / attack_chain_service 的 Service 门面模式。
"""

import logging
from dataclasses import dataclass
from pathlib import Path

from redis.asyncio import Redis
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.enums import PhaseName
from app.models import Report
from app.reports.exporter import to_html, to_markdown, to_pdf_async
from app.reports.generator import ReportData, assemble_report_data
from app.services.audit_service import log_action
from app.services.data_cleanup_service import delete_report_files
from app.utils import append_task_log, generate_id
from app.websockets.publisher import EventPublisher

logger = logging.getLogger(__name__)

REPORT_AGENT = "report_gen_agent"
_REPORT_PHASE = PhaseName.REPORT_GEN.value
_settings = get_settings()


# ──────────────────────────────────────────────────────
# 结果数据结构
# ──────────────────────────────────────────────────────


@dataclass
class ReportSummary:
    """报告生成结果摘要。"""

    success: bool
    report_id: str | None = None
    version: int = 0
    overall_risk: str = "secure"
    overall_cvss: float | None = None
    total_findings: int = 0
    markdown_path: str | None = None
    html_path: str | None = None
    error: str | None = None


# ──────────────────────────────────────────────────────
# 主流程
# ──────────────────────────────────────────────────────


async def generate_report(
    db: AsyncSession,
    redis: Redis,
    task_id: str,
) -> ReportSummary:
    """生成安全评估报告。

    流程：
    1. 调 generator.assemble_report_data 聚合全部数据
    2. 调 exporter.to_markdown / to_html 渲染字符串
    3. 写文件到 {REPORT_OUTPUT_DIR}/{task_id}/report_v{version}.md/.html
    4. 创建/更新 reports 表记录（version+1）
    5. 写任务日志
    6. 发 WS 事件 report_ready
    7. 返回 ReportSummary

    Args:
        db: 数据库会话
        redis: Redis 连接
        task_id: 任务 ID

    Returns:
        ReportSummary
    """
    # ── 1. 聚合数据 ──
    try:
        data: ReportData = await assemble_report_data(db, task_id)
    except Exception as e:
        logger.exception("[report_service] Failed to assemble data: %s", e)
        return ReportSummary(success=False, error=f"数据聚合失败: {e}")

    if data.task is None:
        return ReportSummary(success=False, error=f"Task {task_id} not found")

    # ── 2. 确定版本号 ──
    existing = await get_report_by_task(db, task_id)
    version = (existing.version + 1) if existing else 1

    # ── 3. 渲染模板 ──
    template_dir = str(
        Path(_settings.REPORT_TEMPLATE_DIR)
        if Path(_settings.REPORT_TEMPLATE_DIR).is_absolute()
        else Path.cwd() / _settings.REPORT_TEMPLATE_DIR
    )
    try:
        md_content = to_markdown(data, template_dir)
        html_content = to_html(data, template_dir)
    except Exception as e:
        logger.exception("[report_service] Failed to render templates: %s", e)
        return ReportSummary(success=False, error=f"模板渲染失败: {e}")

    # ── 4. 写文件 ──
    output_dir = Path(_settings.REPORT_OUTPUT_DIR) / task_id
    output_dir.mkdir(parents=True, exist_ok=True)

    md_filename = f"report_v{version}.md"
    html_filename = f"report_v{version}.html"
    pdf_filename = f"report_v{version}.pdf"
    md_path = output_dir / md_filename
    html_path = output_dir / html_filename
    pdf_path = output_dir / pdf_filename

    try:
        md_path.write_text(md_content, encoding="utf-8")
        html_path.write_text(html_content, encoding="utf-8")
    except Exception as e:
        logger.exception("[report_service] Failed to write files: %s", e)
        return ReportSummary(success=False, error=f"文件写入失败: {e}")

    # 生成 PDF；本机无可用浏览器时不阻塞报告生成
    generated_pdf = await to_pdf_async(str(html_path), str(pdf_path))

    # ── 5. 入库 ──
    sev_dist = data.statistics.get("severity_distribution", {})
    report_id = generate_id()
    report = Report(
        id=report_id,
        task_id=task_id,
        project_id=data.task.project_id,
        sections=data.sections,
        total_findings=data.statistics.get("total_findings", 0),
        critical_count=sev_dist.get("critical", 0),
        high_count=sev_dist.get("high", 0),
        medium_count=sev_dist.get("medium", 0),
        low_count=sev_dist.get("low", 0),
        info_count=sev_dist.get("info", 0),
        overall_risk=data.overall_risk,
        overall_cvss=data.overall_cvss,
        markdown_path=str(md_path),
        html_path=str(html_path),
        pdf_path=generated_pdf,
        version=version,
    )
    db.add(report)
    await db.commit()

    # ── 6. 写日志 ──
    await append_task_log(
        db,
        task_id,
        _REPORT_PHASE,
        REPORT_AGENT,
        "info",
        (
            f"报告生成完成 (v{version}): {report.total_findings} 漏洞, "
            f"风险={report.overall_risk}"
        ),
        detail={
            "report_id": report_id,
            "version": version,
            "markdown_path": str(md_path),
            "html_path": str(html_path),
        },
    )

    # ── 7. 发 WS 事件 ──
    await EventPublisher.publish(
        redis,
        task_id,
        "report_ready",
        {
            "report_id": report_id,
            "version": version,
            "overall_risk": report.overall_risk,
            "total_findings": report.total_findings,
            "markdown_download_url": f"/api/v1/reports/{report_id}/download/markdown",
            "html_download_url": f"/api/v1/reports/{report_id}/download/html",
            "message": f"安全评估报告已生成 (v{version})",
        },
    )

    logger.info(
        "[report_service] Report generated: task=%s, v%d, risk=%s",
        task_id,
        version,
        report.overall_risk,
    )

    return ReportSummary(
        success=True,
        report_id=report_id,
        version=version,
        overall_risk=report.overall_risk,
        overall_cvss=report.overall_cvss,
        total_findings=report.total_findings,
        markdown_path=str(md_path),
        html_path=str(html_path),
    )


# ──────────────────────────────────────────────────────
# 辅助函数
# ──────────────────────────────────────────────────────


async def get_report_by_task(
    db: AsyncSession,
    task_id: str,
) -> Report | None:
    """查询任务下最新版本的报告。

    Args:
        db: 数据库会话
        task_id: 任务 ID

    Returns:
        Report | None
    """
    stmt = (
        select(Report).where(Report.task_id == task_id).order_by(Report.version.desc())
    )
    result = await db.execute(stmt)
    return result.scalars().first()


async def list_reports(
    db: AsyncSession,
    page: int = 1,
    size: int = 20,
) -> dict:
    """查询全部报告，附项目名称。"""
    from app.models import Project, Report, Task

    stmt = (
        select(Report, Project.project_name)
        .join(Task, Task.id == Report.task_id)
        .join(Project, Project.id == Task.project_id)
        .order_by(Report.created_at.desc())
    )
    count_stmt = select(func.count()).select_from(
        select(Report.id).subquery()
    )
    total = (await db.execute(count_stmt)).scalar_one()

    offset = (page - 1) * size
    result = await db.execute(stmt.offset(offset).limit(size))
    rows = result.all()
    items = []
    for report, project_name in rows:
        item = {
            "id": report.id,
            "project_name": project_name,
            "task_id": report.task_id,
            "project_id": report.project_id,
            "overall_risk": report.overall_risk,
            "overall_cvss": report.overall_cvss,
            "total_findings": report.total_findings,
            "critical_count": report.critical_count,
            "high_count": report.high_count,
            "medium_count": report.medium_count,
            "low_count": report.low_count,
            "info_count": report.info_count,
            "markdown_path": report.markdown_path,
            "html_path": report.html_path,
            "pdf_path": report.pdf_path,
            "version": report.version,
            "created_at": report.created_at,
            "updated_at": report.updated_at,
        }
        items.append(item)

    pages = (total + size - 1) // size if size else 0
    return {"items": items, "total": total, "page": page, "size": size, "pages": pages}


async def get_report_by_id(
    db: AsyncSession,
    report_id: str,
) -> Report | None:
    """按 ID 查询报告。"""
    stmt = select(Report).where(Report.id == report_id)
    result = await db.execute(stmt)
    return result.scalar_one_or_none()


async def get_report_file_path(
    db: AsyncSession,
    report_id: str,
    fmt: str,
) -> Path | None:
    """获取报告文件路径，供前端下载使用。

    Args:
        db: 数据库会话
        report_id: 报告 ID
        fmt: 格式（markdown / html / pdf）

    Returns:
        Path | None：文件路径，不存在返回 None
    """
    report = await get_report_by_id(db, report_id)
    if report is None:
        return None

    if fmt == "markdown":
        path_str = report.markdown_path
    elif fmt == "html":
        path_str = report.html_path
    elif fmt == "pdf":
        path_str = report.pdf_path
    else:
        return None

    if not path_str:
        return None

    path = Path(path_str)
    if not path.exists():
        return None

    return path


async def delete_report(
    db: AsyncSession,
    report_id: str,
    operator: str = "admin",
) -> Report | None:
    """删除报告记录及其导出的 Markdown/HTML/PDF 文件。"""
    report = await get_report_by_id(db, report_id)
    if report is None:
        return None

    await log_action(
        db,
        action="delete",
        operator=operator,
        target_type="report",
        target_id=report_id,
        task_id=report.task_id,
        project_id=report.project_id,
        detail={
            "version": report.version,
            "overall_risk": report.overall_risk,
            "deleted_files": delete_report_files(report),
        },
    )
    await db.delete(report)
    await db.commit()
    return report


async def regenerate_report(
    db: AsyncSession,
    redis: Redis,
    task_id: str,
) -> ReportSummary:
    """强制重新生成报告（version+1，不覆盖旧文件）。

    Args:
        db: 数据库会话
        redis: Redis 连接
        task_id: 任务 ID

    Returns:
        ReportSummary
    """
    await append_task_log(
        db,
        task_id,
        _REPORT_PHASE,
        REPORT_AGENT,
        "info",
        "开始重新生成报告...",
    )

    result = await generate_report(db, redis, task_id)

    if result.success:
        await append_task_log(
            db,
            task_id,
            _REPORT_PHASE,
            REPORT_AGENT,
            "info",
            f"报告重新生成完成 (v{result.version})",
        )

    return result


async def export_report(
    db: AsyncSession,
    task_id: str,
    fmt: str,
) -> dict:
    """导出报告（markdown/html 同步返回路径，pdf 异步）。

    Args:
        db: 数据库会话
        task_id: 任务 ID
        fmt: 格式（markdown / html / pdf）

    Returns:
        dict: {file_path, format, success, message}
    """
    report = await get_report_by_task(db, task_id)
    if report is None:
        return {
            "file_path": None,
            "format": fmt,
            "success": False,
            "message": "Report not found for this task",
        }

    if fmt == "markdown":
        path = report.markdown_path
    elif fmt == "html":
        path = report.html_path
    elif fmt == "pdf":
        if report.pdf_path:
            path = report.pdf_path
        else:
            output_dir = Path(_settings.REPORT_OUTPUT_DIR) / task_id
            output_path = output_dir / f"report_v{report.version}.pdf"
            result = await to_pdf_async(report.html_path or "", str(output_path))
            if result is None:
                return {
                    "file_path": None,
                    "format": "pdf",
                    "success": False,
                    "message": "PDF export failed: no browser available or file not generated",
                }
            path = result
            report.pdf_path = result
            await db.commit()
    else:
        return {
            "file_path": None,
            "format": fmt,
            "success": False,
            "message": f"Unsupported format: {fmt}",
        }

    if not path or not Path(path).exists():
        return {
            "file_path": None,
            "format": fmt,
            "success": False,
            "message": "File not found on disk",
        }

    return {
        "file_path": path,
        "format": fmt,
        "success": True,
        "message": "Export ready",
    }
