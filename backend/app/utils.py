"""全局公共工具方法集合。

本模块提供系统中各层共用的工具函数。
"""

import hashlib
import json
import math
import os
import re
from datetime import datetime, timezone
from typing import Any

import ulid
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import (
    FindingNotFoundError,
    ProjectNotFoundError,
    TaskNotFoundError,
)
from app.enums import PHASE_ORDER, PhaseStatus
from app.models import Finding, Project, Task, TaskLog


def generate_id() -> str:
    """生成 ULID 格式唯一 ID（26 字符，时间有序）。"""
    return str(ulid.new())


def now_utc() -> datetime:
    """获取当前 UTC 时间。"""
    return datetime.now(timezone.utc)


def format_iso8601(dt: datetime | None) -> str | None:
    """格式化为 ISO 8601 字符串。"""
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def parse_iso8601(s: str) -> datetime:
    """解析 ISO 8601 字符串为 datetime。"""
    return datetime.fromisoformat(s)


def compute_sha256(data: bytes | str) -> str:
    """计算数据的 SHA-256 哈希。"""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def serialize_model(obj: Any) -> dict:
    """将 Pydantic 模型或 SQLAlchemy 对象序列化为字典。"""
    if hasattr(obj, "model_dump"):
        return obj.model_dump()
    if hasattr(obj, "__dict__"):
        return {k: v for k, v in obj.__dict__.items() if not k.startswith("_")}
    return dict(obj)


async def paginate(
    db: AsyncSession,
    stmt,
    page: int = 1,
    size: int = 20,
) -> dict:
    """通用分页封装。

    Args:
        db: 数据库会话
        stmt: SQLAlchemy select 语句（不带 limit/offset）
        page: 页码（从 1 开始）
        size: 每页条数

    Returns:
        dict: {"items": [...], "total": int, "page": int, "size": int, "pages": int}
    """
    # 查询总数
    from sqlalchemy import func

    count_stmt = select(func.count()).select_from(stmt.order_by(None).subquery())
    total_result = await db.execute(count_stmt)
    total = total_result.scalar_one()

    # 分页查询
    offset = (page - 1) * size
    result = await db.execute(stmt.offset(offset).limit(size))
    items = list(result.scalars().all())

    pages = math.ceil(total / size) if size > 0 else 0

    return {
        "items": items,
        "total": total,
        "page": page,
        "size": size,
        "pages": pages,
    }


async def get_task_or_404(db: AsyncSession, task_id: str) -> Task:
    """获取任务或抛 404。"""
    result = await db.execute(select(Task).where(Task.id == task_id))
    task = result.scalar_one_or_none()
    if task is None:
        raise TaskNotFoundError(task_id)
    return task


async def get_project_or_404(db: AsyncSession, project_id: str) -> Project:
    """获取项目或抛 404。"""
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if project is None:
        raise ProjectNotFoundError(project_id)
    return project


async def get_finding_or_404(db: AsyncSession, finding_id: str) -> Finding:
    """获取漏洞或抛 404。"""
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if finding is None:
        raise FindingNotFoundError(finding_id)
    return finding


async def update_task_phase(
    db: AsyncSession,
    task_id: str,
    phase: str,
    status: str,
) -> Task:
    """更新任务阶段状态。"""
    task = await get_task_or_404(db, task_id)
    phase_status = dict(task.phase_status) if task.phase_status else {}
    phase_status[phase] = status
    task.phase_status = phase_status
    task.current_phase = phase

    # 计算总体进度
    task.overall_progress = calculate_overall_progress(phase_status)

    await db.flush()
    return task


async def append_task_log(
    db: AsyncSession,
    task_id: str,
    phase: str,
    agent: str,
    level: str,
    message: str,
    detail: dict | None = None,
) -> TaskLog:
    """追加任务日志。"""
    log = TaskLog(
        task_id=task_id,
        phase=phase,
        agent=agent,
        level=level,
        message=message,
        detail=detail,
    )
    db.add(log)
    await db.flush()
    return log


def calculate_overall_progress(phase_status: dict) -> float:
    """根据各阶段状态计算总体进度百分比。"""
    weight_per_phase = 100.0 / len(PHASE_ORDER)
    progress = 0.0
    for phase in PHASE_ORDER:
        status = phase_status.get(phase, PhaseStatus.PENDING.value)
        if status == PhaseStatus.COMPLETED.value:
            progress += weight_per_phase
        elif status == PhaseStatus.RUNNING.value:
            progress += weight_per_phase * 0.5
    return round(progress, 1)


def next_phase(current_phase: str) -> str | None:
    """返回下一个阶段名，末尾返回 None。"""
    try:
        idx = PHASE_ORDER.index(current_phase)
    except ValueError:
        return None
    if idx + 1 < len(PHASE_ORDER):
        return PHASE_ORDER[idx + 1]
    return None


def estimate_token_cost(text: str) -> int:
    """粗略估算 LLM token 消耗（1 中文字符 ≈ 2 token，1 英文单词 ≈ 1.3 token）。"""
    chinese_chars = len(re.findall(r"[\u4e00-\u9fff]", text))
    english_chars = len(text) - chinese_chars
    return int(chinese_chars * 2 + english_chars * 0.3)


def truncate_response(text: str, max_tokens: int) -> str:
    """截断超长 LLM 响应。"""
    max_chars = max_tokens * 2
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n\n[... 响应已截断 ...]"


def safe_filename(name: str) -> str:
    """清理文件名中的危险字符。"""
    name = os.path.basename(name)
    name = re.sub(r"[^\w.\-]", "_", name)
    return name[:128]


def ensure_dir(path: str) -> str:
    """确保目录存在。"""
    os.makedirs(path, exist_ok=True)
    return path


def read_file_lines(path: str, max_lines: int = 100) -> list[str]:
    """安全读取文件前 N 行。"""
    lines: list[str] = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for i, line in enumerate(f):
                if i >= max_lines:
                    break
                lines.append(line.rstrip("\n\r"))
    except (FileNotFoundError, PermissionError, OSError):
        pass
    return lines


def merge_dicts(base: dict, override: dict) -> dict:
    """深度合并字典。"""
    result = dict(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = merge_dicts(result[key], value)
        else:
            result[key] = value
    return result
