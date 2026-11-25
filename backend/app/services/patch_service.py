"""修复补丁服务模块（业务门面）。

本模块串起 patches 三层，提供完整业务接口：
- generate_patch(db, redis, finding_id) → 调 generator 写 patch 记录
  （adopt_status=pending, validated=False），返回 patch_id
- validate_patch(db, redis, patch_id) → 调 validator 三步走，更新
  validation_result 和 validated 字段，发布 WS 事件
- adopt_patch(db, redis, patch_id) → 状态 → adopted + finding 状态 → adopted
- reject_patch(db, redis, patch_id, reason) → 状态 → rejected
- get_patches_by_task(db, task_id) → 列表
- get_patch_diff(db, patch_id) → 给前端展示 diff 的纯文本
- export_patch_zip(db, patch_id) → 打包 zip（含 original + patched + diff + 说明）
"""

import io
import logging
import zipfile
from pathlib import Path
from typing import Any

from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import (
    AppError,
    FindingNotFoundError,
    PatchNotFoundError,
)
from app.enums import FindingStatus
from app.models import FixPatch, SourceSnapshot, Task
from app.patches.generator import generate_patch
from app.patches.repository import (
    get_patch,
    get_patch_by_finding,
    list_patches_by_task,
    save_patch,
    update_adopt_status,
    update_validation_result,
)
from app.patches.validator import validate_patch as run_validation
from app.services.finding_service import get_finding, update_finding_status
from app.utils import append_task_log
from app.websockets.publisher import EventPublisher

logger = logging.getLogger(__name__)

PATCH_AGENT = "patch_agent"


async def _load_real_source_code(db: AsyncSession, finding) -> None:
    """把扫描器可能无效的 snippet 替换为源码快照中的真实文件内容。"""
    if not finding.file_path:
        return

    task = await db.get(Task, finding.task_id)
    if not task or not task.source_snapshot_id:
        return
    snapshot = await db.get(SourceSnapshot, task.source_snapshot_id)
    if not snapshot or not snapshot.snapshot_path:
        return

    source_root = Path(snapshot.snapshot_path)
    relative = str(finding.file_path).replace("\\", "/").lstrip("/")
    candidates = [
        source_root / relative,
        source_root / relative.replace("/", "\\"),
    ]
    if not any(candidate.exists() for candidate in candidates):
        try:
            matches = list(source_root.rglob(relative.split("/")[-1]))
        except OSError:
            matches = []
        if not matches:
            return
        candidates.append(matches[0])

    source_file = next((candidate for candidate in candidates if candidate.is_file()), None)
    if source_file is None:
        return

    try:
        content = source_file.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return

    lines = content.splitlines()
    start = max(0, (finding.line_start or 1) - 1)
    end = min(len(lines), finding.line_end or finding.line_start or start + 1)
    target_code = "\n".join(lines[start:end]) or content

    finding.snippet = target_code
    finding.code_context = content
    if not finding.source_code or "requires login" in finding.source_code:
        finding.source_code = target_code
    if not finding.sink_code or "requires login" in finding.sink_code:
        finding.sink_code = target_code


# ──────────────────────────────────────────────────────
# 补丁生成
# ──────────────────────────────────────────────────────


async def generate_patch_for_finding(
    db: AsyncSession,
    redis: Redis,
    finding_id: str,
    force_regenerate: bool = False,
) -> str:
    """为漏洞生成修复补丁。

    流程：
    1. 读取 finding
    2. 调用 generator.generate_patch（LLM + 规则兜底）
    3. 保存到 fix_patches 表（adopt_status=pending, validated=0）
    4. 发布 patch_ready WS 事件
    5. 返回 patch_id

    Args:
        db: 数据库会话
        redis: Redis 连接
        finding_id: 漏洞 ID

    Returns:
        patch_id

    Raises:
        FindingNotFoundError: 漏洞不存在
    """
    # 1. 读取 finding
    finding = await get_finding(db, finding_id)
    if finding is None:
        raise FindingNotFoundError(finding_id)

    # 检查是否已有补丁
    existing = await get_patch_by_finding(db, finding_id)
    if existing is not None:
        should_rebuild = (
            force_regenerate
            or not existing.diff_content
            or "requires login" in (existing.original_code or "")
        )
        if not should_rebuild:
            logger.info(
                "[patch_service] Patch already exists for finding %s: %s",
                finding_id,
                existing.id,
            )
            return existing.id
        logger.info(
            "[patch_service] Removing/replacing patch for finding %s: %s",
            finding_id,
            existing.id,
        )
        await db.delete(existing)
        await db.flush()

    await _load_real_source_code(db, finding)

    # 2. 生成补丁
    result = generate_patch(finding)
    logger.info(
        "[patch_service] Generated patch for finding %s (model=%s, diff_len=%d)",
        finding_id,
        result.llm_model,
        len(result.diff_content),
    )

    # 3. 保存
    patch = await save_patch(
        db=db,
        finding_id=finding_id,
        task_id=finding.task_id,
        original_code=result.original_code,
        patched_code=result.patched_code,
        diff_content=result.diff_content,
        description=result.description,
        llm_model=result.llm_model,
        token_usage=result.token_usage,
    )
    await db.commit()

    # 4. 发布 WS 事件
    await EventPublisher.publish(
        redis,
        finding.task_id,
        "patch_ready",
        {
            "patch_id": patch.id,
            "finding_id": finding_id,
            "llm_model": result.llm_model,
            "validated": False,
            "adopt_status": "pending",
            "description": result.description,
            "message": f"补丁已生成: {result.description}",
        },
    )

    # 5. 写日志
    await append_task_log(
        db,
        finding.task_id,
        "patch",
        PATCH_AGENT,
        "info",
        f"补丁生成完成 (finding={finding_id}, patch={patch.id}, model={result.llm_model})",
        detail={
            "patch_id": patch.id,
            "finding_id": finding_id,
            "llm_model": result.llm_model,
            "token_usage": result.token_usage,
        },
    )

    return patch.id


# ──────────────────────────────────────────────────────
# 补丁校验
# ──────────────────────────────────────────────────────


async def validate_patch_by_id(
    db: AsyncSession,
    redis: Redis,
    patch_id: str,
    sandbox_manager: Any | None = None,
    container_id: str | None = None,
) -> dict[str, Any]:
    """校验补丁（三层：语法/编译/安全回归）。

    Args:
        db: 数据库会话
        redis: Redis 连接
        patch_id: 补丁 ID
        sandbox_manager: 沙箱管理器（可选）。若不传，自动从 task 查找。
        container_id: 容器 ID（可选）。若不传，自动从 sandbox_instance 查找。

    Returns:
        校验结果字典

    Raises:
        PatchNotFoundError: 补丁不存在
    """
    patch = await get_patch(db, patch_id)
    if patch is None:
        raise PatchNotFoundError(patch_id)

    # 读取关联 finding
    finding = await get_finding(db, patch.finding_id)

    # ── 自动解析沙箱参数（修复 Bug 2：之前一直传 None 导致安全回归永远跳过）──
    if sandbox_manager is None or container_id is None:
        from app.services.sandbox_service import get_sandbox_by_task
        from app.sandbox.manager import get_docker_manager

        sandbox_manager = sandbox_manager or get_docker_manager()
        sandbox_instance = await get_sandbox_by_task(db, patch.task_id)
        if (
            sandbox_instance
            and sandbox_instance.container_id
            and sandbox_instance.status not in ("destroyed", "error")
        ):
            container_id = sandbox_instance.container_id

    # ── 执行校验（validator 是同步函数，security_regression 会调用 sandbox_manager.exec_command，
    #     在 async 上下文里会阻塞事件循环，因此用 run_in_executor 包装）──
    import asyncio

    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(
        None,
        lambda: run_validation(
            patched_code=patch.patched_code or "",
            finding=finding,
            sandbox_manager=sandbox_manager,
            container_id=container_id,
        ),
    )

    # 更新数据库
    await update_validation_result(
        db=db,
        patch_id=patch_id,
        validated=result.overall_passed,
        validation_result=result.to_dict(),
    )
    await db.commit()

    # 发布 WS 事件
    await EventPublisher.publish(
        redis,
        patch.task_id,
        "patch_validated",
        {
            "patch_id": patch_id,
            "finding_id": patch.finding_id,
            "validated": result.overall_passed,
            "validation_result": result.to_dict(),
            "message": ("补丁校验通过" if result.overall_passed else "补丁校验未通过"),
        },
    )

    # 写日志
    await append_task_log(
        db,
        patch.task_id,
        "patch",
        PATCH_AGENT,
        "info" if result.overall_passed else "warning",
        f"补丁校验 {'通过' if result.overall_passed else '未通过'} (patch={patch_id})",
        detail={
            "patch_id": patch_id,
            "validated": result.overall_passed,
            "validation_result": result.to_dict(),
        },
    )

    return {
        "patch_id": patch_id,
        "validated": result.overall_passed,
        "validation_result": result.to_dict(),
        "message": "补丁校验通过" if result.overall_passed else "补丁校验未通过",
    }


# ──────────────────────────────────────────────────────
# 采纳 / 拒绝
# ──────────────────────────────────────────────────────


async def adopt_patch(
    db: AsyncSession,
    redis: Redis,
    patch_id: str,
) -> FixPatch:
    """采纳补丁。

    - 更新补丁 adopt_status → adopted
    - 更新关联 finding 状态 → adopted

    Args:
        db: 数据库会话
        redis: Redis 连接
        patch_id: 补丁 ID

    Returns:
        更新后的 FixPatch 对象

    Raises:
        PatchNotFoundError: 补丁不存在
        FindingNotFoundError: 关联漏洞不存在
    """
    patch = await get_patch(db, patch_id)
    if patch is None:
        raise PatchNotFoundError(patch_id)

    # 1. 更新补丁状态（直接修改 ORM 对象，不重新查询）
    patch.adopt_status = "adopted"
    await db.flush()

    # 2. 通过 finding_service 更新漏洞状态（享受 WS 事件 + 审计日志 + task_log）
    await update_finding_status(
        db,
        redis,
        patch.task_id,
        patch.finding_id,
        FindingStatus.ADOPTED.value,
        reason="补丁已采纳",
    )

    # 3. 发布 WS 事件
    await EventPublisher.publish(
        redis,
        patch.task_id,
        "patch_adopted",
        {
            "patch_id": patch_id,
            "finding_id": patch.finding_id,
            "adopt_status": "adopted",
            "message": "补丁已采纳",
        },
    )

    # 4. 写日志
    await append_task_log(
        db,
        patch.task_id,
        "patch",
        PATCH_AGENT,
        "info",
        f"补丁已采纳 (patch={patch_id}, finding={patch.finding_id})",
        detail={
            "patch_id": patch_id,
            "finding_id": patch.finding_id,
            "adopt_status": "adopted",
        },
    )

    await db.commit()
    return patch


async def reject_patch(
    db: AsyncSession,
    redis: Redis,
    patch_id: str,
    reason: str | None = None,
) -> FixPatch:
    """拒绝补丁。

    Args:
        db: 数据库会话
        redis: Redis 连接
        patch_id: 补丁 ID
        reason: 拒绝理由

    Returns:
        更新后的 FixPatch 对象

    Raises:
        PatchNotFoundError: 补丁不存在
    """
    patch = await get_patch(db, patch_id)
    if patch is None:
        raise PatchNotFoundError(patch_id)

    finding = await get_finding(db, patch.finding_id)
    patch.adopt_status = "rejected"
    await db.flush()

    if finding and finding.status == FindingStatus.ADOPTED.value:
        # 拒绝已采纳的补丁时，漏洞状态恢复为“潜在隐患/待复核”，避免继续显示已采纳。
        await update_finding_status(
            db,
            redis,
            patch.task_id,
            patch.finding_id,
            FindingStatus.LATENT.value,
            reason="补丁已拒绝",
        )

    await db.commit()

    # 发布 WS 事件
    await EventPublisher.publish(
        redis,
        patch.task_id,
        "patch_rejected",
        {
            "patch_id": patch_id,
            "finding_id": patch.finding_id,
            "adopt_status": "rejected",
            "reason": reason or "",
            "message": "补丁已拒绝",
        },
    )

    # 写日志
    await append_task_log(
        db,
        patch.task_id,
        "patch",
        PATCH_AGENT,
        "info",
        f"补丁已拒绝 (patch={patch_id}, reason={reason or 'N/A'})",
        detail={
            "patch_id": patch_id,
            "finding_id": patch.finding_id,
            "adopt_status": "rejected",
            "reason": reason,
        },
    )

    return patch


# ──────────────────────────────────────────────────────
# 查询
# ──────────────────────────────────────────────────────


async def get_patches_by_task(
    db: AsyncSession,
    task_id: str,
) -> list[FixPatch]:
    """获取任务下所有补丁。"""
    return await list_patches_by_task(db, task_id)


async def get_patch_for_finding(
    db: AsyncSession,
    finding_id: str,
) -> FixPatch | None:
    """查询漏洞已有补丁，不触发生成。"""
    patch = await get_patch_by_finding(db, finding_id)
    if patch is None or not patch.diff_content:
        return None
    return patch


async def get_patch_detail(
    db: AsyncSession,
    patch_id: str,
) -> FixPatch:
    """获取补丁详情。

    Raises:
        PatchNotFoundError: 补丁不存在
    """
    patch = await get_patch(db, patch_id)
    if patch is None:
        raise PatchNotFoundError(patch_id)
    return patch


async def get_patch_diff_text(
    db: AsyncSession,
    patch_id: str,
) -> str:
    """获取补丁 diff 纯文本。

    Raises:
        PatchNotFoundError: 补丁不存在
    """
    patch = await get_patch(db, patch_id)
    if patch is None:
        raise PatchNotFoundError(patch_id)
    return patch.diff_content or ""


# ──────────────────────────────────────────────────────
# 导出 ZIP
# ──────────────────────────────────────────────────────


async def export_patch_zip(
    db: AsyncSession,
    patch_id: str,
) -> bytes:
    """将补丁打包为 ZIP 文件。

    ZIP 内含：
    - original_code.<ext>：原始漏洞代码
    - patched_code.<ext>：修复后代码
    - diff.patch：统一 Diff
    - README.md：补丁说明（漏洞信息 + 修复说明 + 采纳状态）

    Args:
        db: 数据库会话
        patch_id: 补丁 ID

    Returns:
        ZIP 文件字节流

    Raises:
        PatchNotFoundError: 补丁不存在
    """
    patch = await get_patch(db, patch_id)
    if patch is None:
        raise PatchNotFoundError(patch_id)

    # 读取关联 finding
    finding = await get_finding(db, patch.finding_id)

    # 根据文件路径确定扩展名
    ext = ".py"
    if finding and finding.file_path:
        import os

        _, file_ext = os.path.splitext(finding.file_path)
        if file_ext:
            ext = file_ext

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # 原始代码
        zf.writestr(
            f"original_code{ext}",
            patch.original_code or "",
        )
        # 修复后代码
        zf.writestr(
            f"patched_code{ext}",
            patch.patched_code or "",
        )
        # Diff
        zf.writestr("diff.patch", patch.diff_content or "")
        # 说明
        readme = _build_readme(patch, finding)
        zf.writestr("README.md", readme)

    return buf.getvalue()


def _build_readme(patch: FixPatch, finding: Any | None) -> str:
    """构建 README 说明文件。"""
    lines = [
        "# 修复补丁说明",
        "",
        f"- **补丁 ID**: {patch.id}",
        f"- **漏洞 ID**: {patch.finding_id}",
        f"- **任务 ID**: {patch.task_id}",
        f"- **采纳状态**: {patch.adopt_status}",
        f"- **校验通过**: {'是' if patch.validated else '否'}",
        f"- **生成模型**: {patch.llm_model or 'N/A'}",
        f"- **Token 用量**: {patch.token_usage or 0}",
        "",
    ]

    if finding:
        lines.extend(
            [
                "## 漏洞信息",
                "",
                f"- **漏洞类型**: {finding.vuln_type}",
                f"- **CWE**: {finding.cwe_id or 'N/A'}",
                f"- **严重等级**: {finding.severity}",
                f"- **CVSS 评分**: {finding.cvss_score if finding.cvss_score is not None else 'N/A'}",
                f"- **CVSS 向量**: {finding.cvss_vector or 'N/A'}",
                f"- **文件路径**: {finding.file_path or 'N/A'}",
                f"- **触发行号**: {finding.line_start if finding.line_start is not None else 'N/A'}",
                "",
            ]
        )

    lines.extend(
        [
            "## 修复说明",
            "",
            patch.description or "N/A",
            "",
            "## 文件列表",
            "",
            "- `original_code.*` - 原始漏洞代码",
            "- `patched_code.*` - 修复后代码",
            "- `diff.patch` - 统一 Diff（可直接 `git apply`）",
            "",
        ]
    )

    return "\n".join(lines)
