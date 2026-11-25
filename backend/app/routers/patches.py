"""修复补丁路由模块。

提供补丁生成、详情、Diff、校验、采纳/拒绝、列表和导出功能。
"""

from redis.asyncio import Redis
from fastapi import APIRouter, Depends
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.errors import FindingNotFoundError
from app.core.redis import get_redis
from app.core.security import get_current_user
from app.schemas.fix_patch import (
    FixPatchAdoptRequest,
    FixPatchCreateRequest,
    FixPatchDiffResponse,
    FixPatchListResponse,
    FixPatchResponse,
    FixPatchValidateResponse,
)
from app.services.finding_service import get_finding
from app.services.patch_service import (
    adopt_patch,
    export_patch_zip,
    generate_patch_for_finding,
    get_patch_detail,
    get_patch_diff_text,
    get_patch_for_finding,
    get_patches_by_task,
    reject_patch,
    validate_patch_by_id,
)

router = APIRouter(tags=["修复补丁"])


@router.get(
    "/findings/{finding_id}/patch",
    response_model=FixPatchResponse,
)
async def get_existing_patch(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
    operator: str = Depends(get_current_user),
) -> FixPatchResponse:
    """查询漏洞已有补丁；不存在时返回 404，不会自动生成。"""
    patch = await get_patch_for_finding(db, finding_id)
    if patch is None:
        from app.core.errors import AppError

        raise AppError(
            status_code=404,
            code="patch_not_found",
            message="该漏洞尚未生成修复补丁",
        )
    return FixPatchResponse.model_validate(patch)


# ──────────────────────────────────────────────────────
# 生成补丁
# ──────────────────────────────────────────────────────


@router.post(
    "/findings/{finding_id}/patches",
    response_model=FixPatchResponse,
    status_code=201,
)
async def create_patch(
    finding_id: str,
    body: FixPatchCreateRequest | None = None,
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis),
    operator: str = Depends(get_current_user),
) -> FixPatchResponse:
    """为指定漏洞生成修复补丁。

    异步生成：调用后立即返回 patch_id，生成完成后通过 WS
    ``patch_ready`` 事件通知前端。
    """
    finding = await get_finding(db, finding_id)
    if finding is None:
        raise FindingNotFoundError(finding_id)

    force_regenerate = body.force_regenerate if body else False
    patch_id = await generate_patch_for_finding(
        db,
        redis,
        finding_id,
        force_regenerate=force_regenerate,
    )
    patch = await get_patch_detail(db, patch_id)
    return FixPatchResponse.model_validate(patch)


# ──────────────────────────────────────────────────────
# 补丁详情
# ──────────────────────────────────────────────────────


@router.get(
    "/patches/{patch_id}",
    response_model=FixPatchResponse,
)
async def get_patch(
    patch_id: str,
    db: AsyncSession = Depends(get_db),
    operator: str = Depends(get_current_user),
) -> FixPatchResponse:
    """获取补丁详情。"""
    patch = await get_patch_detail(db, patch_id)
    return FixPatchResponse.model_validate(patch)


# ──────────────────────────────────────────────────────
# Diff 纯文本
# ──────────────────────────────────────────────────────


@router.get(
    "/patches/{patch_id}/diff",
    response_model=FixPatchDiffResponse,
)
async def get_patch_diff(
    patch_id: str,
    db: AsyncSession = Depends(get_db),
    operator: str = Depends(get_current_user),
) -> FixPatchDiffResponse:
    """获取补丁的 unified diff 纯文本。"""
    patch = await get_patch_detail(db, patch_id)
    diff_text = await get_patch_diff_text(db, patch_id)
    return FixPatchDiffResponse(
        patch_id=patch_id,
        finding_id=patch.finding_id,
        diff=diff_text,
        adopt_status=patch.adopt_status,
    )


# ──────────────────────────────────────────────────────
# 校验
# ──────────────────────────────────────────────────────


@router.post(
    "/patches/{patch_id}/validate",
    response_model=FixPatchValidateResponse,
)
async def validate_patch(
    patch_id: str,
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis),
    operator: str = Depends(get_current_user),
) -> FixPatchValidateResponse:
    """触发补丁校验（语法 / 编译 / 安全回归）。"""
    result = await validate_patch_by_id(db, redis, patch_id)
    return FixPatchValidateResponse(**result)


# ──────────────────────────────────────────────────────
# 采纳 / 拒绝
# ──────────────────────────────────────────────────────


@router.post(
    "/patches/{patch_id}/adopt",
    response_model=FixPatchResponse,
)
async def adopt(
    patch_id: str,
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis),
    operator: str = Depends(get_current_user),
) -> FixPatchResponse:
    """采纳补丁。"""
    patch = await adopt_patch(db, redis, patch_id)
    return FixPatchResponse.model_validate(patch)


@router.post(
    "/patches/{patch_id}/reject",
    response_model=FixPatchResponse,
)
async def reject(
    patch_id: str,
    body: FixPatchAdoptRequest | None = None,
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis),
    operator: str = Depends(get_current_user),
) -> FixPatchResponse:
    """拒绝补丁。"""
    reason = body.reason if body else None
    patch = await reject_patch(db, redis, patch_id, reason)
    return FixPatchResponse.model_validate(patch)


# ──────────────────────────────────────────────────────
# 任务下补丁列表
# ──────────────────────────────────────────────────────


@router.get(
    "/tasks/{task_id}/patches",
    response_model=FixPatchListResponse,
)
async def list_task_patches(
    task_id: str,
    db: AsyncSession = Depends(get_db),
    operator: str = Depends(get_current_user),
) -> FixPatchListResponse:
    """获取任务下所有补丁。"""
    items = await get_patches_by_task(db, task_id)
    return FixPatchListResponse(
        items=[FixPatchResponse.model_validate(p) for p in items],
        total=len(items),
    )


# ──────────────────────────────────────────────────────
# 导出 ZIP
# ──────────────────────────────────────────────────────


@router.get("/patches/{patch_id}/export")
async def export_patch(
    patch_id: str,
    db: AsyncSession = Depends(get_db),
    operator: str = Depends(get_current_user),
) -> Response:
    """导出补丁为 ZIP 文件。

    ZIP 内含：original_code、patched_code、diff.patch、README.md
    """
    zip_bytes = await export_patch_zip(db, patch_id)
    return Response(
        content=zip_bytes,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="patch_{patch_id}.zip"',
        },
    )
