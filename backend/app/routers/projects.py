"""项目管理路由模块。

本模块定义项目管理的 HTTP 接口。
"""

import os

from fastapi import APIRouter, Depends, File, Query, Request, UploadFile
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.database import get_db
from app.core.errors import ProjectNotFoundError, ValidationError
from app.core.security import get_current_user
from app.schemas.common import PaginatedResponse, SuccessResponse
from app.schemas.project import (
    ProjectCreateRequest,
    ProjectListItem,
    ProjectResponse,
    ProjectUpdateRequest,
)
from app.schemas.source_snapshot import (
    GitCloneRequest,
    LocalPathRequest,
    SourceSnapshotListItem,
    SourceSnapshotResponse,
)
from app.schemas.task import TaskCreateRequest, TaskResponse
from app.services.project_service import (
    archive_project,
    create_project,
    get_project,
    list_projects,
    purge_project,
    restore_project,
    update_project,
)
from app.services.source_snapshot_service import (
    create_snapshot_from_archive,
    create_snapshot_from_git,
    create_snapshot_from_local_path,
    delete_snapshot,
    list_snapshots,
)
from app.services.task_service import create_task
from app.utils import ensure_dir, generate_id

router = APIRouter(prefix="/projects", tags=["项目管理"])
settings = get_settings()


@router.post("", response_model=ProjectResponse, status_code=201)
async def create_project_endpoint(
    body: ProjectCreateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    operator: str = Depends(get_current_user),
) -> ProjectResponse:
    """创建项目（Git URL 或目录路径）。"""
    project = await create_project(
        db=db,
        project_name=body.project_name,
        source_type=body.source_type,
        source_input=body.source_input,
        source_ref=body.source_ref,
        operator=operator,
    )
    return ProjectResponse.model_validate(project)


@router.get("", response_model=PaginatedResponse[ProjectListItem])
async def list_projects_endpoint(
    status: str | None = Query(None, description="按状态过滤"),
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    operator: str = Depends(get_current_user),
) -> dict:
    """获取项目列表（分页、过滤）。"""
    result = await list_projects(db=db, status=status, page=page, size=size)
    return {
        "items": [ProjectListItem.model_validate(p) for p in result["items"]],
        "total": result["total"],
        "page": result["page"],
        "size": result["size"],
        "pages": result["pages"],
    }


@router.get("/{project_id}", response_model=ProjectResponse)
async def get_project_endpoint(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    operator: str = Depends(get_current_user),
) -> ProjectResponse:
    """获取项目详情。"""
    project = await get_project(db, project_id)
    if project is None:
        raise ProjectNotFoundError(project_id)
    return ProjectResponse.model_validate(project)


@router.put("/{project_id}", response_model=ProjectResponse)
async def update_project_endpoint(
    project_id: str,
    body: ProjectUpdateRequest,
    db: AsyncSession = Depends(get_db),
    operator: str = Depends(get_current_user),
) -> ProjectResponse:
    """更新项目信息。"""
    project = await update_project(
        db, project_id, body.model_dump(exclude_unset=True), operator
    )
    if project is None:
        raise ProjectNotFoundError(project_id)
    return ProjectResponse.model_validate(project)


@router.delete("/{project_id}", response_model=SuccessResponse)
async def archive_project_endpoint(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    operator: str = Depends(get_current_user),
) -> SuccessResponse:
    """归档项目（软删除）。"""
    project = await archive_project(db, project_id, operator)
    if project is None:
        raise ProjectNotFoundError(project_id)
    return SuccessResponse(message=f"项目已归档: {project_id}")


@router.post("/{project_id}/restore", response_model=ProjectResponse)
async def restore_project_endpoint(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    operator: str = Depends(get_current_user),
) -> ProjectResponse:
    """恢复已归档项目。"""
    project = await restore_project(db, project_id, operator)
    if project is None:
        raise ProjectNotFoundError(project_id)
    return ProjectResponse.model_validate(project)


@router.delete("/{project_id}/purge", response_model=SuccessResponse)
async def purge_project_endpoint(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    operator: str = Depends(get_current_user),
) -> SuccessResponse:
    """彻底删除项目，并清理关联任务、源码快照目录与报告文件。"""
    project = await purge_project(db, project_id, operator)
    if project is None:
        raise ProjectNotFoundError(project_id)
    return SuccessResponse(message=f"项目已彻底删除: {project.project_name}")


@router.post(
    "/{project_id}/upload", response_model=SourceSnapshotResponse, status_code=201
)
async def upload_source_endpoint(
    project_id: str,
    file: UploadFile = File(..., description="ZIP 压缩包"),
    db: AsyncSession = Depends(get_db),
    operator: str = Depends(get_current_user),
) -> SourceSnapshotResponse:
    """上传 ZIP 压缩包创建源码快照。"""
    # 校验文件类型
    if not file.filename or not file.filename.lower().endswith(".zip"):
        raise ValidationError("仅支持 .zip 格式的压缩包")

    max_bytes = settings.UPLOAD_MAX_SIZE_MB * 1024 * 1024
    upload_dir = ensure_dir(settings.UPLOAD_DIR)
    temp_path = os.path.join(upload_dir, f"upload_{generate_id()}.zip")
    size = 0
    try:
        with open(temp_path, "wb") as f:
            while chunk := await file.read(1024 * 1024):
                size += len(chunk)
                if size > max_bytes:
                    raise ValidationError(
                        f"文件大小超过限制: {settings.UPLOAD_MAX_SIZE_MB}MB",
                        detail={"size_mb": size // (1024 * 1024)},
                    )
                f.write(chunk)

        try:
            snapshot = await create_snapshot_from_archive(
                db=db,
                project_id=project_id,
                zip_path=temp_path,
                operator=operator,
            )
        except ValueError as e:
            raise ValidationError(str(e)) from e
    finally:
        await file.close()
        if os.path.exists(temp_path):
            os.remove(temp_path)

    return SourceSnapshotResponse.model_validate(snapshot)


@router.post(
    "/{project_id}/clone", response_model=SourceSnapshotResponse, status_code=201
)
async def clone_source_endpoint(
    project_id: str,
    body: GitCloneRequest,
    db: AsyncSession = Depends(get_db),
    operator: str = Depends(get_current_user),
) -> SourceSnapshotResponse:
    """从 Git URL 克隆源码创建快照。"""
    try:
        snapshot = await create_snapshot_from_git(
            db=db,
            project_id=project_id,
            git_url=body.git_url,
            ref=body.ref,
            operator=operator,
        )
    except (RuntimeError, ValueError) as e:
        raise ValidationError(str(e)) from e
    return SourceSnapshotResponse.model_validate(snapshot)


@router.post(
    "/{project_id}/local-path",
    response_model=SourceSnapshotResponse,
    status_code=201,
)
async def ingest_local_path_endpoint(
    project_id: str,
    body: LocalPathRequest,
    db: AsyncSession = Depends(get_db),
    operator: str = Depends(get_current_user),
) -> SourceSnapshotResponse:
    """导入本机文件或文件夹并自动识别为源码快照。"""
    try:
        snapshot = await create_snapshot_from_local_path(
            db=db,
            project_id=project_id,
            local_path=body.local_path,
            operator=operator,
        )
    except (OSError, ValueError) as e:
        raise ValidationError(str(e)) from e
    return SourceSnapshotResponse.model_validate(snapshot)


@router.get(
    "/{project_id}/snapshots",
    response_model=PaginatedResponse[SourceSnapshotListItem],
)
async def list_snapshots_endpoint(
    project_id: str,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    operator: str = Depends(get_current_user),
) -> dict:
    """获取项目的源码快照列表。"""
    result = await list_snapshots(db=db, project_id=project_id, page=page, size=size)
    return {
        "items": [SourceSnapshotListItem.model_validate(s) for s in result["items"]],
        "total": result["total"],
        "page": result["page"],
        "size": result["size"],
        "pages": result["pages"],
    }


@router.delete(
    "/{project_id}/snapshots/{snapshot_id}",
    response_model=SuccessResponse,
)
async def delete_snapshot_endpoint(
    project_id: str,
    snapshot_id: str,
    db: AsyncSession = Depends(get_db),
    operator: str = Depends(get_current_user),
) -> SuccessResponse:
    """删除源码快照（物理删除）。"""
    await delete_snapshot(
        db, snapshot_id, project_id=project_id, operator=operator
    )
    return SuccessResponse(message=f"快照已删除: {snapshot_id}")


@router.post("/{project_id}/tasks", response_model=TaskResponse, status_code=201)
async def create_project_task_endpoint(
    project_id: str,
    body: TaskCreateRequest,
    db: AsyncSession = Depends(get_db),
    operator: str = Depends(get_current_user),
) -> TaskResponse:
    """为项目创建评估任务。"""
    task = await create_task(
        db=db,
        project_id=project_id,
        source_snapshot_id=body.source_snapshot_id,
        sandbox_image=body.sandbox_image,
        network_mode=body.network_mode,
        timeout_secs=body.timeout_secs,
        llm_mode=body.llm_mode,
        max_concurrent=body.max_concurrent,
        operator=operator,
    )
    return TaskResponse.model_validate(task)
