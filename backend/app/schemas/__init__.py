"""Pydantic 请求/响应模型层包。

本包定义所有 API 接口的请求和响应模型，与 ORM 模型严格分离。
"""

from app.schemas.audit_log import AuditLogResponse
from app.schemas.common import (
    BatchResponse,
    ErrorDetail,
    ErrorResponse,
    PaginatedResponse,
    SuccessResponse,
)
from app.schemas.project import (
    ProjectCreateRequest,
    ProjectListItem,
    ProjectResponse,
    ProjectUpdateRequest,
)
from app.schemas.source_snapshot import (
    GitCloneRequest,
    SourceSnapshotListItem,
    SourceSnapshotResponse,
)
from app.schemas.task import (
    TaskCreateRequest,
    TaskListItem,
    TaskLogResponse,
    TaskResponse,
)

__all__ = [
    "AuditLogResponse",
    "BatchResponse",
    "ErrorDetail",
    "ErrorResponse",
    "PaginatedResponse",
    "SuccessResponse",
    "ProjectCreateRequest",
    "ProjectListItem",
    "ProjectResponse",
    "ProjectUpdateRequest",
    "GitCloneRequest",
    "SourceSnapshotListItem",
    "SourceSnapshotResponse",
    "TaskCreateRequest",
    "TaskListItem",
    "TaskLogResponse",
    "TaskResponse",
]
