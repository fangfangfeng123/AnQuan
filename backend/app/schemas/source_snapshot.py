"""源码快照相关响应模型。

本模块定义源码快照的 API 响应模型。
"""

from datetime import datetime

from pydantic import BaseModel


class SourceSnapshotResponse(BaseModel):
    """源码快照详情响应。"""

    id: str
    project_id: str
    commit_id: str | None = None
    file_count: int | None = None
    total_size_kb: int | None = None
    line_count: int | None = None
    checksum: str | None = None
    language_stats: dict | None = None
    created_at: datetime

    model_config = {"from_attributes": True}


class SourceSnapshotListItem(BaseModel):
    """源码快照列表项（精简字段）。"""

    id: str
    project_id: str
    commit_id: str | None = None
    file_count: int | None = None
    line_count: int | None = None
    created_at: datetime

    model_config = {"from_attributes": True}


class GitCloneRequest(BaseModel):
    """Git 克隆请求。"""

    git_url: str
    ref: str | None = None


class LocalPathRequest(BaseModel):
    """本地文件/文件夹导入请求。"""

    local_path: str
