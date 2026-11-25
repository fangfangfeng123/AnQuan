"""内置靶场响应模型。"""

from datetime import datetime

from pydantic import BaseModel


class TargetItemResponse(BaseModel):
    """单个内置靶场条目。"""

    name: str
    kind: str  # directory / file / archive
    path: str
    file_count: int = 0
    total_size_kb: int = 0
    updated_at: datetime | None = None


class TargetListResponse(BaseModel):
    """内置靶场目录列表。"""

    root_path: str
    items: list[TargetItemResponse] = []
