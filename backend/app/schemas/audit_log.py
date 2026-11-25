"""审计日志响应模型。

本模块定义审计日志的 API 响应模型。
"""

from datetime import datetime

from pydantic import BaseModel


class AuditLogResponse(BaseModel):
    """单条审计日志。"""

    id: int
    action: str
    task_id: str | None = None
    project_id: str | None = None
    operator: str
    target_type: str | None = None
    target_id: str | None = None
    detail: dict | None = None
    ip_address: str | None = None
    created_at: datetime

    model_config = {"from_attributes": True}
