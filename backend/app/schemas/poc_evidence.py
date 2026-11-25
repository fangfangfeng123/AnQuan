"""PoC 证据相关请求/响应模型。

- PocEvidenceResponse：PoC 证据详情响应
- PocEvidenceListResponse：证据列表
"""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class PocEvidenceResponse(BaseModel):
    """PoC 证据详情响应。"""

    id: str
    finding_id: str = Field(..., description="关联漏洞 ID")
    task_id: str = Field(..., description="任务 ID")
    poc_type: str = Field("http", description="PoC 类型: http/command/file_read")

    # 请求信息
    request_method: str | None = Field(None, description="HTTP 方法")
    request_url: str | None = Field(None, description="请求 URL")
    request_headers: dict[str, Any] | None = Field(None, description="请求头")
    request_body: str | None = Field(None, description="请求体")

    # 响应信息
    response_status: int | None = Field(None, description="HTTP 状态码")
    response_headers: dict[str, Any] | None = Field(None, description="响应头")
    response_body: str | None = Field(None, description="响应体")

    # 验证结果
    expected_feature: str | None = Field(None, description="预期特征")
    actual_feature: str | None = Field(None, description="实际特征")
    matched: bool = Field(False, description="是否匹配成功")
    validation_status: str = Field(
        "pending", description="验证状态: passed/failed/error"
    )
    error_message: str | None = Field(None, description="异常信息")

    # 时间戳
    executed_at: datetime | None = None
    verified_at: datetime | None = None
    created_at: datetime | None = None

    class Config:
        from_attributes = True


class PocEvidenceListResponse(BaseModel):
    """证据列表响应。"""

    items: list[PocEvidenceResponse]
    total: int
