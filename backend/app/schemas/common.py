"""通用响应包装模型。

本模块定义所有 API 接口共用的响应包装结构。
"""

from datetime import datetime
from typing import Generic, TypeVar

from pydantic import BaseModel, Field


T = TypeVar("T")


class SuccessResponse(BaseModel):
    """统一成功响应。"""

    message: str = "操作成功"


class ErrorResponse(BaseModel):
    """统一错误响应。"""

    code: str = "error"
    message: str = "操作失败"
    detail: dict | None = None


class ErrorDetail(BaseModel):
    """字段级错误详情（用于表单校验）。"""

    field: str
    message: str


class PaginatedResponse(BaseModel, Generic[T]):
    """泛型分页响应。"""

    items: list[T]
    total: int
    page: int
    size: int
    pages: int


class BatchResponse(BaseModel, Generic[T]):
    """批量操作响应。"""

    success_count: int
    failed_count: int
    errors: list[dict] = Field(default_factory=list)
