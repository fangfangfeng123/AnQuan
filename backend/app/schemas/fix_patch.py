"""修复补丁相关请求/响应模型。

- FixPatchResponse：补丁详情响应
- FixPatchListResponse：补丁列表
- FixPatchDiffResponse：Diff 纯文本响应
- FixPatchCreateRequest：生成补丁请求
- FixPatchValidateResponse：校验结果响应
"""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class FixPatchResponse(BaseModel):
    """修复补丁详情响应。"""

    id: str
    finding_id: str = Field(..., description="关联漏洞 ID")
    task_id: str = Field(..., description="任务 ID")

    # 代码内容
    original_code: str | None = Field(None, description="原始漏洞代码")
    patched_code: str | None = Field(None, description="修复后代码")
    diff_content: str | None = Field(None, description="统一 Diff 内容")
    description: str | None = Field(None, description="AI 生成的修改说明")

    # 采纳状态
    adopt_status: str = Field(
        "pending", description="采纳状态: pending/adopted/rejected/superseded"
    )

    # 校验结果
    validated: bool = Field(False, description="是否通过校验")
    validation_result: dict[str, Any] | None = Field(
        None, description="校验结果详情(语法/编译/安全回归)"
    )

    # LLM 记录
    llm_model: str | None = Field(None, description="生成此补丁的 LLM 模型")
    token_usage: int | None = Field(None, description="消耗的 token 数")

    # 时间戳
    created_at: datetime | None = None
    updated_at: datetime | None = None

    class Config:
        from_attributes = True


class FixPatchListResponse(BaseModel):
    """补丁列表响应。"""

    items: list[FixPatchResponse]
    total: int


class FixPatchDiffResponse(BaseModel):
    """Diff 纯文本响应。"""

    patch_id: str
    finding_id: str
    diff: str
    adopt_status: str


class FixPatchCreateRequest(BaseModel):
    """生成补丁请求（可选指定 LLM 模型）。"""

    llm_model: str | None = Field(None, description="指定 LLM 模型，不指定则用默认")
    force_regenerate: bool = Field(False, description="是否强制重新生成已有补丁")


class FixPatchValidateResponse(BaseModel):
    """校验结果响应。"""

    patch_id: str
    validated: bool
    validation_result: dict[str, Any] | None = None
    message: str = ""


class FixPatchAdoptRequest(BaseModel):
    """采纳/拒绝补丁请求。"""

    reason: str | None = Field(None, description="拒绝理由（拒绝时填写）")
