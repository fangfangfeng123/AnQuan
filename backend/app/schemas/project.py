"""项目相关请求/响应模型。

本模块定义项目管理的 API 请求和响应模型。
"""

from datetime import datetime

from pydantic import BaseModel, Field


class ProjectCreateRequest(BaseModel):
    """创建项目请求。"""

    project_name: str = Field(..., min_length=1, max_length=256, description="项目名称")
    source_type: str = Field(
        "git",
        description="源码类型: git / archive / directory / file / local_path",
    )
    source_input: str = Field(..., description="源码来源: Git URL / 目录路径")
    source_ref: str | None = Field(None, description="分支/tag/commit")


class ProjectUpdateRequest(BaseModel):
    """更新项目请求。"""

    project_name: str | None = Field(None, min_length=1, max_length=256)
    tech_stack: dict | None = None
    status: str | None = None


class ProjectResponse(BaseModel):
    """项目详情响应。"""

    id: str
    project_name: str
    source_type: str
    source_input: str
    source_ref: str | None = None
    commit_id: str | None = None
    tech_stack: dict | None = None
    status: str
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class ProjectListItem(BaseModel):
    """项目列表项（精简字段）。"""

    id: str
    project_name: str
    source_type: str
    status: str
    created_at: datetime

    model_config = {"from_attributes": True}
