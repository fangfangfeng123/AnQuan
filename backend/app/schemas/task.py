"""任务相关请求/响应模型。

本模块定义评估任务的 API 请求和响应模型。
"""

from datetime import datetime

from pydantic import BaseModel, Field


class TaskCreateRequest(BaseModel):
    """创建任务请求。"""

    sandbox_image: str | None = Field(None, description="沙箱镜像名")
    source_snapshot_id: str | None = Field(
        None, description="本次评估使用的源码快照 ID"
    )
    network_mode: str = Field("restricted", description="网络模式")
    timeout_secs: int = Field(1800, ge=60, le=7200, description="超时秒数")
    llm_mode: str = Field("demo", description="LLM 模式")
    max_concurrent: int = Field(3, ge=1, le=10, description="最大并发")


class TaskResponse(BaseModel):
    """任务详情响应。"""

    id: str
    project_id: str
    source_snapshot_id: str | None = None
    status: str
    current_phase: str | None
    phase_status: dict
    overall_progress: float
    overall_risk: str | None = None
    sandbox_id: str | None = None
    llm_mode: str
    error_message: str | None = None
    started_at: datetime | None = None
    ended_at: datetime | None = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class TaskListItem(BaseModel):
    """任务列表项。"""

    id: str
    project_id: str
    source_snapshot_id: str | None = None
    status: str
    current_phase: str | None
    overall_progress: float
    overall_risk: str | None = None
    created_at: datetime

    model_config = {"from_attributes": True}


class TaskLogResponse(BaseModel):
    """任务日志响应。"""

    id: int
    task_id: str
    phase: str
    agent: str
    level: str
    message: str
    detail: dict | None = None
    created_at: datetime

    model_config = {"from_attributes": True}


class PhaseStatusResponse(BaseModel):
    """阶段状态详情。"""

    phase: str
    status: str
    progress: float
