"""沙箱实例相关响应模型。

本模块定义沙箱容器的 API 响应模型，覆盖状态查询、资源指标、
容器日志与命令执行结果等接口。
"""

from datetime import datetime

from pydantic import BaseModel, Field


class SandboxResponse(BaseModel):
    """沙箱实例详情响应。"""

    id: str
    task_id: str
    container_id: str | None = None
    container_name: str | None = None
    image: str
    status: str
    network_mode: str
    memory_limit: str | None = None
    cpu_limit: int | None = None
    pid_limit: int | None = None
    timeout_secs: int
    mount_target: str
    tmp_dir: str
    exit_code: int | None = None
    error_message: str | None = None
    resource_usage: dict | None = None
    created_at: datetime
    ready_at: datetime | None = None
    destroyed_at: datetime | None = None

    model_config = {"from_attributes": True}


class SandboxStatusResponse(BaseModel):
    """沙箱运行状态响应（DB 状态 + Docker 实时状态）。"""

    sandbox_id: str | None = None
    container_id: str | None = None
    db_status: str = "none"
    docker_status: str = "none"
    image: str | None = None
    created_at: datetime | None = None
    ready_at: datetime | None = None
    destroyed_at: datetime | None = None


class SandboxStatsResponse(BaseModel):
    """沙箱资源使用统计响应。"""

    cpu_percent: float = 0.0
    memory_usage_mb: float = 0.0
    memory_limit_mb: float = 0.0
    memory_percent: float = 0.0
    pid_count: int = 0
    available: bool = False
    error: str | None = None
