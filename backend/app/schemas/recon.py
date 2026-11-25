"""环境侦察相关响应模型。

本模块定义环境侦察阶段的 API 响应模型，
包括 RuntimeProfile 详情、精简列表项和端口/入口子结构。
"""

from datetime import datetime

from pydantic import BaseModel


class PortInfo(BaseModel):
    """服务端口信息。"""

    port: int
    protocol: str = "http"
    description: str = ""


class EntryPoint(BaseModel):
    """入口文件信息。"""

    file: str
    type: str = "entry"
    line: int | None = None
    routes: list[dict] | None = None


class DependencyItem(BaseModel):
    """依赖项（精简视图）。"""

    name: str
    version: str | None = None


class RuntimeProfileResponse(BaseModel):
    """运行时画像详情响应。"""

    id: str
    task_id: str
    project_id: str | None = None
    language: str = "unknown"
    framework: str = "unknown"
    dependencies: dict | list | None = None
    run_command: str | None = None
    service_ports: list[PortInfo] | list[dict] | None = None
    entry_points: list[EntryPoint] | list[dict] | None = None
    db_type: str = "not_detected"
    raw_result: dict | None = None
    created_at: datetime
    updated_at: datetime | None = None

    model_config = {"from_attributes": True}


class ReconSummaryResponse(BaseModel):
    """Recon 阶段精简摘要（供工作台快速展示）。"""

    language: str = "unknown"
    framework: str = "unknown"
    dependency_count: int = 0
    entry_point_count: int = 0
    service_ports: list[int] | None = None
    db_type: str = "not_detected"
    run_command: str | None = None

    model_config = {"from_attributes": True}
