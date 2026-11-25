"""LLM 配置请求/响应模型。

本模块定义 LLM 配置管理的 API 请求和响应模型：
- LlmModeConfig：单个 LLM 模式的配置（api_key 脱敏）
- LlmConfigListResponse：所有模式配置列表 + 当前激活模式
- LlmConfigUpdateRequest：更新配置请求
- LlmModeListResponse：可用模式列表
- LlmTestRequest：连通性测试请求
- LlmTestResponse：测试结果
"""

from pydantic import BaseModel, Field


class LlmModeConfig(BaseModel):
    """单个 LLM 模式的配置。"""

    mode: str = Field(..., description="模式名: openai / ollama / demo")
    enabled: bool = Field(True, description="是否启用")
    api_key_masked: str = Field("", description="脱敏 API Key (sk-xx****xx)")
    base_url: str | None = Field(None, description="API 基础 URL")
    model: str | None = Field(None, description="模型名称")
    max_tokens: int | None = Field(None, description="最大 token 数")
    temperature: float | None = Field(None, description="温度参数")
    timeout: int | None = Field(None, description="超时秒数")


class LlmConfigListResponse(BaseModel):
    """所有模式配置列表 + 当前激活模式。"""

    items: list[LlmModeConfig] = Field(default_factory=list, description="各模式配置")
    active_mode: str = Field("demo", description="当前激活的模式")


class LlmConfigUpdateRequest(BaseModel):
    """更新配置请求。"""

    mode: str = Field(..., description="要更新的模式: openai / ollama / demo")
    api_key: str | None = Field(None, description="完整 API Key（仅在更新时传）")
    base_url: str | None = Field(None, description="API 基础 URL")
    model: str | None = Field(None, description="模型名称")
    max_tokens: int | None = Field(None, description="最大 token 数")
    temperature: float | None = Field(None, description="温度参数")
    enabled: bool | None = Field(None, description="是否启用")


class LlmModeListResponse(BaseModel):
    """可用模式列表。"""

    modes: list[str] = Field(default_factory=list, description="模式名列表")


class LlmTestRequest(BaseModel):
    """连通性测试请求。"""

    mode: str = Field(..., description="要测试的模式")


class LlmTestResponse(BaseModel):
    """连通性测试结果。"""

    success: bool = Field(False, description="是否成功")
    latency_ms: int = Field(0, description="响应延迟（毫秒）")
    message: str = Field("", description="结果消息")


class LlmActivateRequest(BaseModel):
    """切换激活模式请求。"""

    mode: str = Field(..., description="要激活的模式: openai / ollama / demo")


class LlmActivateResponse(BaseModel):
    """切换激活模式响应。"""

    active_mode: str = Field(..., description="当前激活的模式")
    success: bool = Field(True, description="是否成功")
