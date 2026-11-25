"""LLM 配置路由模块。

本模块定义 LLM 配置管理的 HTTP 接口：
- GET  /llm/config：获取所有 LLM 模式的配置（api_key 脱敏）
- PUT  /llm/config：更新指定模式的配置（需 admin 角色）
- POST /llm/config/activate：切换激活模式（需 admin 角色）
- POST /llm/test：测试 LLM 连通性
- GET  /llm/modes：获取可用模式列表
"""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import get_current_user, require_role
from app.schemas.llm_config import (
    LlmActivateRequest,
    LlmActivateResponse,
    LlmConfigListResponse,
    LlmConfigUpdateRequest,
    LlmModeConfig,
    LlmModeListResponse,
    LlmTestRequest,
    LlmTestResponse,
)
from app.services import llm_config_service

router = APIRouter(prefix="/llm", tags=["LLM 配置"])


@router.get("/config", response_model=LlmConfigListResponse)
async def get_config(
    db: AsyncSession = Depends(get_db),
    operator: str = Depends(get_current_user),
) -> LlmConfigListResponse:
    """获取所有 LLM 模式的配置（api_key 脱敏）。"""
    data = await llm_config_service.get_all_configs(db)
    items = [LlmModeConfig(**item) for item in data["items"]]
    return LlmConfigListResponse(
        items=items,
        active_mode=data["active_mode"],
    )


@router.put(
    "/config",
    response_model=LlmModeConfig,
    dependencies=[Depends(require_role("admin"))],
)
async def update_config(
    request: LlmConfigUpdateRequest,
    db: AsyncSession = Depends(get_db),
    operator: str = Depends(get_current_user),
) -> LlmModeConfig:
    """更新指定模式的 LLM 配置（需 admin 角色）。

    MVP 阶段静态 token 默认 admin 角色；
    用 "developer:dev-api-token-change-in-production" 格式可指定其他角色。
    """
    data = await llm_config_service.update_config(
        db, request.mode, request.model_dump(exclude_none=True), operator
    )
    return LlmModeConfig(**data)


@router.post(
    "/config/activate",
    response_model=LlmActivateResponse,
    dependencies=[Depends(require_role("admin"))],
)
async def activate_mode(
    request: LlmActivateRequest,
    db: AsyncSession = Depends(get_db),
    operator: str = Depends(get_current_user),
) -> LlmActivateResponse:
    """切换激活 LLM 模式（需 admin 角色）。

    同时只允许一个模式为激活状态。
    """
    result = await llm_config_service.activate_mode(db, request.mode, operator)
    return LlmActivateResponse(**result)


@router.post("/test", response_model=LlmTestResponse)
async def test_llm(
    request: LlmTestRequest,
    db: AsyncSession = Depends(get_db),
    operator: str = Depends(get_current_user),
) -> LlmTestResponse:
    """测试指定模式的 LLM 连通性。"""
    data = await llm_config_service.test_llm_connection(db, request.mode)
    return LlmTestResponse(**data)


@router.get("/modes", response_model=LlmModeListResponse)
async def get_modes(
    operator: str = Depends(get_current_user),
) -> LlmModeListResponse:
    """获取可用 LLM 模式列表。"""
    from app.enums import LlmMode

    modes = [LlmMode.OPENAI.value, LlmMode.OLLAMA.value, LlmMode.DEMO.value]
    return LlmModeListResponse(modes=modes)
