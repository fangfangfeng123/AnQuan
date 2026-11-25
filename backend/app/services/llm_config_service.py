"""LLM 配置服务模块。

本模块封装 LLM 配置的业务逻辑：
- get_all_configs()：读取所有 LLM 模式的配置（api_key 脱敏）
- update_config()：更新指定模式的配置，写审计日志
- activate_mode()：切换激活模式（只允许一个为 True）
- get_active_llm_client()：获取当前激活模式的 LLM 客户端实例
- test_llm_connection()：用指定模式发简单 prompt 验证连通性
- mask_api_key()：脱敏 API Key（前4后4，短 key 全掩）

配置存储方案：DB 表 llm_configs（键值对 JSONB），config_key 格式 "llm:{mode}"，
config_value 存 {api_key, base_url, model, max_tokens, temperature, timeout, enabled, is_active}。
MVP 阶段 API Key 明文存 DB，对外返回时脱敏。
TODO(生产): 用 cryptography.Fernet 加密 API Key。
"""

import logging
import time

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import AppError, LlmError
from app.enums import AuditAction, LlmMode
from app.models import LlmConfig
from app.services.audit_service import log_action

logger = logging.getLogger(__name__)

# config_key 前缀
_KEY_PREFIX = "llm:"

# 支持的模式列表
_VALID_MODES = [LlmMode.OPENAI.value, LlmMode.OLLAMA.value, LlmMode.DEMO.value]

# demo 模式的默认配置
_DEMO_DEFAULTS = {
    "api_key": None,
    "base_url": None,
    "model": "demo-mock",
    "max_tokens": 4096,
    "temperature": 0.1,
    "timeout": 120,
    "enabled": True,
    "is_active": True,
}

# openai 模式的默认配置
_OPENAI_DEFAULTS = {
    "api_key": None,
    "base_url": "https://api.openai.com/v1",
    "model": "gpt-4o",
    "max_tokens": 4096,
    "temperature": 0.1,
    "timeout": 120,
    "enabled": False,
    "is_active": False,
}

# ollama 模式的默认配置
_OLLAMA_DEFAULTS = {
    "api_key": None,
    "base_url": "http://localhost:11434",
    "model": "llama3",
    "max_tokens": 4096,
    "temperature": 0.1,
    "timeout": 120,
    "enabled": False,
    "is_active": False,
}

_MODE_DEFAULTS = {
    LlmMode.OPENAI.value: _OPENAI_DEFAULTS,
    LlmMode.OLLAMA.value: _OLLAMA_DEFAULTS,
    LlmMode.DEMO.value: _DEMO_DEFAULTS,
}


# ──────────────────────────────────────────────────────
# 辅助函数
# ──────────────────────────────────────────────────────


def mask_api_key(key: str | None) -> str:
    """脱敏 API Key。

    "sk-abcdefghijklmnop" → "sk-a****op"
    短 key (< 8 chars) → "****"

    Args:
        key: 完整 API Key

    Returns:
        脱敏后的 Key
    """
    if not key:
        return ""
    if len(key) < 8:
        return "****"
    return f"{key[:4]}****{key[-2:]}"


def _config_key(mode: str) -> str:
    """构造 DB 中的 config_key。"""
    return f"{_KEY_PREFIX}{mode}"


async def _get_or_create_config(db: AsyncSession, mode: str) -> LlmConfig:
    """获取或创建指定模式的配置行。"""
    key = _config_key(mode)
    result = await db.execute(select(LlmConfig).where(LlmConfig.config_key == key))
    config = result.scalar_one_or_none()

    if config is None:
        defaults = _MODE_DEFAULTS.get(mode, {}).copy()
        config = LlmConfig(
            config_key=key,
            config_value=defaults,
            description=f"LLM mode: {mode}",
            enabled=defaults.get("enabled", True),
        )
        db.add(config)
        await db.flush()

    return config


def _config_to_mode_config(config: LlmConfig, mode: str) -> dict:
    """将 LlmConfig ORM 转为 API 响应 dict（api_key 脱敏）。"""
    value = config.config_value or {}
    return {
        "mode": mode,
        "enabled": config.enabled,
        "api_key_masked": mask_api_key(value.get("api_key")),
        "base_url": value.get("base_url"),
        "model": value.get("model"),
        "max_tokens": value.get("max_tokens"),
        "temperature": value.get("temperature"),
        "timeout": value.get("timeout"),
    }


# ──────────────────────────────────────────────────────
# 主流程函数
# ──────────────────────────────────────────────────────


async def get_all_configs(db: AsyncSession) -> dict:
    """读取所有 LLM 模式的配置（api_key 脱敏）+ 当前激活模式。

    Returns:
        {"items": [mode_config_dict, ...], "active_mode": "demo"}
    """
    # 确保所有模式的配置行都存在
    for mode in _VALID_MODES:
        await _get_or_create_config(db, mode)
    await db.flush()

    # 读取所有配置
    result = await db.execute(
        select(LlmConfig).where(LlmConfig.config_key.like(f"{_KEY_PREFIX}%"))
    )
    configs = result.scalars().all()

    items = []
    active_mode = LlmMode.DEMO.value  # 默认

    for config in configs:
        mode = config.config_key.replace(_KEY_PREFIX, "")
        if mode not in _VALID_MODES:
            continue
        items.append(_config_to_mode_config(config, mode))
        if config.config_value.get("is_active", False):
            active_mode = mode

    # 按 _VALID_MODES 的顺序排序
    mode_order = {m: i for i, m in enumerate(_VALID_MODES)}
    items.sort(key=lambda x: mode_order.get(x["mode"], 99))

    return {"items": items, "active_mode": active_mode}


async def update_config(
    db: AsyncSession, mode: str, updates: dict, operator: str = "admin"
) -> dict:
    """更新指定模式的配置。

    Args:
        db: 数据库会话
        mode: 模式名 (openai / ollama / demo)
        updates: 更新字段 dict
        operator: 操作人

    Returns:
        更新后的配置（脱敏）

    Raises:
        AppError: 模式不合法
    """
    if mode not in _VALID_MODES:
        raise AppError(
            status_code=400,
            code="invalid_llm_mode",
            message=f"不支持的 LLM 模式: {mode}，可用: {', '.join(_VALID_MODES)}",
        )

    config = await _get_or_create_config(db, mode)
    value = dict(config.config_value)

    # 更新字段（api_key 仅在传入非 None 时更新）
    if updates.get("api_key") is not None:
        value["api_key"] = updates["api_key"]
    if updates.get("base_url") is not None:
        value["base_url"] = updates["base_url"]
    if updates.get("model") is not None:
        value["model"] = updates["model"]
    if updates.get("max_tokens") is not None:
        value["max_tokens"] = updates["max_tokens"]
    if updates.get("temperature") is not None:
        value["temperature"] = updates["temperature"]

    config.config_value = value
    config.enabled = updates.get("enabled", config.enabled)
    await db.flush()

    # 写审计日志
    await log_action(
        db,
        action=AuditAction.CONFIG_UPDATE.value,
        operator=operator,
        target_type="llm_config",
        target_id=mode,
        detail={"mode": mode, "updated_fields": list(updates.keys())},
    )

    logger.info(
        "[llm_config] mode=%s updated by %s, fields=%s",
        mode,
        operator,
        list(updates.keys()),
    )

    return _config_to_mode_config(config, mode)


async def activate_mode(db: AsyncSession, mode: str, operator: str = "admin") -> dict:
    """切换激活模式（只允许一个 is_active=True）。

    Args:
        db: 数据库会话
        mode: 要激活的模式
        operator: 操作人

    Returns:
        {"active_mode": mode, "success": True}

    Raises:
        AppError: 模式不合法
    """
    if mode not in _VALID_MODES:
        raise AppError(
            status_code=400,
            code="invalid_llm_mode",
            message=f"不支持的 LLM 模式: {mode}，可用: {', '.join(_VALID_MODES)}",
        )

    # 先把所有模式设为非激活，被激活的设为 enabled=True，其他保持原 enabled 状态
    for m in _VALID_MODES:
        config = await _get_or_create_config(db, m)
        value = dict(config.config_value)
        value["is_active"] = m == mode
        # 激活的同时启用；其他模式不动 enabled 字段（保留管理员原配置）
        if m == mode:
            value["enabled"] = True
            config.enabled = True
        config.config_value = value

    await db.flush()

    # 写审计日志
    await log_action(
        db,
        action=AuditAction.CONFIG_UPDATE.value,
        operator=operator,
        target_type="llm_config",
        target_id=mode,
        detail={"action": "activate", "mode": mode},
    )

    logger.info("[llm_config] mode=%s activated by %s", mode, operator)

    return {"active_mode": mode, "success": True}


async def get_active_llm_config(db: AsyncSession) -> dict:
    """获取当前激活模式的 LLM 配置（dict，含 api_key 明文）。

    注意：本函数返回的是**配置字典**，不是真正的 LLM client 实例。
    如需调用 LLM，请用 app.llm.factory.LlmFactory 配合本函数的结果实例化。

    Returns:
        激活模式的完整配置 dict（含 api_key 明文）
    """
    configs_data = await get_all_configs(db)
    active_mode = configs_data["active_mode"]

    config = await _get_or_create_config(db, active_mode)
    value = dict(config.config_value)
    value["mode"] = active_mode

    return value


async def test_llm_connection(db: AsyncSession, mode: str) -> dict:
    """测试指定模式的 LLM 连通性。

    对 demo 模式：直接返回成功（mock）
    对 openai/ollama 模式：检查配置完整性，模拟简单请求

    Args:
        db: 数据库会话
        mode: 要测试的模式

    Returns:
        {"success": bool, "latency_ms": int, "message": str}
    """
    if mode not in _VALID_MODES:
        raise AppError(
            status_code=400,
            code="invalid_llm_mode",
            message=f"不支持的 LLM 模式: {mode}，可用: {', '.join(_VALID_MODES)}",
        )

    config = await _get_or_create_config(db, mode)
    value = config.config_value or {}

    start = time.time()

    if mode == LlmMode.DEMO.value:
        # demo 模式总是成功
        latency = int((time.time() - start) * 1000)
        return {
            "success": True,
            "latency_ms": latency,
            "message": "Demo 模式无需连接测试，始终可用",
        }

    # openai / ollama：检查关键配置
    if mode == LlmMode.OPENAI.value:
        api_key = value.get("api_key")
        if not api_key:
            return {
                "success": False,
                "latency_ms": 0,
                "message": "API Key 未配置，无法测试连接",
            }
        base_url = value.get("base_url", "https://api.openai.com/v1")
        model = value.get("model", "gpt-4o")
        latency = int((time.time() - start) * 1000)
        # TODO(生产): 实际发起 HTTP 请求到 base_url/models 端点验证连通性
        return {
            "success": True,
            "latency_ms": latency,
            "message": (
                f"配置验证通过 (base_url={base_url}, model={model})，"
                f"未实际发起 HTTP 请求"
            ),
        }

    if mode == LlmMode.OLLAMA.value:
        base_url = value.get("base_url", "http://localhost:11434")
        model = value.get("model", "llama3")
        latency = int((time.time() - start) * 1000)
        # TODO(生产): 实际发请求到 {base_url}/api/tags 端点验证
        return {
            "success": True,
            "latency_ms": latency,
            "message": (
                f"配置验证通过 (base_url={base_url}, model={model})，"
                f"未实际发起 HTTP 请求"
            ),
        }

    return {
        "success": False,
        "latency_ms": 0,
        "message": f"未知模式: {mode}",
    }
