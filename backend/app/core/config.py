"""全局配置管理模块。

本模块通过 pydantic-settings 从 .env 文件加载配置，提供全局 Settings 单例。
"""

from functools import lru_cache
from typing import List

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """应用全局配置，从 .env 文件自动加载。"""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ── 应用基础 ──
    APP_NAME: str = "安全评估系统"
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"
    SECRET_KEY: str = "dev-secret-key-change-in-production"
    API_TOKEN: str = "dev-api-token-change-in-production"

    # ── 数据库 ──
    DATABASE_URL: str = (
        "postgresql+asyncpg://postgres:postgres@localhost:5432/security_assessment"
    )
    DB_POOL_SIZE: int = 10
    DB_MAX_OVERFLOW: int = 20
    DB_POOL_RECYCLE: int = 3600

    # ── Redis ──
    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_MAX_CONNECTIONS: int = 50

    # ── Docker 沙箱 ──
    DOCKER_HOST: str = "unix:///var/run/docker.sock"
    SANDBOX_IMAGE_DEFAULT: str = "python:3.11-slim"
    SANDBOX_NETWORK_MODE: str = "none"
    SANDBOX_MEMORY_LIMIT: str = "512m"
    SANDBOX_CPU_LIMIT: int = 1
    SANDBOX_TIMEOUT_SECS: int = 1800
    SANDBOX_PID_LIMIT: int = 200

    # ── LLM 配置 ──
    LLM_MODE: str = "demo"
    OPENAI_API_KEY: str = ""
    OPENAI_BASE_URL: str = "https://api.openai.com/v1"
    OPENAI_MODEL: str = "gpt-4o"
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "qwen2.5:7b"
    LLM_MAX_TOKENS: int = 4096
    LLM_TIMEOUT: int = 120
    LLM_TEMPERATURE: float = 0.1

    # ── CORS ──
    CORS_ORIGINS: List[str] = Field(
        default_factory=lambda: ["http://localhost:5173", "http://localhost:3000"]
    )

    # ── 文件路径 ──
    UPLOAD_DIR: str = "./data/uploads"
    REPORT_TEMPLATE_DIR: str = "./report-templates"
    REPORT_OUTPUT_DIR: str = "./data/reports"
    SNAPSHOT_DIR: str = "./data/snapshots"

    # ── 上传限制 ──
    UPLOAD_MAX_SIZE_MB: int = 200
    GIT_CLONE_TIMEOUT_SECS: int = 300


@lru_cache
def get_settings() -> Settings:
    """返回全局 Settings 单例。"""
    return Settings()
