"""SQLAlchemy 异步引擎和会话工厂。

本模块负责：
- 创建 create_async_engine 实例（PostgreSQL + asyncpg 驱动）
- 创建 async_sessionmaker 会话工厂
- 提供 get_db() 异步上下文管理器，作为 FastAPI 依赖注入使用
- 定义 Base 声明性基类，所有 ORM 模型继承它
- 提供 init_db() 初始化函数（创建所有表，开发环境用）
"""

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from app.core.config import get_settings


class Base(DeclarativeBase):
    """所有 ORM 模型的声明性基类。"""

    pass


settings = get_settings()

# ── 异步引擎 ──
engine = create_async_engine(
    settings.DATABASE_URL,
    pool_size=settings.DB_POOL_SIZE,
    max_overflow=settings.DB_MAX_OVERFLOW,
    pool_recycle=settings.DB_POOL_RECYCLE,
    pool_pre_ping=True,
    echo=settings.DEBUG,
)

# ── 会话工厂 ──
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI 依赖注入：提供数据库会话。

    用法::

        @router.get("/items")
        async def list_items(db: AsyncSession = Depends(get_db)):
            ...
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db() -> None:
    """开发环境用：创建所有表（生产环境走 Alembic 迁移）。"""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def dispose_db() -> None:
    """关闭数据库连接池（应用停止时调用）。"""
    await engine.dispose()
