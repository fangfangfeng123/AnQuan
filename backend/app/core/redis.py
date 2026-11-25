"""Redis 异步连接池模块。

本模块负责：
- 创建 redis.asyncio 连接池
- 提供 get_redis() 依赖注入函数
- 提供 RedisPubSub 封装类（订阅/发布消息）
- 用于：任务队列（brpop 消费）、WebSocket 事件发布/订阅、缓存
"""

from collections.abc import AsyncGenerator

import redis.asyncio as aioredis
from redis.asyncio import Redis

from app.core.config import get_settings

settings = get_settings()

# ── Redis 连接池 ──
redis_pool = aioredis.ConnectionPool.from_url(
    settings.REDIS_URL,
    max_connections=settings.REDIS_MAX_CONNECTIONS,
    encoding="utf-8",
    decode_responses=True,
)


async def get_redis() -> AsyncGenerator[Redis, None]:
    """FastAPI 依赖注入：提供 Redis 连接。"""
    r = Redis(connection_pool=redis_pool)
    try:
        yield r
    finally:
        await r.aclose()


def get_redis_sync() -> Redis:
    """非依赖注入场景获取 Redis 连接（如 worker）。"""
    return Redis(connection_pool=redis_pool)


class RedisPubSub:
    """Redis 发布/订阅封装，用于 worker → WebSocket 跨进程事件推送。"""

    CHANNEL_PREFIX = "ws:task:"

    @classmethod
    async def publish(cls, redis: Redis, task_id: str, message: dict) -> None:
        """向指定 task 的事件频道发布消息。"""
        channel = f"{cls.CHANNEL_PREFIX}{task_id}"
        import json

        await redis.publish(
            channel, json.dumps(message, ensure_ascii=False, default=str)
        )

    @classmethod
    async def subscribe(cls, redis: Redis, task_id: str):
        """订阅指定 task 的事件频道。返回 pubsub 对象。"""
        pubsub = redis.pubsub()
        channel = f"{cls.CHANNEL_PREFIX}{task_id}"
        await pubsub.subscribe(channel)
        return pubsub
