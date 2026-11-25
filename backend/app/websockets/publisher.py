"""WebSocket 事件发布器模块。

本模块封装事件发布逻辑，解耦 worker/agent 与 WebSocket 管理器。
通过 Redis pubsub 实现跨进程广播（worker → redis → websocket 服务）。
"""

import json

from redis.asyncio import Redis

from app.core.redis import RedisPubSub


class EventPublisher:
    """事件发布器。

    从 worker/agent 发布事件到前端。
    事件类型：phase_started / phase_completed / finding_discovered /
    poc_verified / attack_chain_updated / report_ready / error / log
    """

    CHANNEL_PREFIX = "ws:task:"

    @classmethod
    async def publish(
        cls,
        redis: Redis,
        task_id: str,
        event_type: str,
        payload: dict,
    ) -> None:
        """构造标准事件结构并广播。

        同时走两条路径：
        1. Redis pubsub（跨进程，worker → websocket 服务）
        2. 直接连管理器（同进程时直接推送）
        """
        message = {
            "task_id": task_id,
            "event": event_type,
            "payload": payload,
        }

        # Redis pubsub
        await RedisPubSub.publish(redis, task_id, message)

        # WebSocket 服务端订阅 Redis 频道后统一推送，
        # 避免同进程直接推送和 Redis 订阅重复发送。
