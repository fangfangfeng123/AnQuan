"""WebSocket 实时推送层包。

本包负责任务执行过程中的实时事件推送：
- manager.py：WebSocket 连接管理器（taskId → 连接集合映射）
- publisher.py：事件发布器（从 worker/agent 发布事件到前端）
"""

from app.websockets.manager import manager
from app.websockets.publisher import EventPublisher

__all__ = ["manager", "EventPublisher"]
