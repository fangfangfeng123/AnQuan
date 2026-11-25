"""WebSocket 连接管理器模块。

本模块管理 WebSocket 长连接，维护 task_id → WebSocket 连接集合的映射。
"""

import asyncio
import json
from collections import defaultdict

from fastapi import WebSocket


class ConnectionManager:
    """WebSocket 连接管理器。

    维护 task_id → WebSocket 连接集合的映射，支持广播。
    """

    def __init__(self) -> None:
        self._connections: dict[str, set[WebSocket]] = defaultdict(set)
        self._lock = asyncio.Lock()

    async def connect(self, task_id: str, websocket: WebSocket) -> None:
        """客户端连接时注册。"""
        await websocket.accept()
        async with self._lock:
            self._connections[task_id].add(websocket)

    async def disconnect(self, task_id: str, websocket: WebSocket) -> None:
        """断开时移除。"""
        async with self._lock:
            self._connections[task_id].discard(websocket)
            if not self._connections[task_id]:
                del self._connections[task_id]

    async def send_to_task(self, task_id: str, message: dict) -> None:
        """向指定任务的所有连接广播消息。"""
        connections = self._connections.get(task_id, set()).copy()
        text = json.dumps(message, ensure_ascii=False, default=str)
        disconnected: list[WebSocket] = []
        for ws in connections:
            try:
                await ws.send_text(text)
            except Exception:
                disconnected.append(ws)

        # 清理断开的连接
        if disconnected:
            async with self._lock:
                for ws in disconnected:
                    self._connections[task_id].discard(ws)


# ── 全局单例 ──
manager = ConnectionManager()
