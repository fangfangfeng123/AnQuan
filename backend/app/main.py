"""FastAPI 应用入口。

本模块负责：
- 创建 FastAPI 应用实例
- 注册所有路由
- 注册 WebSocket 端点
- 注册全局异常处理器
- 配置 CORS 中间件
- lifespan 上下文管理
"""

import asyncio
import json
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone

import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi import Depends
from redis.asyncio import Redis

from app.core.config import get_settings
from app.core.database import dispose_db, init_db
from app.core.errors import AppError
from app.core.redis import get_redis, get_redis_sync
from app.routers import (
    attack_chains_router,
    audit_logs_router,
    auth_router,
    dashboard_router,
    findings_router,
    llm_router,
    patches_router,
    projects_router,
    recon_router,
    reports_router,
    sandbox_router,
    tasks_router,
    targets_router,
)
from app.websockets.manager import manager
from app.workers.worker import start_worker, stop_worker

settings = get_settings()
logger = logging.getLogger(__name__)
API_V1_PREFIX = "/api/v1"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """应用生命周期管理。

    - 启动时：初始化 DB（开发环境）、Redis 连接池
    - 停止时：释放 DB 和 Redis 连接
    """
    logger.info("启动安全评估系统后端...")

    # 开发环境自动建表
    if settings.DEBUG:
        logger.info("DEBUG 模式：初始化数据库表...")
        await init_db()

    # Redis 健康检查
    redis = get_redis_sync()
    try:
        await redis.ping()
        logger.info("Redis 连接正常")
    except Exception as e:
        logger.warning(f"Redis 连接失败: {e}")
    finally:
        await redis.aclose()

    # 启动任务 Worker
    worker_task = asyncio.create_task(start_worker())
    logger.info("任务 Worker 已启动")

    yield

    # 停止 Worker
    await stop_worker()
    worker_task.cancel()
    try:
        await worker_task
    except asyncio.CancelledError:
        pass

    # 关闭连接
    logger.info("关闭数据库连接...")
    await dispose_db()
    logger.info("安全评估系统后端已停止")


def create_app() -> FastAPI:
    """创建 FastAPI 应用实例。"""
    app = FastAPI(
        title=settings.APP_NAME,
        description="AI 驱动的自动化安全评估系统 API",
        version="0.1.0",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    # ── CORS ──
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── 路由 ──
    app.include_router(projects_router, prefix=API_V1_PREFIX)
    app.include_router(tasks_router, prefix=API_V1_PREFIX)
    app.include_router(sandbox_router, prefix=API_V1_PREFIX)
    app.include_router(recon_router, prefix=API_V1_PREFIX)
    app.include_router(audit_logs_router, prefix=API_V1_PREFIX)
    app.include_router(auth_router, prefix=API_V1_PREFIX)
    app.include_router(findings_router, prefix=API_V1_PREFIX)
    app.include_router(patches_router, prefix=API_V1_PREFIX)
    app.include_router(attack_chains_router, prefix=API_V1_PREFIX)
    app.include_router(reports_router, prefix=API_V1_PREFIX)
    app.include_router(dashboard_router, prefix=API_V1_PREFIX)
    app.include_router(llm_router, prefix=API_V1_PREFIX)
    app.include_router(targets_router, prefix=API_V1_PREFIX)

    # ── WebSocket 端点 ──
    @app.websocket(f"{API_V1_PREFIX}/ws/tasks/{{task_id}}")
    async def websocket_endpoint(
        websocket: WebSocket,
        task_id: str,
        redis: Redis = Depends(get_redis),
    ):
        """任务实时事件 WebSocket 端点。

        客户端连接后接收任务执行过程中的实时事件：
        phase_started / phase_completed / finding_discovered / etc.
        """
        await manager.connect(task_id, websocket)
        await websocket.send_text(
            json.dumps(
                {
                    "event": "connected",
                    "task_id": task_id,
                    "payload": {"status": "connected"},
                },
                ensure_ascii=False,
            )
        )

        channel = f"ws:task:{task_id}"
        pubsub = redis.pubsub()
        await pubsub.subscribe(channel)

        async def forward_redis_events() -> None:
            async for message in pubsub.listen():
                if message.get("type") != "message":
                    continue
                data = message.get("data")
                if isinstance(data, bytes):
                    data = data.decode("utf-8")
                if not data:
                    continue
                await manager.send_to_task(task_id, json.loads(data))

        redis_listener = asyncio.create_task(forward_redis_events())

        try:
            while True:
                data = await websocket.receive_text()
                if data == "ping":
                    await websocket.send_text(
                        json.dumps(
                            {
                                "event": "pong",
                                "task_id": task_id,
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                            },
                            ensure_ascii=False,
                        )
                    )
        except WebSocketDisconnect:
            pass
        finally:
            redis_listener.cancel()
            try:
                await redis_listener
            except (asyncio.CancelledError, Exception):
                pass
            await pubsub.unsubscribe(channel)
            await pubsub.aclose()
            await manager.disconnect(task_id, websocket)

    # ── 全局异常处理器 ──
    @app.exception_handler(AppError)
    async def app_error_handler(request, exc: AppError):
        from fastapi.responses import JSONResponse

        return JSONResponse(
            status_code=exc.status_code,
            content={
                "code": exc.code,
                "message": exc.message,
                "detail": exc.detail,
            },
        )

    # ── 健康检查 ──
    @app.get("/health", tags=["系统"])
    async def health_check() -> dict:
        return {"status": "ok", "app": settings.APP_NAME, "version": "0.1.0"}

    @app.get(f"{API_V1_PREFIX}/health", tags=["系统"])
    async def health_check_v1() -> dict:
        return {"status": "ok", "app": settings.APP_NAME, "version": "0.1.0"}

    return app


# ── 全局实例 ──
app = create_app()


if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8001,
        reload=settings.DEBUG,
        log_level=settings.LOG_LEVEL.lower(),
    )
