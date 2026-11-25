"""Redis 队列消费者模块。

本模块是任务执行的入口点，在应用启动时由 lifespan 启动：
- while True 循环阻塞消费 Redis task_queue 队列（brpop）
- 每收到一个 task_id，创建 asyncio 任务交给 task_executor 执行
- 支持并发控制（信号量限制同时运行的任务数）
- 异常捕获和重试逻辑
- 通过 Redis pubsub 向 WebSocket 推送执行进度
"""

import asyncio
import json
import logging

from redis.asyncio import Redis

from app.core.config import get_settings
from app.core.redis import get_redis_sync
from app.workers.task_executor import run as run_task

logger = logging.getLogger(__name__)
settings = get_settings()

# Redis 任务队列名
TASK_QUEUE = "task:queue"

# 并发控制信号量
_semaphore: asyncio.Semaphore | None = None

# worker 运行标志
_running = False


def _get_semaphore() -> asyncio.Semaphore:
    """获取并发控制信号量（惰性初始化）。"""
    global _semaphore
    if _semaphore is None:
        _semaphore = asyncio.Semaphore(settings.SANDBOX_CPU_LIMIT or 3)
    return _semaphore


async def _process_task(task_id: str, redis: Redis) -> None:
    """处理单个任务（带并发控制）。"""
    async with _get_semaphore():
        logger.info(f"开始处理任务: {task_id}")
        try:
            await run_task(task_id, redis)
        except Exception as e:
            logger.exception(f"任务 {task_id} 处理异常: {e}")


async def start_worker() -> None:
    """启动 Redis 队列消费者。

    在 FastAPI lifespan 中调用：
    ```
    asyncio.create_task(start_worker())
    ```
    """
    global _running
    _running = True
    logger.info("任务 Worker 已启动，等待任务队列...")

    redis = get_redis_sync()
    if redis is None:
        logger.error("无法获取 Redis 连接，Worker 启动失败")
        return

    try:
        while _running:
            try:
                # brpop 阻塞等待任务（超时 5 秒，便于检查 _running 标志）
                result = await redis.brpop(TASK_QUEUE, timeout=5)
                if result is None:
                    continue

                # result = (queue_name, payload)
                _, payload = result
                if isinstance(payload, bytes):
                    payload = payload.decode("utf-8")

                task_data = json.loads(payload)
                task_id = task_data.get("task_id")
                if not task_id:
                    logger.warning(f"无效的任务消息: {payload}")
                    continue

                # 异步执行任务（不阻塞消费循环）
                asyncio.create_task(_process_task(task_id, redis))

            except asyncio.CancelledError:
                logger.info("Worker 被取消，正在退出...")
                break
            except Exception as e:
                logger.exception(f"Worker 消费循环异常: {e}")
                await asyncio.sleep(1)

    finally:
        _running = False
        await redis.aclose()
        logger.info("任务 Worker 已停止")


async def stop_worker() -> None:
    """停止 Worker（优雅退出）。"""
    global _running
    _running = False
    logger.info("正在停止任务 Worker...")
