"""沙箱服务模块。

本模块封装 Docker 沙箱容器的业务逻辑，是 sandbox/manager.py（同步）与
worker / API 路由（异步）之间的桥梁：

- create_sandbox(db, redis, task_id)：创建沙箱容器 + 记录 DB + WebSocket 事件 + 关联 Task
- exec_in_sandbox(db, redis, task_id, command)：在沙箱内执行命令 + 日志落库 + WS 事件
- get_sandbox_by_task(db, task_id)：获取任务关联的沙箱实例
- get_sandbox_status(db, task_id)：获取沙箱容器运行状态
- destroy_sandbox(db, redis, task_id)：销毁沙箱容器 + 更新 DB + WS 事件
- get_sandbox_stats(db, task_id)：获取沙箱资源指标

所有 DockerManager 调用通过 run_in_executor 在线程池中执行，
避免阻塞 asyncio 事件循环。
"""

import asyncio
import logging
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.errors import SandboxError, TaskNotFoundError
from app.enums import SandboxStatus
from app.models import SandboxInstance, SourceSnapshot, Task
from app.sandbox.manager import get_docker_manager
from app.utils import append_task_log, generate_id
from app.websockets.publisher import EventPublisher

logger = logging.getLogger(__name__)
settings = get_settings()

# Docker 调用使用的线程池（独立于默认 executor）
_docker_executor = None


def _get_executor() -> ThreadPoolExecutor:
    """获取专用于 Docker 调用的线程池。"""
    global _docker_executor
    if _docker_executor is None or _docker_executor._shutdown:  # type: ignore[attr-defined]
        _docker_executor = ThreadPoolExecutor(
            max_workers=4,
            thread_name_prefix="docker-pool",
        )
    return _docker_executor


async def _run_docker(func, *args, **kwargs):
    """在线程池中执行同步 DockerManager 方法。"""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(_get_executor(), lambda: func(*args, **kwargs))


async def _publish(redis: Redis, task_id: str, event_type: str, payload: dict) -> None:
    """发布 WebSocket 事件。"""
    await EventPublisher.publish(redis, task_id, event_type, payload)


# ── 核心方法 ──


async def create_sandbox(
    db: AsyncSession,
    redis: Redis,
    task_id: str,
    image: str | None = None,
    network_mode: str | None = None,
    memory_limit: str | None = None,
    cpu_limit: int | None = None,
    pid_limit: int | None = None,
    timeout_secs: int | None = None,
) -> SandboxInstance:
    """为任务创建 Docker 沙箱容器。

    流程：
    1. 查询 Task + SourceSnapshot 获取源码快照路径
    2. 检查镜像是否存在（不存在时抛 SandboxError）
    3. 创建 SandboxInstance DB 记录（状态=creating）
    4. 调用 DockerManager.create_container + start_container
    5. 更新 SandboxInstance 状态=ready + 更新 Task.sandbox_id
    6. 发布 sandbox_created / sandbox_ready WebSocket 事件

    Args:
        db: 数据库会话
        redis: Redis 连接
        task_id: 任务 ID
        image: 镜像名（None 时用 task.sandbox_image 或 settings.SANDBOX_IMAGE_DEFAULT）
        network_mode: 网络模式（None 时用 task.network_mode 或 settings）
        memory_limit: 内存限制（None 时用 settings）
        cpu_limit: CPU 限制（None 时用 settings）
        pid_limit: PID 限制（None 时用 settings）
        timeout_secs: 超时秒数（None 时用 task.timeout_secs）

    Returns:
        创建的 SandboxInstance 对象

    Raises:
        TaskNotFoundError: 任务不存在
        SandboxError: 镜像不存在或 Docker 操作失败
    """
    # 1. 查询 Task + SourceSnapshot
    result = await db.execute(select(Task).where(Task.id == task_id))
    task = result.scalar_one_or_none()
    if task is None:
        raise TaskNotFoundError(task_id)

    # 获取源码快照路径
    snapshot_path: str | None = None
    if task.source_snapshot_id:
        snapshot = await db.get(SourceSnapshot, task.source_snapshot_id)
        if snapshot:
            snapshot_path = os.path.abspath(snapshot.snapshot_path)

    # 2. 确定参数
    use_image = image or task.sandbox_image or settings.SANDBOX_IMAGE_DEFAULT
    # 将应用层网络模式枚举映射到 Docker 网络名称
    # isolated/restricted -> none（完全隔离）；bridge -> bridge（受限网络）
    raw_network = network_mode or task.network_mode or settings.SANDBOX_NETWORK_MODE
    if raw_network == "isolated":
        use_network = "none"
    elif raw_network == "restricted":
        use_network = "bridge"
    else:
        use_network = raw_network
    use_memory = memory_limit or settings.SANDBOX_MEMORY_LIMIT
    use_cpu = cpu_limit or settings.SANDBOX_CPU_LIMIT
    use_pid = pid_limit or settings.SANDBOX_PID_LIMIT
    use_timeout = timeout_secs or task.timeout_secs or settings.SANDBOX_TIMEOUT_SECS

    # 源码挂载路径（容器内固定 /workspace/source）
    mount_source_container = "/workspace/source"
    tmp_dir_container = "/workspace/tmp"

    container_name = f"sandbox-{task_id}"

    dm = get_docker_manager()

    # 3. 检查镜像是否存在
    await _publish(
        redis,
        task_id,
        "sandbox_created",
        {"status": "creating", "image": use_image, "message": "正在创建沙箱容器..."},
    )

    image_exists = await _run_docker(dm.check_image, use_image)
    if not image_exists:
        error_msg = f"沙箱镜像 {use_image} 不存在，请先拉取或构建该镜像"
        logger.error(error_msg)
        # 创建一个 error 状态的记录
        instance = SandboxInstance(
            id=generate_id(),
            task_id=task_id,
            image=use_image,
            status=SandboxStatus.ERROR.value,
            network_mode=use_network,
            memory_limit=use_memory,
            cpu_limit=use_cpu,
            pid_limit=use_pid,
            timeout_secs=use_timeout,
            mount_source=snapshot_path,
            mount_target=mount_source_container,
            tmp_dir=tmp_dir_container,
            error_message=error_msg,
        )
        db.add(instance)
        await db.commit()
        await append_task_log(
            db,
            task_id,
            "sandbox",
            "sandbox_service",
            "error",
            error_msg,
        )
        await _publish(
            redis,
            task_id,
            "error",
            {"task_id": task_id, "message": error_msg},
        )
        raise SandboxError(error_msg)

    # 4. 创建 SandboxInstance DB 记录
    instance = SandboxInstance(
        id=generate_id(),
        task_id=task_id,
        image=use_image,
        status=SandboxStatus.CREATING.value,
        network_mode=use_network,
        memory_limit=use_memory,
        cpu_limit=use_cpu,
        pid_limit=use_pid,
        timeout_secs=use_timeout,
        mount_source=snapshot_path,
        mount_target=mount_source_container,
        tmp_dir=tmp_dir_container,
    )
    db.add(instance)
    await db.flush()

    # 5. 创建 + 启动 Docker 容器
    container_id = None
    try:
        container_id = await _run_docker(
            dm.create_container,
            image=use_image,
            container_name=container_name,
            source_mount_host=snapshot_path,
            source_mount_container=mount_source_container,
            tmp_dir_container=tmp_dir_container,
            network_mode=use_network,
            memory_limit=use_memory,
            cpu_limit=use_cpu,
            pid_limit=use_pid,
            timeout_secs=use_timeout,
            working_dir="/workspace",
        )

        instance.container_id = container_id
        instance.container_name = container_name

        # 启动容器
        await _run_docker(dm.start_container, container_id)
        instance.status = SandboxStatus.READY.value
        instance.ready_at = datetime.now(timezone.utc)
        await db.commit()

        # 更新 Task.sandbox_id
        task.sandbox_id = instance.id
        await db.commit()

        # 6. 发布 WebSocket 事件
        await _publish(
            redis,
            task_id,
            "sandbox_ready",
            {
                "sandbox_id": instance.id,
                "container_id": container_id[:12],
                "message": "沙箱就绪，可以执行命令",
            },
        )

        await append_task_log(
            db,
            task_id,
            "sandbox",
            "sandbox_service",
            "info",
            f"沙箱容器已创建: image={use_image}, container={container_id[:12]}",
            detail={
                "sandbox_id": instance.id,
                "container_id": container_id[:12],
                "image": use_image,
                "network": use_network,
                "memory": use_memory,
                "cpu": use_cpu,
            },
        )

        logger.info(f"沙箱已创建: task={task_id}, container={container_id[:12]}")
        return instance

    except Exception as e:
        if container_id:
            try:
                await _run_docker(
                    get_docker_manager().destroy_container,
                    container_id=container_id,
                )
            except Exception:
                logger.error(f"创建失败后清理容器异常: task={task_id}")

        # 创建失败，更新状态
        instance.status = SandboxStatus.ERROR.value
        instance.error_message = str(e)[:1024]
        await db.commit()

        await append_task_log(
            db,
            task_id,
            "sandbox",
            "sandbox_service",
            "error",
            f"沙箱创建失败: {e}",
        )
        await _publish(
            redis,
            task_id,
            "error",
            {"task_id": task_id, "message": f"沙箱创建失败: {e}"},
        )
        raise SandboxError(f"沙箱容器创建失败: {e}", detail={"task_id": task_id})


async def exec_in_sandbox(
    db: AsyncSession,
    redis: Redis,
    task_id: str,
    command: str,
    timeout: int | None = None,
    working_dir: str | None = None,
    log_output: bool = True,
    agent: str = "sandbox_service",
    phase: str = "sandbox",
) -> dict:
    """在任务的沙箱容器内执行命令。

    Args:
        db: 数据库会话
        redis: Redis 连接
        task_id: 任务 ID
        command: 要执行的命令
        timeout: 命令超时秒数（None 时用沙箱 timeout_secs）
        working_dir: 执行命令的工作目录
        log_output: 是否将输出写入 task_logs 表
        agent: 日志中的 agent 名称
        phase: 日志中的阶段名

    Returns:
        dict: {
            "exit_code": int,
            "stdout": str,
            "stderr": str,
            "timed_out": bool,
        }

    Raises:
        SandboxError: 沙箱不存在或不在就绪/运行状态
    """
    instance = await get_sandbox_by_task(db, task_id)
    if instance is None or not instance.container_id:
        raise SandboxError(f"任务 {task_id} 没有关联的沙箱容器")

    if instance.status not in (
        SandboxStatus.READY.value,
        SandboxStatus.RUNNING.value,
    ):
        raise SandboxError(f"沙箱状态为 {instance.status}，无法执行命令")

    # 更新状态为 running
    instance.status = SandboxStatus.RUNNING.value
    await db.commit()

    use_timeout = timeout or instance.timeout_secs or 300

    dm = get_docker_manager()

    # 发布执行开始事件
    await _publish(
        redis,
        task_id,
        "sandbox_exec_start",
        {
            "sandbox_id": instance.id,
            "command": command[:200],
            "timeout": use_timeout,
        },
    )

    try:
        result = await _run_docker(
            dm.exec_command,
            container_id=instance.container_id,
            command=command,
            timeout=use_timeout,
            working_dir=working_dir,
        )

        # 发布执行完成事件
        await _publish(
            redis,
            task_id,
            "sandbox_exec_done",
            {
                "sandbox_id": instance.id,
                "exit_code": result["exit_code"],
                "timed_out": result["timed_out"],
                "stdout_preview": result["stdout"][:500],
                "stderr_preview": result["stderr"][:500],
            },
        )

        if result.get("timed_out"):
            instance.status = SandboxStatus.ERROR.value
            instance.error_message = (
                f"命令执行超时，沙箱容器已终止: {command[:200]}"
            )
            await db.commit()
            await destroy_sandbox(db, redis, task_id)
            raise SandboxError(
                f"沙箱命令执行超时: {command[:200]}",
                detail={"task_id": task_id},
            )

        if log_output:
            level = "info" if result["exit_code"] == 0 else "warning"
            msg_parts = [
                f"命令执行完成 (exit={result['exit_code']})",
            ]
            if result["timed_out"]:
                msg_parts.append("[超时]")
            msg_parts.append(f"cmd: {command[:200]}")
            await append_task_log(
                db,
                task_id,
                phase,
                agent,
                level,
                " | ".join(msg_parts),
                detail={
                    "command": command,
                    "exit_code": result["exit_code"],
                    "stdout": result["stdout"][:2000],
                    "stderr": result["stderr"][:2000],
                    "timed_out": result["timed_out"],
                },
            )

        # 执行完后恢复为 ready
        instance.status = SandboxStatus.READY.value
        await db.commit()

        return result

    except Exception as e:
        instance.status = SandboxStatus.ERROR.value
        instance.error_message = str(e)[:1024]
        await db.commit()
        logger.error(f"沙箱执行命令失败: task={task_id}, error={e}")
        raise SandboxError(f"沙箱命令执行失败: {e}")


async def destroy_sandbox(
    db: AsyncSession,
    redis: Redis,
    task_id: str,
    force: bool = True,
) -> SandboxInstance | None:
    """销毁任务的沙箱容器。

    先停止容器内进程，再删除容器，更新 DB 状态为 destroyed。
    注意：不会删除 task_logs、findings 等已持久化的数据。

    Args:
        db: 数据库会话
        redis: Redis 连接
        task_id: 任务 ID
        force: 是否强制删除

    Returns:
        更新后的 SandboxInstance，或 None（沙箱不存在时）
    """
    instance = await get_sandbox_by_task(db, task_id)
    if instance is None:
        logger.warning(f"任务 {task_id} 没有关联的沙箱，跳过销毁")
        return None

    if instance.status == SandboxStatus.DESTROYED.value:
        logger.info(f"沙箱已销毁，跳过: task={task_id}")
        return instance

    container_id = instance.container_id

    # 更新状态为 destroying
    instance.status = SandboxStatus.DESTROYING.value
    await db.commit()

    await _publish(
        redis,
        task_id,
        "sandbox_destroying",
        {
            "sandbox_id": instance.id,
            "container_id": (container_id or "")[:12],
            "message": "正在销毁沙箱容器...",
        },
    )

    if container_id:
        dm = get_docker_manager()
        try:
            # 先停止容器内进程，再删除容器
            await _run_docker(
                dm.destroy_container,
                container_id=container_id,
                force=force,
                timeout=10,
            )
        except Exception as e:
            logger.error(f"销毁容器 {container_id[:12]} 时出错: {e}")
            # 即使出错也继续更新 DB 状态

    # 更新 DB
    instance.status = SandboxStatus.DESTROYED.value
    instance.destroyed_at = datetime.now(timezone.utc)

    # 清除 Task 上的 sandbox_id 引用（沙箱已不存在）
    task_result = await db.execute(select(Task).where(Task.id == task_id))
    task = task_result.scalar_one_or_none()
    if task:
        task.sandbox_id = None

    await db.commit()

    await _publish(
        redis,
        task_id,
        "sandbox_destroyed",
        {
            "sandbox_id": instance.id,
            "container_id": (container_id or "")[:12],
            "message": "沙箱容器已销毁，数据已保留",
        },
    )

    await append_task_log(
        db,
        task_id,
        "sandbox",
        "sandbox_service",
        "info",
        "沙箱容器已销毁，任务日志和阶段数据已保留",
        detail={
            "sandbox_id": instance.id,
            "container_id": (container_id or "")[:12],
        },
    )

    logger.info(f"沙箱已销毁: task={task_id}")
    return instance


async def get_sandbox_by_task(db: AsyncSession, task_id: str) -> SandboxInstance | None:
    """获取任务关联的最新沙箱实例。"""
    result = await db.execute(
        select(SandboxInstance)
        .where(SandboxInstance.task_id == task_id)
        .order_by(SandboxInstance.created_at.desc())
        .limit(1)
    )
    return result.scalar_one_or_none()


async def get_sandbox_status(db: AsyncSession, task_id: str) -> dict:
    """获取沙箱运行状态（DB 状态 + Docker 实时状态）。

    Returns:
        dict: {
            "sandbox_id": str,
            "container_id": str | None,
            "db_status": str,
            "docker_status": str,
            "image": str,
            "created_at": datetime,
            "ready_at": datetime | None,
            "destroyed_at": datetime | None,
        }
    """
    instance = await get_sandbox_by_task(db, task_id)
    if instance is None:
        return {
            "sandbox_id": None,
            "container_id": None,
            "db_status": "none",
            "docker_status": "none",
            "image": None,
            "created_at": None,
            "ready_at": None,
            "destroyed_at": None,
        }

    docker_status = "none"
    if instance.container_id and instance.status != SandboxStatus.DESTROYED.value:
        dm = get_docker_manager()
        try:
            status_info = await _run_docker(
                dm.get_container_status, instance.container_id
            )
            docker_status = status_info.get("status", "unknown")
        except Exception:
            docker_status = "unknown"

    return {
        "sandbox_id": instance.id,
        "container_id": instance.container_id,
        "db_status": instance.status,
        "docker_status": docker_status,
        "image": instance.image,
        "created_at": instance.created_at,
        "ready_at": instance.ready_at,
        "destroyed_at": instance.destroyed_at,
    }


async def get_sandbox_stats(db: AsyncSession, task_id: str) -> dict:
    """获取沙箱资源使用统计。"""
    instance = await get_sandbox_by_task(db, task_id)
    if instance is None or not instance.container_id:
        return {
            "cpu_percent": 0.0,
            "memory_usage_mb": 0.0,
            "memory_limit_mb": 0.0,
            "memory_percent": 0.0,
            "pid_count": 0,
            "available": False,
        }

    if instance.status == SandboxStatus.DESTROYED.value:
        return {
            "cpu_percent": 0.0,
            "memory_usage_mb": 0.0,
            "memory_limit_mb": 0.0,
            "memory_percent": 0.0,
            "pid_count": 0,
            "available": False,
        }

    dm = get_docker_manager()
    try:
        stats = await _run_docker(dm.get_container_stats, instance.container_id)
        stats["available"] = True
        return stats
    except Exception as e:
        logger.error(f"获取沙箱统计失败: {e}")
        return {
            "cpu_percent": 0.0,
            "memory_usage_mb": 0.0,
            "memory_limit_mb": 0.0,
            "memory_percent": 0.0,
            "pid_count": 0,
            "available": False,
            "error": str(e),
        }


async def get_sandbox_logs(db: AsyncSession, task_id: str, tail: int = 200) -> str:
    """获取沙箱容器日志。"""
    instance = await get_sandbox_by_task(db, task_id)
    if instance is None or not instance.container_id:
        return ""

    if instance.status == SandboxStatus.DESTROYED.value:
        return "[沙箱已销毁，容器日志不可用]"

    dm = get_docker_manager()
    try:
        return await _run_docker(
            dm.get_container_logs,
            container_id=instance.container_id,
            tail=tail,
        )
    except Exception as e:
        return f"[获取日志失败: {e}]"
