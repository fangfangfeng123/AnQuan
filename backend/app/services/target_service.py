"""临时目标服务管理模块。

在沙箱容器内启动被测目标服务（纯 Python http.server 实现，无需安装 flask），
使用 urllib 进行健康检查（无需 curl），确保 PoC 探针能访问目标。
失败时记录原因而非直接误报。

流程：
1. 将源码从只读挂载路径复制到 /workspace/tmp 并启动
2. 健康检查：python urllib 请求目标服务根路径
3. 返回服务状态和 base_url
4. 任务完成后目标服务随沙箱一起销毁
"""

import asyncio
import logging
from typing import Any

from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.sandbox_service import exec_in_sandbox

logger = logging.getLogger(__name__)

TARGET_AGENT = "poc_verify_agent"
TARGET_PHASE = "poc_verify"

# 默认目标服务端口
DEFAULT_PORT = 5000


async def _exec(
    db: AsyncSession,
    redis: Redis,
    task_id: str,
    command: str,
    timeout: int = 120,
) -> dict[str, Any]:
    """在沙箱内执行命令，返回完整结果字典。"""
    return await exec_in_sandbox(
        db,
        redis,
        task_id,
        command,
        timeout=timeout,
        agent=TARGET_AGENT,
        phase=TARGET_PHASE,
    )


async def start_target_service(
    db: AsyncSession,
    redis: Redis,
    task_id: str,
    entry_file: str = "app.py",
    port: int = DEFAULT_PORT,
    install_deps: bool = False,
) -> dict[str, Any]:
    """在沙箱内启动临时目标服务。

    流程：
    1. 后台启动目标服务（纯 Python http.server，无需 pip install）
    2. 等待健康检查通过（使用 urllib 而非 curl）

    Args:
        db: 数据库会话
        redis: Redis 连接
        task_id: 任务 ID
        entry_file: 入口文件名（如 app.py）
        port: 目标服务端口
        install_deps: 兼容参数，实际不安装（沙箱无网络）

    Returns:
        dict: {
            "success": bool,
            "base_url": str,
            "port": int,
            "error": str | None,
        }
    """
    base_url = f"http://127.0.0.1:{port}"
    source_dir = "/workspace/source"
    tmp_dir = "/workspace/tmp"

    # 解析真实入口文件
    if entry_file.startswith(source_dir + "/"):
        entry_file = entry_file[len(source_dir + "/") :]
    check_entry = await _exec(
        db,
        redis,
        task_id,
        (
            f"if [ -f {source_dir}/{entry_file} ]; then "
            f"echo {entry_file}; "
            "else find /workspace/source -maxdepth 3 -type f "
            r"\( -name 'main.py' -o -name 'app.py' -o -name 'wsgi.py' \) "
            "| head -1; fi"
        ),
        timeout=15,
    )
    entry_stdout = (check_entry.get("stdout") or "").strip()
    if entry_stdout:
        entry_file = entry_stdout.splitlines()[0].strip()
        if entry_file.startswith(source_dir + "/"):
            entry_file = entry_file[len(source_dir + "/") :]

    # ── 1. 后台启动目标服务 ──
    # 使用 nohup + & 在后台启动，输出重定向到 /workspace/tmp/app.log
    start_cmd = (
        f"mkdir -p {tmp_dir} && "
        f"cd {source_dir} && "
        f"PYTHONPATH={source_dir} ECOM_DB_PATH={tmp_dir}/ecommerce.db "
        f"ECOM_UPLOAD_DIR={tmp_dir}/uploads "
        f"PYTHONDONTWRITEBYTECODE=1 nohup python {entry_file} "
        f"> {tmp_dir}/app.log 2>&1 &"
    )
    logger.info("[target_service] Starting target: %s", start_cmd[:100])
    result = await _exec(db, redis, task_id, start_cmd, timeout=15)
    # nohup + & 会立即返回，exit_code 可能是 0 或 1

    # ── 2. 健康检查：等待服务启动 ──
    # 使用 Python urllib 替代 curl（沙箱镜像内无 curl）
    # 先写入健康检查脚本，再调用（避免复杂的 shell 引号转义）
    health_script = (
        "import urllib.request, urllib.error, sys\n"
        "try:\n"
        "    r = urllib.request.urlopen(sys.argv[1], timeout=3)\n"
        "    print(r.getcode())\n"
        "except urllib.error.HTTPError as e:\n"
        "    print(e.code)\n"
        "except Exception:\n"
        "    print(0)\n"
    )
    write_hc_cmd = (
        f"mkdir -p {tmp_dir} && "
        f"cat > {tmp_dir}/healthcheck.py << 'HC_EOF'\n"
        f"{health_script}\n"
        f"HC_EOF"
    )
    await _exec(db, redis, task_id, write_hc_cmd, timeout=10)

    health_cmd = f"python {tmp_dir}/healthcheck.py {base_url}/"
    logger.info("[target_service] Health check: python urllib")

    max_retries = 10
    for attempt in range(max_retries):
        await asyncio.sleep(1.5)
        hc = await _exec(db, redis, task_id, health_cmd, timeout=10)
        stdout = hc.get("stdout", "").strip()
        exit_code = hc.get("exit_code", -1)

        if exit_code == 0 and stdout:
            try:
                status = int(stdout.strip())
            except ValueError:
                status = 0

            # 200 或 404 都说明服务已启动
            if status in (200, 301, 302, 404):
                logger.info(
                    "[target_service] Target is up (attempt=%d, status=%d)",
                    attempt + 1,
                    status,
                )
                return {
                    "success": True,
                    "base_url": base_url,
                    "port": port,
                    "error": None,
                }

        logger.debug(
            "[target_service] Health check attempt %d/%d: exit=%s, out=%s",
            attempt + 1,
            max_retries,
            exit_code,
            stdout[:50],
        )

    # ── 3. 健康检查失败，获取服务日志 ──
    log_cmd = f"cat {tmp_dir}/app.log 2>/dev/null || echo 'no log file'"
    log_result = await _exec(db, redis, task_id, log_cmd, timeout=10)
    app_log = log_result.get("stdout", "")[:1000]

    error_msg = (
        f"Target service not ready after {max_retries} health checks. Log:\n{app_log}"
    )
    logger.error("[target_service] %s", error_msg)

    return {
        "success": False,
        "base_url": base_url,
        "port": port,
        "error": error_msg,
    }


async def stop_target_service(
    db: AsyncSession,
    redis: Redis,
    task_id: str,
    port: int = DEFAULT_PORT,
) -> None:
    """停止沙箱内的目标服务。

    杀掉监听指定端口的进程。沙箱销毁时会自动清理，
    但提前停止可以释放资源。
    """
    # 使用 fuser 替代 lsof（沙箱内可能无 lsof）
    kill_cmd = f"fuser -k {port}/tcp 2>/dev/null || kill $(ss -tlnp 2>/dev/null | grep ':{port} ' | grep -oP 'pid=\\K[0-9]+' | head -1) 2>/dev/null || true"
    try:
        await _exec(db, redis, task_id, kill_cmd, timeout=10)
        logger.info("[target_service] Target service stopped on port %d", port)
    except Exception as e:
        logger.warning("[target_service] Failed to stop target: %s", e)
