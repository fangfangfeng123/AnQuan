"""Docker 沙箱管理器模块。

本模块封装 Docker SDK 的底层操作，为 sandbox_service 提供基础能力。
DockerManager 是一个同步类（Docker SDK 本身是同步），由 sandbox_service 在
asyncio 线程池中调用（run_in_executor）。

核心能力：
  - check_image(image)：检查镜像本地是否存在
  - create_container(...)：创建容器（配置只读挂载、tmpfs、网络、资源限制）
  - start_container(container_id)：启动容器
  - exec_command(container_id, command, timeout)：在运行中容器内执行命令
  - get_container_status(container_id)：获取容器状态
  - get_container_stats(container_id)：获取容器资源使用统计
  - get_container_logs(container_id, tail)：获取容器日志
  - stop_container(container_id, timeout)：停止容器
  - remove_container(container_id, force)：删除容器
  - destroy_container(container_id, force)：停止 + 删除（一步到位）
"""

import logging
import threading
import time
from typing import Any

import docker
from docker import DockerClient
from docker.errors import APIError, ImageNotFound, NotFound
from docker.models.containers import Container

from app.core.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


class DockerManager:
    """Docker 沙箱容器生命周期管理器。

    所有方法均为同步调用——Docker SDK 本身是同步的。
    调用方（sandbox_service）应在 asyncio 线程池中调用本类方法。
    """

    def __init__(self, base_url: str | None = None) -> None:
        """初始化 Docker 客户端。

        Args:
            base_url: Docker daemon 地址。None 时使用 docker.from_env()
                      （本机连本机 Docker，Docker Desktop 默认 npipe/tcp）。
        """
        if base_url:
            self._client: DockerClient = docker.DockerClient(base_url=base_url)
        else:
            self._client = docker.from_env()
        logger.info(f"DockerManager 初始化完成, base_url={base_url or 'from_env()'}")

    # -- 镜像管理 --

    def check_image(self, image: str) -> bool:
        """检查镜像是否在本地存在。"""
        try:
            self._client.images.get(image)
            return True
        except ImageNotFound:
            return False
        except APIError as e:
            logger.error(f"检查镜像 {image} 时出错: {e}")
            return False

    def list_images(self) -> list[dict[str, Any]]:
        """列出本地所有镜像。"""
        images = self._client.images.list()
        result: list[dict[str, Any]] = []
        for img in images:
            tags = img.tags or []
            result.append(
                {
                    "id": img.id,
                    "tags": tags,
                    "short_id": img.short_id,
                    "size_mb": round(img.attrs.get("Size", 0) / 1024 / 1024, 1),
                }
            )
        return result

    # -- 容器生命周期 --

    def create_container(
        self,
        image: str,
        container_name: str,
        source_mount_host: str | None = None,
        source_mount_container: str = "/workspace/source",
        tmp_dir_container: str = "/workspace/tmp",
        network_mode: str = "none",
        memory_limit: str = "512m",
        cpu_limit: int = 1,
        pid_limit: int | None = None,
        timeout_secs: int = 1800,
        working_dir: str = "/workspace",
        environment: dict[str, str] | None = None,
    ) -> str:
        """创建 Docker 容器（不启动）。

        源码目录以只读 bind mount 方式挂载，临时可写目录使用 tmpfs。
        容器以 sleep 模式启动（command=sleep infinity），等待后续 exec 执行命令。

        Args:
            image: 镜像名
            container_name: 容器名（唯一，建议用 task_id 衍生）
            source_mount_host: 宿主机源码快照路径（None 时不挂载）
            source_mount_container: 容器内源码挂载点
            tmp_dir_container: 容器内临时可写目录
            network_mode: 网络模式（none=完全隔离, bridge=受限网络）
            memory_limit: 内存限制（如 512m, 1g）
            cpu_limit: CPU 核数限制
            pid_limit: 最大进程数限制（None 时不限制）
            timeout_secs: 容器最大存活时间（秒）
            working_dir: 容器工作目录
            environment: 环境变量

        Returns:
            container_id (str)
        """
        # -- 构建挂载配置 --
        volumes: dict[str, dict[str, str]] = {}

        if source_mount_host:
            volumes[source_mount_host] = {
                "bind": source_mount_container,
                "mode": "ro",  # 只读挂载
            }

        # tmpfs 挂载临时可写目录
        tmpfs = {tmp_dir_container: "size=256m,mode=1777"}

        # -- 资源限制 --
        nano_cpus = cpu_limit * 10**9 if cpu_limit else None
        mem_limit = memory_limit
        pids_limit = pid_limit if pid_limit else None

        # -- 创建容器 --
        container: Container = self._client.containers.create(
            image=image,
            name=container_name,
            command=["sleep", "infinity"],
            working_dir=working_dir,
            volumes=volumes,
            tmpfs=tmpfs,
            network_mode=network_mode,
            cap_drop=["ALL"],
            security_opt=["no-new-privileges"],
            mem_limit=mem_limit,
            nano_cpus=nano_cpus,
            pids_limit=pids_limit,
            tty=True,
            stdin_open=False,
            detach=True,
            environment=environment or {},
            labels={
                "app": "security-assessment",
                "managed-by": "docker-manager",
            },
        )

        container_id: str = container.id or ""
        logger.info(
            f"容器已创建: name={container_name}, id={container_id[:12]}, "
            f"image={image}, network={network_mode}, "
            f"source_mount={'yes' if source_mount_host else 'no'}"
        )
        return container_id

    def start_container(self, container_id: str) -> None:
        """启动已创建的容器。"""
        container = self._client.containers.get(container_id)
        container.start()
        logger.info(f"容器已启动: {container_id[:12]}")

    def exec_command(
        self,
        container_id: str,
        command: str | list[str],
        timeout: int = 300,
        working_dir: str | None = None,
    ) -> dict[str, Any]:
        """在运行中的容器内执行命令，获取 stdout/stderr/exit_code。

        使用 docker exec 在容器内执行命令，支持超时控制。
        超时后自动终止该 exec 进程（不影响容器本身）。

        Args:
            container_id: 容器 ID 或名称
            command: 要执行的命令（str 或 list[str]）
            timeout: 命令超时时间（秒），默认 300
            working_dir: 执行命令的工作目录

        Returns:
            dict: {"exit_code": int, "stdout": str, "stderr": str, "timed_out": bool}
        """
        container = self._client.containers.get(container_id)

        # 如果传入的是字符串且包含 shell 运算符（重定向、管道、&&、||、$ 等），
        # 则用 sh -c 包装以确保 shell 语义正确解析。
        _shell_ops = {"&", "|", ">", "<", ";", "$", "`", "(", ")"}
        if isinstance(command, str):
            if any(op in command for op in _shell_ops):
                cmd_list = ["sh", "-c", command]
            else:
                cmd_list = command.split()
        else:
            cmd_list = list(command)

        logger.debug(
            f"在容器 {container_id[:12]} 中执行: {cmd_list}, timeout={timeout}s"
        )

        timed_out = threading.Event()

        def kill_on_timeout() -> None:
            timed_out.set()
            try:
                container.kill()
            except Exception:
                logger.warning(
                    f"容器 {container_id[:12]} 命令超时后 kill 失败"
                )

        watchdog = threading.Timer(max(int(timeout or 1), 1), kill_on_timeout)
        watchdog.daemon = True
        watchdog.start()

        try:
            # 使用高层 exec_run API，demux=True 分离 stdout/stderr
            # 在线程池中执行以支持超时控制
            exec_result = container.exec_run(
                cmd=cmd_list,
                workdir=working_dir,
                stderr=True,
                stdout=True,
                stream=False,
                demux=True,
            )

            # ExecResult: namedtuple(exit_code, output)
            # demux=True 时 output = (stdout_bytes | None, stderr_bytes | None)
            exit_code = exec_result.exit_code
            output = exec_result.output

            if isinstance(output, tuple):
                stdout_bytes = output[0] or b""
                stderr_bytes = output[1] or b""
            else:
                stdout_bytes = output or b""
                stderr_bytes = b""

            # 确保 stdout_bytes 和 stderr_bytes 始终是 bytes 类型
            if not isinstance(stdout_bytes, bytes):
                stdout_bytes = str(stdout_bytes).encode("utf-8")
            if not isinstance(stderr_bytes, bytes):
                stderr_bytes = str(stderr_bytes).encode("utf-8")

            return {
                "exit_code": exit_code if exit_code is not None else -1,
                "stdout": stdout_bytes.decode("utf-8", errors="replace"),
                "stderr": stderr_bytes.decode("utf-8", errors="replace"),
                "timed_out": timed_out.is_set(),
            }

        except Exception as e:
            error_str = str(e)
            is_timeout = timed_out.is_set() or (
                "timed out" in error_str.lower() or "timeout" in error_str.lower()
            )

            if is_timeout:
                logger.warning(f"容器 {container_id[:12]} 命令执行超时: {cmd_list}")
                return {
                    "exit_code": -1,
                    "stdout": "",
                    "stderr": f"Command timed out after {timeout}s",
                    "timed_out": True,
                }

            logger.error(f"容器 {container_id[:12]} 命令执行异常: {e}")
            return {
                "exit_code": -1,
                "stdout": "",
                "stderr": str(e),
                "timed_out": False,
            }
        finally:
            watchdog.cancel()

    def get_container_status(self, container_id: str) -> dict[str, Any]:
        """获取容器状态。"""
        try:
            container = self._client.containers.get(container_id)
            attrs = container.attrs or {}
            state = attrs.get("State", {})
            return {
                "exists": True,
                "status": state.get("Status", "unknown"),
                "short_id": container.short_id,
                "name": container.name,
                "image": attrs.get("Config", {}).get("Image", ""),
                "started_at": state.get("StartedAt"),
                "finished_at": state.get("FinishedAt"),
                "exit_code": state.get("ExitCode"),
            }
        except NotFound:
            return {
                "exists": False,
                "status": "none",
                "short_id": "",
                "name": "",
                "image": "",
                "started_at": None,
                "finished_at": None,
                "exit_code": None,
            }

    def get_container_stats(self, container_id: str) -> dict[str, Any]:
        """获取容器资源使用统计（CPU/内存/网络 IO）。"""
        try:
            container = self._client.containers.get(container_id)
            # stream=False 时返回一个 dict（非迭代器）
            stats: dict[str, Any] = container.stats(stream=False)  # type: ignore[assignment]

            # CPU 计算
            cpu_stats = stats.get("cpu_stats", {})
            precpu_stats = stats.get("precpu_stats", {})
            cpu_delta = cpu_stats.get("cpu_usage", {}).get(
                "total_usage", 0
            ) - precpu_stats.get("cpu_usage", {}).get("total_usage", 0)
            sys_delta = cpu_stats.get("system_cpu_usage", 0) - precpu_stats.get(
                "system_cpu_usage", 0
            )
            online_cpus = cpu_stats.get("online_cpus", 1) or 1
            if sys_delta > 0 and cpu_delta > 0:
                cpu_percent = round((cpu_delta / sys_delta) * online_cpus * 100, 2)
            else:
                cpu_percent = 0.0

            # 内存
            mem_stats = stats.get("memory_stats", {})
            mem_usage = mem_stats.get("usage", 0)
            mem_limit = mem_stats.get("limit", 1)
            mem_usage_mb = round(mem_usage / 1024 / 1024, 2) if mem_usage else 0.0
            mem_limit_mb = round(mem_limit / 1024 / 1024, 2) if mem_limit else 0.0
            mem_percent = (
                round((mem_usage / mem_limit) * 100, 2) if mem_limit > 0 else 0.0
            )

            # PID
            pids_stats = stats.get("pids_stats", {})
            pid_count = pids_stats.get("current", 0)

            # 网络
            networks = stats.get("networks", {})
            rx_total = sum(v.get("rx_bytes", 0) for v in networks.values())
            tx_total = sum(v.get("tx_bytes", 0) for v in networks.values())

            return {
                "cpu_percent": cpu_percent,
                "memory_usage_mb": mem_usage_mb,
                "memory_limit_mb": mem_limit_mb,
                "memory_percent": mem_percent,
                "pid_count": pid_count,
                "network_rx_bytes": rx_total,
                "network_tx_bytes": tx_total,
                "read_time": stats.get("read", ""),
            }
        except (NotFound, APIError) as e:
            logger.warning(f"获取容器 {container_id[:12]} 统计失败: {e}")
            return {
                "cpu_percent": 0.0,
                "memory_usage_mb": 0.0,
                "memory_limit_mb": 0.0,
                "memory_percent": 0.0,
                "pid_count": 0,
                "network_rx_bytes": 0,
                "network_tx_bytes": 0,
                "read_time": "",
            }

    def get_container_logs(self, container_id: str, tail: int = 200) -> str:
        """获取容器日志（最近 N 行）。"""
        try:
            container = self._client.containers.get(container_id)
            logs = container.logs(
                stdout=True,
                stderr=True,
                stream=False,
                tail=tail,
            )
            if isinstance(logs, bytes):
                return logs.decode("utf-8", errors="replace")
            return str(logs)
        except (NotFound, APIError) as e:
            logger.warning(f"获取容器 {container_id[:12]} 日志失败: {e}")
            return ""

    def stop_container(self, container_id: str, timeout: int = 10) -> None:
        """停止容器（优雅停止，超时后 SIGKILL）。"""
        try:
            container = self._client.containers.get(container_id)
            container.stop(timeout=timeout)
            logger.info(f"容器已停止: {container_id[:12]}")
        except NotFound:
            logger.warning(f"容器不存在，跳过停止: {container_id[:12]}")

    def remove_container(self, container_id: str, force: bool = True) -> None:
        """删除容器（force=True 时强制删除运行中的容器）。"""
        try:
            container = self._client.containers.get(container_id)
            container.remove(force=force, v=True)
            logger.info(f"容器已删除: {container_id[:12]}, force={force}")
        except NotFound:
            logger.warning(f"容器不存在，跳过删除: {container_id[:12]}")

    def destroy_container(
        self, container_id: str, force: bool = True, timeout: int = 10
    ) -> None:
        """停止并删除容器（一步到位）。

        先停止容器（等待 timeout 秒优雅退出），再强制删除。
        确保容器退出后不留残留。
        """
        try:
            container = self._client.containers.get(container_id)
            # 先停止
            try:
                container.stop(timeout=timeout)
            except Exception as e:
                logger.debug(f"停止容器时已停止或出错（忽略）: {e}")
            # 再删除
            container.remove(force=force, v=True)
            logger.info(f"容器已销毁（stop+remove）: {container_id[:12]}")
        except NotFound:
            logger.warning(f"容器不存在，跳过销毁: {container_id[:12]}")
        except APIError as e:
            logger.error(f"销毁容器 {container_id[:12]} 时出错: {e}")
            try:
                container = self._client.containers.get(container_id)
                container.remove(force=True, v=True)
                logger.info(f"容器强制删除成功: {container_id[:12]}")
            except Exception:
                logger.error(f"容器最终强制删除也失败: {container_id[:12]}")

    # -- 清理工具 --

    def cleanup_orphaned_containers(self) -> int:
        """清理所有由本系统创建但已无主任务关联的残留容器。

        删除所有带 label app=security-assessment 的容器。
        用于应用启动时的健康清理。

        Returns:
            清理的容器数量
        """
        count = 0
        containers = self._client.containers.list(
            all=True,
            filters={"label": "app=security-assessment"},
        )
        for c in containers:
            try:
                c.remove(force=True, v=True)
                count += 1
                logger.info(f"清理残留容器: {c.short_id}")
            except Exception as e:
                logger.error(f"清理容器 {c.short_id} 失败: {e}")
        if count:
            logger.info(f"共清理 {count} 个残留沙箱容器")
        return count

    def ping(self) -> bool:
        """检查 Docker daemon 是否可达。"""
        try:
            self._client.ping()
            return True
        except Exception:
            return False


# -- 全局单例 --
_manager: DockerManager | None = None


def get_docker_manager() -> DockerManager:
    """获取 DockerManager 全局单例。

    本机连本机 Docker 时使用 from_env()，可自动适配
    Docker Desktop（npipe）或 Linux（unix socket）。
    """
    global _manager
    if _manager is None:
        docker_host = settings.DOCKER_HOST
        if docker_host and not docker_host.startswith("unix:///var/run"):
            _manager = DockerManager(base_url=docker_host)
        else:
            _manager = DockerManager()
    return _manager
