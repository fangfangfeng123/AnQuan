"""环境侦察服务层模块。

本模块是 Recon Agent 的核心服务层，负责：
1. 在沙箱容器内执行侦察命令（ls / cat / find / grep）
2. 调用三个 scanner（manifest_parser / tech_detector / route_scanner）解析结果
3. 将识别出的 runtimeProfile 写入 runtime_profiles 表
4. 发布 WebSocket 事件让前端工作台实时展示
5. 写入 Recon 阶段日志

输入：task_id + 沙箱容器（已创建并挂载源码）
输出：runtime_profile 记录 + Recon 阶段 completed + 日志 + WS 事件
"""

import json
import logging
from datetime import datetime, timezone

from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import SandboxError
from app.models import RuntimeProfile, Task
from app.scanners.manifest_parser import (
    detect_manifest_files,
    parse_manifest,
)
from app.scanners.route_scanner import scan_routes, summarize_routes
from app.scanners.tech_detector import (
    detect_db_type,
    detect_entry_points,
    detect_framework,
    detect_language,
    detect_ports,
    detect_run_command,
)
from app.services.sandbox_service import exec_in_sandbox
from app.utils import append_task_log, generate_id
from app.websockets.publisher import EventPublisher

logger = logging.getLogger(__name__)

# 侦察阶段 agent 名称
RECON_AGENT = "recon_agent"
RECON_PHASE = "recon"

# 依赖清单文件完整列表（用于沙箱内检测）
MANIFEST_FILENAMES = [
    "requirements.txt",
    "pyproject.toml",
    "Pipfile",
    "package.json",
    "pom.xml",
    "build.gradle",
    "go.mod",
    "composer.json",
    "Gemfile",
]

# 配置文件列表（用于数据库识别）
CONFIG_FILENAMES = [
    ".env",
    ".env.example",
    ".env.local",
    "settings.py",
    "config.py",
    "config.json",
    "config.yaml",
    "config.yml",
    "application.properties",
    "application.yml",
    "application.yaml",
    "database.py",
    "settings.json",
    "settings.yaml",
    "settings.yml",
]


async def _exec(
    db: AsyncSession,
    redis: Redis,
    task_id: str,
    command: str,
) -> str:
    """在沙箱中执行命令并返回 stdout（封装 exec_in_sandbox）。

    如果命令失败（非零退出码），返回空字符串而非抛异常，
    让侦察流程对单个命令失败有韧性。
    """
    try:
        result = await exec_in_sandbox(
            db,
            redis,
            task_id,
            command,
            agent=RECON_AGENT,
            phase=RECON_PHASE,
        )
        return result.get("stdout", "")
    except SandboxError as e:
        logger.warning(f"侦察命令执行失败: cmd={command[:80]}, error={e}")
        return ""


async def _exec_required(
    db: AsyncSession,
    redis: Redis,
    task_id: str,
    command: str,
) -> str:
    """在沙箱中执行命令，失败时抛异常（用于关键命令）。"""
    result = await exec_in_sandbox(
        db,
        redis,
        task_id,
        command,
        agent=RECON_AGENT,
        phase=RECON_PHASE,
    )
    return result.get("stdout", "")


async def _publish(
    redis: Redis,
    task_id: str,
    event_type: str,
    payload: dict,
) -> None:
    """发布 WebSocket 事件。"""
    await EventPublisher.publish(redis, task_id, event_type, payload)


# ── 主流程 ──


async def run_recon(
    db: AsyncSession,
    redis: Redis,
    task_id: str,
) -> RuntimeProfile:
    """执行完整环境侦察流程。

    流程：
    1. 在沙箱内扫描源码根目录
    2. 检测并读取依赖清单文件
    3. 识别主语言、主框架
    4. 解析依赖清单
    5. 识别入口文件
    6. 读取入口代码识别路由
    7. 识别端口和数据库类型
    8. 写入 runtime_profiles 表
    9. 发布 WS 事件 + 写日志

    Args:
        db: 数据库会话
        redis: Redis 连接
        task_id: 任务 ID

    Returns:
        RuntimeProfile ORM 对象

    Raises:
        SandboxError: 沙箱命令执行失败
    """
    # ── 1. 扫描源码根目录 ──
    await _publish(
        redis,
        task_id,
        "recon_progress",
        {"step": "scanning_root", "message": "正在扫描源码根目录..."},
    )

    source_dir = "/workspace/source"

    # ls -la 获取根目录文件列表
    file_listing = await _exec(db, redis, task_id, f"ls -1 {source_dir}")

    # find 统计文件数
    file_count_raw = await _exec(
        db,
        redis,
        task_id,
        f"find {source_dir} -type f | wc -l",
    )
    file_count = int(file_count_raw.strip()) if file_count_raw.strip().isdigit() else 0

    # 文件类型分布
    file_type_dist = await _exec(
        db,
        redis,
        task_id,
        f'find {source_dir} -type f | sed "s/.*\\.//" | sort | uniq -c | sort -rn | head -20',
    )

    # 总代码行数
    total_lines_raw = await _exec(
        db,
        redis,
        task_id,
        f'find {source_dir} -name "*.py" -o -name "*.js" -o -name "*.java" -o -name "*.go" -o -name "*.php" -o -name "*.rb" | xargs wc -l 2>/dev/null | tail -1',
    )

    # find 完整文件列表（用于入口文件识别）
    full_file_list = await _exec(
        db,
        redis,
        task_id,
        f"find {source_dir} -maxdepth 3 -type f | head -200",
    )

    # ── 2. 检测并读取依赖清单文件 ──
    await _publish(
        redis,
        task_id,
        "recon_progress",
        {"step": "detecting_manifests", "message": "正在检测依赖清单文件..."},
    )

    # 用 detect_manifest_files 从 ls 输出中检测存在的清单文件
    manifest_files_found = detect_manifest_files(file_listing)

    # 如果根目录没找到，尝试在子目录中查找
    if not manifest_files_found:
        # 从 find 输出中查找
        for fname in MANIFEST_FILENAMES:
            if fname in full_file_list:
                manifest_files_found.append(fname)

    # 读取找到的依赖清单文件内容
    manifest_contents: dict[str, str] = {}
    for fname in manifest_files_found:
        # 尝试从根目录读取
        content = await _exec(
            db,
            redis,
            task_id,
            f"cat {source_dir}/{fname} 2>/dev/null",
        )
        if not content:
            # 尝试从 find 输出中找完整路径
            for line in full_file_list.split("\n"):
                if line.strip().endswith(f"/{fname}") or line.strip() == fname:
                    content = await _exec(
                        db,
                        redis,
                        task_id,
                        f"cat {line.strip()} 2>/dev/null",
                    )
                    if content:
                        break
        if content:
            manifest_contents[fname] = content

    # ── 3. 识别主语言 ──
    language = detect_language(manifest_files_found, file_type_dist)

    # ── 4. 解析依赖清单 ──
    all_dependencies: dict[str, str | None] = {}
    for fname, content in manifest_contents.items():
        deps = parse_manifest(fname, content)
        all_dependencies.update(deps)

    # ── 5. 识别主框架 ──
    framework = detect_framework(language, all_dependencies)

    # ── 6. 识别入口文件 ──
    await _publish(
        redis,
        task_id,
        "recon_progress",
        {"step": "detecting_entries", "message": "正在识别入口文件..."},
    )

    entry_points = detect_entry_points(
        language, framework, file_listing + "\n" + full_file_list
    )

    # ── 7. 读取入口代码内容（用于端口、路由识别） ──
    entry_code_contents: dict[str, str] = {}
    for ep in entry_points:
        ep_file = ep.get("file", "")
        if not ep_file:
            continue
        # 读取入口文件内容
        content = await _exec(
            db,
            redis,
            task_id,
            f"cat {source_dir}/{ep_file} 2>/dev/null",
        )
        if not content:
            # 尝试从 find 输出中找完整路径
            for line in full_file_list.split("\n"):
                if line.strip().endswith(ep_file):
                    content = await _exec(
                        db,
                        redis,
                        task_id,
                        f"cat {line.strip()} 2>/dev/null",
                    )
                    if content:
                        break
        if content:
            entry_code_contents[ep_file] = content

    # 拼接所有入口代码内容
    all_entry_code = "\n".join(entry_code_contents.values())

    # ── 8. 读取配置文件（用于数据库识别） ──
    config_contents: list[str] = []
    for cfg_file in CONFIG_FILENAMES:
        content = await _exec(
            db,
            redis,
            task_id,
            f"cat {source_dir}/{cfg_file} 2>/dev/null",
        )
        if content:
            config_contents.append(content)

    config_text = "\n".join(config_contents)

    # ── 9. 识别端口 ──
    service_ports = detect_ports(framework, all_entry_code, config_text)

    # ── 10. 识别数据库类型 ──
    db_type = detect_db_type(all_entry_code, config_text, all_dependencies)

    # ── 11. 识别启动命令 ──
    run_command = detect_run_command(language, framework, entry_points)

    # ── 12. 扫描路由 ──
    await _publish(
        redis,
        task_id,
        "recon_progress",
        {"step": "scanning_routes", "message": "正在扫描路由接口..."},
    )

    routes = scan_routes_from_files_dict(language, entry_code_contents)
    route_summary = summarize_routes(routes)

    # ── 13. 组装 raw_result ──
    raw_result = {
        "source_dir": source_dir,
        "file_listing": file_listing,
        "file_count": file_count,
        "file_type_distribution": file_type_dist,
        "total_code_lines": total_lines_raw.strip(),
        "manifest_files": manifest_files_found,
        "manifest_contents_keys": list(manifest_contents.keys()),
        "config_files_found": [cfg for cfg in CONFIG_FILENAMES if cfg in config_text],
        "entry_code_files": list(entry_code_contents.keys()),
        "routes": routes[:50],  # 限制存储量
        "route_summary": route_summary,
        "recon_timestamp": datetime.now(timezone.utc).isoformat(),
    }

    # ── 14. 写入 runtime_profiles 表 ──
    # 先删除旧记录（如果存在），再插入新的
    old_result = await db.execute(
        select(RuntimeProfile).where(RuntimeProfile.task_id == task_id)
    )
    old_profile = old_result.scalar_one_or_none()
    if old_profile:
        await db.delete(old_profile)
        await db.flush()

    # 获取 project_id
    task_result = await db.execute(select(Task).where(Task.id == task_id))
    task = task_result.scalar_one_or_none()
    project_id = task.project_id if task else None

    profile = RuntimeProfile(
        id=generate_id(),
        task_id=task_id,
        project_id=project_id,
        language=language,
        framework=framework,
        dependencies=all_dependencies,
        run_command=run_command,
        service_ports=service_ports,
        entry_points=entry_points,
        db_type=db_type,
        raw_result=raw_result,
    )
    db.add(profile)
    await db.commit()
    await db.refresh(profile)

    # ── 15. 写入日志 ──
    dep_count = len(all_dependencies)
    log_msg = (
        f"环境侦察完成: language={language}, framework={framework}, "
        f"dependencies={dep_count}, entry_points={len(entry_points)}, "
        f"ports={len(service_ports)}, db_type={db_type}, "
        f"routes={route_summary.get('total', 0)}"
    )
    await append_task_log(
        db,
        task_id,
        RECON_PHASE,
        RECON_AGENT,
        "info",
        log_msg,
        detail={
            "language": language,
            "framework": framework,
            "dependency_count": dep_count,
            "entry_points": entry_points,
            "service_ports": service_ports,
            "db_type": db_type,
            "run_command": run_command,
            "route_count": route_summary.get("total", 0),
            "route_summary": route_summary,
            "file_count": file_count,
        },
    )
    await db.commit()

    # ── 16. 发布完成事件 ──
    await _publish(
        redis,
        task_id,
        "recon_completed",
        {
            "runtime_profile_id": profile.id,
            "language": language,
            "framework": framework,
            "dependency_count": dep_count,
            "entry_points": entry_points,
            "service_ports": service_ports,
            "db_type": db_type,
            "run_command": run_command,
            "route_count": route_summary.get("total", 0),
            "route_summary": route_summary,
            "file_count": file_count,
        },
    )

    logger.info(
        f"Recon 完成: task={task_id}, lang={language}, "
        f"fw={framework}, deps={dep_count}, routes={route_summary.get('total', 0)}"
    )

    return profile


def scan_routes_from_files_dict(
    language: str,
    files: dict[str, str],
) -> list[dict]:
    """批量扫描多个文件的路由（内部辅助函数）。

    Args:
        language: 主语言
        files: {filename: content} 字典

    Returns:
        合并后的路由列表
    """
    all_routes: list[dict] = []
    for filename, content in files.items():
        routes = scan_routes(language, content, filename)
        all_routes.extend(routes)
    return all_routes


async def get_runtime_profile(
    db: AsyncSession,
    task_id: str,
) -> RuntimeProfile | None:
    """查询指定任务的 runtime_profile。

    Args:
        db: 数据库会话
        task_id: 任务 ID

    Returns:
        RuntimeProfile 对象或 None
    """
    result = await db.execute(
        select(RuntimeProfile).where(RuntimeProfile.task_id == task_id)
    )
    return result.scalar_one_or_none()
