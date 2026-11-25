"""源码快照服务模块。

本模块封装源码快照的管理逻辑：
- create_snapshot_from_archive(project_id, zip_path)：解压 ZIP 到快照目录
- create_snapshot_from_git(project_id, git_url, ref)：克隆 Git 仓库到快照目录
- get_snapshot(snapshot_id)：获取快照信息
- get_snapshot_path(snapshot_id)：获取快照磁盘路径
- list_snapshots(project_id)：列出项目的所有快照
- delete_snapshot(snapshot_id)：删除快照（物理删除）
- create_snapshot_from_local_path(...)：从本机文件或文件夹复制创建快照
"""

import asyncio
import hashlib
import os
import shutil
import zipfile
from collections import Counter
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.errors import ProjectNotFoundError, SnapshotNotFoundError
from app.models import Project, SourceSnapshot
from app.services.audit_service import log_action
from app.utils import ensure_dir, generate_id

settings = get_settings()

# ── 语言识别映射（扩展名 → 语言名）──
EXT_LANGUAGE_MAP: dict[str, str] = {
    ".py": "Python",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".java": "Java",
    ".go": "Go",
    ".rs": "Rust",
    ".c": "C",
    ".h": "C",
    ".cpp": "C++",
    ".cc": "C++",
    ".cxx": "C++",
    ".hpp": "C++",
    ".cs": "C#",
    ".rb": "Ruby",
    ".php": "PHP",
    ".swift": "Swift",
    ".kt": "Kotlin",
    ".scala": "Scala",
    ".sh": "Shell",
    ".bash": "Shell",
    ".html": "HTML",
    ".css": "CSS",
    ".scss": "SCSS",
    ".less": "LESS",
    ".vue": "Vue",
    ".svelte": "Svelte",
    ".sql": "SQL",
    ".xml": "XML",
    ".yml": "YAML",
    ".yaml": "YAML",
    ".json": "JSON",
    ".toml": "TOML",
    ".md": "Markdown",
    ".txt": "Text",
    ".dockerfile": "Dockerfile",
}

# 忽略的目录名
IGNORE_DIRS: set[str] = {
    ".git",
    ".svn",
    ".hg",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    ".idea",
    ".vscode",
    "dist",
    "build",
    ".next",
    ".nuxt",
    "target",
    ".gradle",
}

# 单文件最大读取行数（防止超大文件拖慢统计）
MAX_LINES_PER_FILE = 500_000


def _is_ignored_dir(dirpath: str) -> bool:
    """判断目录是否应被忽略。"""
    parts = dirpath.replace("\\", "/").split("/")
    return any(p in IGNORE_DIRS for p in parts)


def _count_directory(root_path: str) -> dict:
    """统计目录下文件数、行数、语言分布。

    Returns:
        dict: {
            "file_count": int,
            "line_count": int,
            "total_size_bytes": int,
            "language_stats": {lang: {"files": int, "lines": int}},
        }
    """
    file_count = 0
    line_count = 0
    total_size = 0
    lang_counter: Counter = Counter()

    for dirpath, dirnames, filenames in os.walk(root_path):
        # 原地过滤被忽略的目录（阻止 walk 继续遍历它们）
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS]

        if _is_ignored_dir(dirpath):
            continue

        for fname in filenames:
            fpath = os.path.join(dirpath, fname)
            try:
                fsize = os.path.getsize(fpath)
            except OSError:
                continue

            file_count += 1
            total_size += fsize

            ext = os.path.splitext(fname)[1].lower()
            lang = EXT_LANGUAGE_MAP.get(ext)

            if lang:
                # 统计行数（仅文本文件）
                lines = 0
                try:
                    with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                        for i, _ in enumerate(f):
                            if i >= MAX_LINES_PER_FILE:
                                break
                            lines += 1
                except (OSError, PermissionError):
                    pass

                line_count += lines
                lang_counter[lang] += lines

    # 构建语言分布字典
    language_stats = {
        lang: {"lines": lines} for lang, lines in lang_counter.most_common(20)
    }

    return {
        "file_count": file_count,
        "line_count": line_count,
        "total_size_bytes": total_size,
        "language_stats": language_stats,
    }


def _compute_directory_checksum(root_path: str) -> str:
    """计算目录下所有文件的 SHA-256 汇总哈希。

    对每个文件的相对路径 + 内容摘要再取哈希，保证目录结构变更也能感知。
    """
    sha = hashlib.sha256()
    for dirpath, dirnames, filenames in os.walk(root_path):
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS]
        if _is_ignored_dir(dirpath):
            continue
        for fname in sorted(filenames):
            fpath = os.path.join(dirpath, fname)
            rel_path = os.path.relpath(fpath, root_path).replace("\\", "/")
            sha.update(rel_path.encode("utf-8"))
            try:
                with open(fpath, "rb") as f:
                    while chunk := f.read(65536):
                        sha.update(chunk)
            except (OSError, PermissionError):
                pass
    return sha.hexdigest()


def _extract_zip_safely(zip_path: str, snapshot_dir: str) -> None:
    """安全解压 ZIP，禁止路径穿越和绝对路径写入。"""
    root = os.path.realpath(snapshot_dir)
    with zipfile.ZipFile(zip_path, "r") as zf:
        for member in zf.infolist():
            member_path = member.filename.replace("\\", "/")
            if (
                member_path.startswith("/")
                or ".." in member_path.split("/")
                or (len(member_path) > 1 and member_path[1] == ":")
            ):
                raise ValueError(f"检测到不安全的 ZIP 成员: {member.filename}")

            target = os.path.realpath(os.path.join(root, member_path))
            if target != root and not target.startswith(root + os.sep):
                raise ValueError(f"检测到路径穿越攻击: {member.filename}")

        zf.extractall(snapshot_dir)


async def _run_subprocess(
    cmd: list[str],
    cwd: str | None = None,
    timeout: float = 120,
) -> tuple[int, str, str]:
    """异步执行子进程，返回 (returncode, stdout, stderr)。"""
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=cwd,
        env=env,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise RuntimeError(f"命令执行超时: {' '.join(cmd[:3])}") from None
    return (
        proc.returncode or 0,
        stdout.decode("utf-8", errors="replace") if stdout else "",
        stderr.decode("utf-8", errors="replace") if stderr else "",
    )


async def create_snapshot_from_archive(
    db: AsyncSession,
    project_id: str,
    zip_path: str,
    operator: str = "admin",
) -> SourceSnapshot:
    """从上传的 ZIP 压缩包创建源码快照。

    Args:
        db: 数据库会话
        project_id: 项目 ID
        zip_path: ZIP 文件磁盘路径
        operator: 操作人

    Returns:
        SourceSnapshot: 创建的快照记录
    """
    project = await db.get(Project, project_id)
    if project is None:
        raise ProjectNotFoundError(project_id)

    snapshot_id = generate_id()
    snapshot_dir = os.path.abspath(os.path.join(settings.SNAPSHOT_DIR, snapshot_id))
    ensure_dir(snapshot_dir)

    # 解压 ZIP
    try:
        _extract_zip_safely(zip_path, snapshot_dir)
    except (zipfile.BadZipFile, ValueError) as e:
        shutil.rmtree(snapshot_dir, ignore_errors=True)
        raise ValueError(f"ZIP 文件无效: {e}") from e

    # 查找解压后的根目录（有些 ZIP 解压后会多一层包裹目录）
    entries = os.listdir(snapshot_dir)
    if len(entries) == 1 and os.path.isdir(os.path.join(snapshot_dir, entries[0])):
        actual_root = os.path.join(snapshot_dir, entries[0])
    else:
        actual_root = snapshot_dir

    # 统计文件
    stats = _count_directory(actual_root)
    checksum = _compute_directory_checksum(actual_root)

    snapshot = SourceSnapshot(
        id=snapshot_id,
        project_id=project_id,
        snapshot_path=actual_root,
        commit_id=None,
        file_count=stats["file_count"],
        total_size_kb=stats["total_size_bytes"] // 1024,
        line_count=stats["line_count"],
        checksum=checksum,
        language_stats=stats["language_stats"],
    )
    db.add(snapshot)

    # 更新项目的 commit_id 字段（ZIP 来源无 commit）
    project.source_type = "archive"

    await db.flush()
    await db.commit()
    return snapshot


async def create_snapshot_from_git(
    db: AsyncSession,
    project_id: str,
    git_url: str,
    ref: str | None = None,
    operator: str = "admin",
) -> SourceSnapshot:
    """从 Git 仓库克隆创建源码快照。

    Args:
        db: 数据库会话
        project_id: 项目 ID
        git_url: Git 仓库 URL
        ref: 分支/tag/commit（可选，默认用默认分支）
        operator: 操作人

    Returns:
        SourceSnapshot: 创建的快照记录
    """
    project = await db.get(Project, project_id)
    if project is None:
        raise ProjectNotFoundError(project_id)

    allowed_prefixes = ("https://", "http://", "ssh://", "git@")
    if not git_url.startswith(allowed_prefixes):
        raise ValueError("Git 地址仅支持 http/https/ssh/git@ 协议")

    snapshot_id = generate_id()
    snapshot_dir = os.path.abspath(os.path.join(settings.SNAPSHOT_DIR, snapshot_id))
    ensure_dir(snapshot_dir)

    # git clone（浅克隆 --depth 1 提升速度）
    clone_cmd = ["git", "clone", "--depth", "1"]
    if ref:
        clone_cmd.extend(["--branch", ref])
    clone_cmd.extend([git_url, snapshot_dir])

    returncode, stdout, stderr = await _run_subprocess(
        clone_cmd, timeout=settings.GIT_CLONE_TIMEOUT_SECS
    )
    if returncode != 0:
        shutil.rmtree(snapshot_dir, ignore_errors=True)
        raise RuntimeError(f"Git 克隆失败: {stderr or stdout}")

    # 获取 commit ID
    commit_id = None
    returncode, stdout, _ = await _run_subprocess(
        ["git", "rev-parse", "HEAD"], cwd=snapshot_dir
    )
    if returncode == 0:
        commit_id = stdout.strip()

    # 统计文件
    stats = _count_directory(snapshot_dir)
    checksum = _compute_directory_checksum(snapshot_dir)

    snapshot = SourceSnapshot(
        id=snapshot_id,
        project_id=project_id,
        snapshot_path=snapshot_dir,
        commit_id=commit_id,
        file_count=stats["file_count"],
        total_size_kb=stats["total_size_bytes"] // 1024,
        line_count=stats["line_count"],
        checksum=checksum,
        language_stats=stats["language_stats"],
    )
    db.add(snapshot)

    # 更新项目信息
    project.source_type = "git"
    project.commit_id = commit_id
    project.source_ref = ref

    await db.flush()
    await db.commit()
    return snapshot


async def create_snapshot_from_local_path(
    db: AsyncSession,
    project_id: str,
    local_path: str,
    operator: str = "admin",
) -> SourceSnapshot:
    """从本机可访问的文件或文件夹复制创建源码快照。

    路径可以是单个源码文件，也可以是包含多个源码文件的目录。
    系统会根据路径类型更新项目 source_type，并复制到受管理的快照目录。
    """
    project = await db.get(Project, project_id)
    if project is None:
        raise ProjectNotFoundError(project_id)

    raw_path = os.path.abspath(os.path.expanduser(local_path.strip()))
    for managed_dir in (
        settings.SNAPSHOT_DIR,
        settings.REPORT_OUTPUT_DIR,
        settings.UPLOAD_DIR,
    ):
        base = os.path.abspath(managed_dir)
        try:
            inside_managed = os.path.commonpath([base, raw_path]) == base
        except ValueError:
            inside_managed = False
        if inside_managed:
            raise ValueError("不能导入系统快照、报告或上传目录")
    if not os.path.exists(raw_path):
        raise ValueError(f"本地路径不存在: {raw_path}")
    if not os.path.isfile(raw_path) and not os.path.isdir(raw_path):
        raise ValueError(f"本地路径既不是文件也不是文件夹: {raw_path}")

    snapshot_id = generate_id()
    snapshot_root = os.path.abspath(settings.SNAPSHOT_DIR)
    snapshot_dir = os.path.join(snapshot_root, snapshot_id)
    ensure_dir(snapshot_root)

    try:
        if os.path.isdir(raw_path):
            shutil.copytree(
                raw_path,
                snapshot_dir,
                ignore=shutil.ignore_patterns(*IGNORE_DIRS),
            )
            actual_root = snapshot_dir
            source_kind = "directory"
        elif os.path.splitext(raw_path)[1].lower() == ".zip":
            # ZIP 文件按压缩包处理，而不是当作单源码文件复制。
            return await create_snapshot_from_archive(
                db,
                project_id,
                raw_path,
                operator,
            )
        else:
            ensure_dir(snapshot_dir)
            filename = os.path.basename(raw_path)
            target_file = os.path.join(snapshot_dir, filename)
            if os.path.exists(target_file):
                name, ext = os.path.splitext(filename)
                target_file = os.path.join(snapshot_dir, f"{name}_1{ext}")
            shutil.copy2(raw_path, target_file)
            actual_root = snapshot_dir
            source_kind = "file"

        stats = _count_directory(actual_root)
        checksum = _compute_directory_checksum(actual_root)
    except (OSError, shutil.Error) as e:
        shutil.rmtree(snapshot_dir, ignore_errors=True)
        raise ValueError(f"本地路径读取失败: {e}") from e

    snapshot = SourceSnapshot(
        id=snapshot_id,
        project_id=project_id,
        snapshot_path=actual_root,
        commit_id=None,
        file_count=stats["file_count"],
        total_size_kb=stats["total_size_bytes"] // 1024,
        line_count=stats["line_count"],
        checksum=checksum,
        language_stats=stats["language_stats"],
    )
    db.add(snapshot)

    project.source_type = source_kind
    project.source_input = raw_path

    await log_action(
        db,
        action="create",
        operator=operator,
        target_type="source_snapshot",
        target_id=snapshot_id,
        project_id=project_id,
        detail={
            "source_kind": source_kind,
            "local_path": raw_path,
            "file_count": stats["file_count"],
            "line_count": stats["line_count"],
        },
    )
    await db.flush()
    await db.commit()
    return snapshot


async def get_snapshot(db: AsyncSession, snapshot_id: str) -> SourceSnapshot | None:
    """获取快照信息。"""
    return await db.get(SourceSnapshot, snapshot_id)


async def get_snapshot_by_id(db: AsyncSession, snapshot_id: str) -> SourceSnapshot:
    """获取快照或抛 404。"""
    snapshot = await get_snapshot(db, snapshot_id)
    if snapshot is None:
        raise SnapshotNotFoundError(snapshot_id)
    return snapshot


async def get_snapshot_path(db: AsyncSession, snapshot_id: str) -> str:
    """获取快照磁盘路径。"""
    snapshot = await get_snapshot_by_id(db, snapshot_id)
    return snapshot.snapshot_path


async def list_snapshots(
    db: AsyncSession,
    project_id: str,
    page: int = 1,
    size: int = 20,
) -> dict:
    """列出项目的所有快照（分页）。"""
    from app.utils import paginate

    stmt = (
        select(SourceSnapshot)
        .where(SourceSnapshot.project_id == project_id)
        .order_by(SourceSnapshot.created_at.desc())
    )
    return await paginate(db, stmt, page, size)


async def delete_snapshot(
    db: AsyncSession,
    snapshot_id: str,
    project_id: str | None = None,
    operator: str = "admin",
) -> None:
    """物理删除快照（磁盘 + 数据库）。"""
    snapshot = await get_snapshot_by_id(db, snapshot_id)
    if project_id and snapshot.project_id != project_id:
        raise SnapshotNotFoundError(snapshot_id)

    # 删除磁盘文件
    if os.path.isdir(snapshot.snapshot_path):
        shutil.rmtree(snapshot.snapshot_path, ignore_errors=True)

    await log_action(
        db,
        action="delete",
        operator=operator,
        target_type="source_snapshot",
        target_id=snapshot_id,
        project_id=snapshot.project_id,
    )
    await db.delete(snapshot)
    await db.commit()
