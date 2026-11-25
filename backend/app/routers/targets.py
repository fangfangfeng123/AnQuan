"""内置靶场只读目录接口。"""

import os
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, Depends

from app.core.security import get_current_user
from app.schemas.target import TargetItemResponse, TargetListResponse

router = APIRouter(prefix="/targets", tags=["内置靶场"])

IGNORED_DIRS = {
    "__pycache__",
    ".git",
    ".idea",
    ".vscode",
    "node_modules",
    ".venv",
    "venv",
}


def _targets_root() -> Path:
    """定位仓库根目录下的 targets 目录。"""
    candidates = [
        Path(__file__).resolve().parents[3] / "targets",
        Path.cwd() / "targets",
        Path.cwd().parent / "targets",
    ]
    for candidate in candidates:
        if candidate.is_dir():
            return candidate
    return candidates[0]


def _count_directory(root: Path) -> tuple[int, int]:
    """递归统计文件数和大小，跳过缓存与依赖目录。"""
    file_count = 0
    total_size = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS]
        for filename in filenames:
            file_path = os.path.join(dirpath, filename)
            try:
                total_size += os.path.getsize(file_path)
            except OSError:
                pass
            file_count += 1
    return file_count, total_size


def _item_kind(path: Path) -> str:
    if path.is_dir():
        return "directory"
    if path.suffix.lower() == ".zip":
        return "archive"
    return "file"


def _list_target_items() -> list[dict]:
    root = _targets_root()
    if not root.is_dir():
        return []

    items = []
    for entry in sorted(root.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())):
        if entry.name.startswith(".") or entry.name in IGNORED_DIRS:
            continue
        kind = _item_kind(entry)
        if kind == "directory":
            file_count, total_size = _count_directory(entry)
        else:
            file_count = 1
            try:
                total_size = entry.stat().st_size
            except OSError:
                total_size = 0
        try:
            mtime = datetime.fromtimestamp(entry.stat().st_mtime)
        except OSError:
            mtime = None
        items.append(
            {
                "name": entry.name,
                "kind": kind,
                "path": str(entry.resolve()),
                "file_count": file_count,
                "total_size_kb": total_size // 1024,
                "updated_at": mtime,
            }
        )
    return items


@router.get("", response_model=TargetListResponse)
async def list_targets(
    _operator: str = Depends(get_current_user),
) -> TargetListResponse:
    """返回内置靶场根目录下的文件夹和文件列表。"""
    root = _targets_root()
    return TargetListResponse(
        root_path=str(root.resolve()),
        items=[TargetItemResponse(**item) for item in _list_target_items()],
    )
