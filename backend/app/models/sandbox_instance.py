"""沙箱实例表 ORM 模型。

SandboxInstance 表记录每个任务关联的 Docker 沙箱容器全生命周期信息：
- 容器 ID、镜像、网络模式、资源限制
- 源码挂载路径、临时可写目录
- 状态流转（creating -> ready -> running -> destroying -> destroyed）
- 创建时间、就绪时间、销毁时间
"""

from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class SandboxInstance(Base):
    __tablename__ = "sandbox_instances"

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    task_id: Mapped[str] = mapped_column(
        String(26),
        ForeignKey("tasks.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    container_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    container_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    image: Mapped[str] = mapped_column(String(256), nullable=False)
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="creating", index=True
    )
    network_mode: Mapped[str] = mapped_column(
        String(32), nullable=False, default="none"
    )
    memory_limit: Mapped[str | None] = mapped_column(String(32), nullable=True)
    cpu_limit: Mapped[int | None] = mapped_column(Integer, nullable=True)
    pid_limit: Mapped[int | None] = mapped_column(Integer, nullable=True)
    timeout_secs: Mapped[int] = mapped_column(Integer, nullable=False, default=1800)
    mount_source: Mapped[str | None] = mapped_column(String(512), nullable=True)
    mount_target: Mapped[str] = mapped_column(
        String(256), nullable=False, default="/workspace/source"
    )
    tmp_dir: Mapped[str] = mapped_column(
        String(256), nullable=False, default="/workspace/tmp"
    )
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error_message: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    resource_usage: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    ready_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    destroyed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # -- relations --
    task = relationship("Task", back_populates="sandbox_instances")
