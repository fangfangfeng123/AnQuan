"""源码快照表 ORM 模型。

SourceSnapshot 表记录每次评估时拉取的源码快照。
"""

from datetime import datetime

from sqlalchemy import BigInteger, DateTime, ForeignKey, Integer, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class SourceSnapshot(Base):
    __tablename__ = "source_snapshots"

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    project_id: Mapped[str] = mapped_column(
        String(26),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    snapshot_path: Mapped[str] = mapped_column(String(512), nullable=False)
    commit_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    file_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    total_size_kb: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    line_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    checksum: Mapped[str | None] = mapped_column(String(64), nullable=True)
    language_stats: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # ── 关系 ──
    project = relationship("Project", back_populates="source_snapshots")
    tasks = relationship("Task", back_populates="source_snapshot")
