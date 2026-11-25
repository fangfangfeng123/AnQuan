"""评估任务表 ORM 模型。

Task 表存储安全评估任务的全生命周期状态。
"""

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class Task(Base):
    __tablename__ = "tasks"

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    project_id: Mapped[str] = mapped_column(
        String(26),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    source_snapshot_id: Mapped[str | None] = mapped_column(
        String(26),
        ForeignKey("source_snapshots.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    sandbox_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="created", index=True
    )
    current_phase: Mapped[str | None] = mapped_column(String(32), nullable=True)
    phase_status: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        default=lambda: {
            "recon": "pending",
            "code_audit": "pending",
            "poc_verify": "pending",
            "exploit_chain": "pending",
            "report_gen": "pending",
        },
    )
    overall_progress: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    overall_risk: Mapped[str | None] = mapped_column(String(32), nullable=True)
    sandbox_image: Mapped[str | None] = mapped_column(String(256), nullable=True)
    network_mode: Mapped[str] = mapped_column(
        String(32), nullable=False, default="restricted"
    )
    timeout_secs: Mapped[int] = mapped_column(Integer, nullable=False, default=1800)
    llm_mode: Mapped[str] = mapped_column(String(32), nullable=False, default="demo")
    max_concurrent: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    is_archived: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    resource_usage: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    ended_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # ── 关系 ──
    project = relationship("Project", back_populates="tasks")
    source_snapshot = relationship("SourceSnapshot", back_populates="tasks")
    findings = relationship("Finding", back_populates="task", lazy="selectin")
    task_logs = relationship("TaskLog", back_populates="task", lazy="selectin")
    sandbox_instances = relationship(
        "SandboxInstance", back_populates="task", lazy="selectin"
    )
    attack_chains = relationship("AttackChain", back_populates="task", lazy="selectin")
