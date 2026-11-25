"""漏洞表 ORM 模型。

Finding 表存储扫描和验证后发现的安全漏洞。
"""

from datetime import datetime, timezone

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    task_id: Mapped[str] = mapped_column(
        String(26),
        ForeignKey("tasks.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    vuln_type: Mapped[str] = mapped_column(String(64), nullable=False)
    cwe_id: Mapped[str | None] = mapped_column(String(16), nullable=True)
    owasp: Mapped[str | None] = mapped_column(String(32), nullable=True)
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="unverified", index=True
    )
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="info")
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(128), nullable=True)
    # 漏洞触发位置（统一路径+行号范围，便于前端跳转）
    file_path: Mapped[str | None] = mapped_column(
        String(512), nullable=True, index=True
    )
    line_start: Mapped[int | None] = mapped_column(Integer, nullable=True)
    line_end: Mapped[int | None] = mapped_column(Integer, nullable=True)
    snippet: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Source / Sink 详细信息
    source_file: Mapped[str | None] = mapped_column(String(512), nullable=True)
    source_line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    source_code: Mapped[str | None] = mapped_column(Text, nullable=True)
    sink_file: Mapped[str | None] = mapped_column(String(512), nullable=True)
    sink_line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    sink_code: Mapped[str | None] = mapped_column(Text, nullable=True)
    taint_path: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    code_context: Mapped[str | None] = mapped_column(Text, nullable=True)
    detected_by: Mapped[str] = mapped_column(
        String(64), nullable=False, default="semgrep"
    )
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
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
    task = relationship("Task", back_populates="findings")
    poc_evidences = relationship(
        "PocEvidence", back_populates="finding", lazy="selectin"
    )
    attack_chain_nodes = relationship(
        "AttackChainNode", back_populates="finding", lazy="selectin"
    )
    fix_patch = relationship(
        "FixPatch", back_populates="finding", uselist=False, lazy="selectin"
    )
