"""修复补丁表 ORM 模型。

FixPatch 表存储 AI 生成的漏洞修复补丁（与 Finding 一对一）：
- id：ULID 主键
- finding_id：关联漏洞 ID（外键，一对一）
- task_id：任务 ID（冗余索引，便于按任务批量查询）
- original_code：原始漏洞代码
- patched_code：修复后代码
- diff_content：统一 diff 格式内容
- description：补丁说明（AI 生成的修改理由）
- adopt_status：采纳状态（pending / adopted / rejected / superseded）
- validated：是否通过校验（bool）
- validation_result：校验结果 JSONB（语法检查 / 编译检查 / 安全回归）
- llm_model：生成此补丁的 LLM 模型名
- token_usage：消耗的 token 数
- created_at / updated_at：时间戳
"""

from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class FixPatch(Base):
    """修复补丁表。

    一个补丁对应一个 finding（一对一），记录 AI 生成的修复代码、
    Diff、校验结果和采纳状态，形成"发现 -> 验证 -> 修复"闭环。
    """

    __tablename__ = "fix_patches"

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    finding_id: Mapped[str] = mapped_column(
        String(26),
        ForeignKey("findings.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )
    task_id: Mapped[str] = mapped_column(
        String(26),
        ForeignKey("tasks.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # 代码内容
    original_code: Mapped[str | None] = mapped_column(Text, nullable=True)
    patched_code: Mapped[str | None] = mapped_column(Text, nullable=True)
    diff_content: Mapped[str | None] = mapped_column(Text, nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # 采纳状态
    adopt_status: Mapped[str] = mapped_column(
        String(16), nullable=False, default="pending"
    )  # pending / adopted / rejected / superseded

    # 校验结果
    validated: Mapped[bool] = mapped_column(
        Integer, nullable=False, default=0
    )  # SQLite 兼容：0/1
    validation_result: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    # validation_result 结构：
    # {
    #   "syntax": {"passed": true, "errors": []},
    #   "compile": {"passed": true, "errors": []},
    #   "security_regression": {"passed": true, "original_vuln_fixed": true, "new_findings": []}
    # }

    # LLM 记录
    llm_model: Mapped[str | None] = mapped_column(String(128), nullable=True)
    token_usage: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # 时间戳
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # ── 关系 ──
    finding = relationship("Finding", back_populates="fix_patch")
