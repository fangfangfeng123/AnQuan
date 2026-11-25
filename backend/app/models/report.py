"""安全评估报告表 ORM 模型。

Report 表存储每次评估任务生成的完整安全审计报告。
- sections（JSONB）：5 个章节的结构化数据，可直接给前端或模板渲染
- 文件版本化：每次重新生成 version+1，不覆盖旧文件
- 外键级联删除：task/project 删除时报告自动清除
"""

from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class Report(Base):
    """安全评估报告。

    每个评估任务对应至少一份报告（可多版本）。
    报告内容以 JSONB 结构化存储，包含 5 个章节：
    1. 执行摘要（executive_summary）
    2. 评估范围（scope）
    3. 漏洞详情（findings）
    4. 攻击链分析（attack_chains）
    5. 修复建议（remediation）
    """

    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    task_id: Mapped[str] = mapped_column(
        String(26),
        ForeignKey("tasks.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    project_id: Mapped[str] = mapped_column(
        String(26),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # 章节内容（结构化 JSONB，5 个章节的完整数据）
    sections: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # 统计信息
    total_findings: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    critical_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    high_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    medium_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    low_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    info_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # 整体风险评级（critical/high/medium/low/secure）
    overall_risk: Mapped[str] = mapped_column(
        String(16), nullable=False, default="secure"
    )
    overall_cvss: Mapped[float | None] = mapped_column(Float, nullable=True)

    # 生成文件路径
    markdown_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    html_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    pdf_path: Mapped[str | None] = mapped_column(String(512), nullable=True)

    # 版本号（每次重新生成 +1）
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    # 时间戳
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
