"""运行时画像表 ORM 模型。

RuntimeProfile 表存储环境侦察阶段（recon）的产出，是后续 Code Audit
阶段选择扫描规则的数据依据：

- language：主语言（python / javascript / java / go / php / ruby / unknown）
- framework：主框架（flask / fastapi / django / express / spring-boot / gin / laravel / rails / unknown）
- dependencies：依赖清单与版本（{name: version, ...}）
- run_command：可能的启动命令
- service_ports：服务端口列表（[{"port": 5000, "protocol": "http", "description": "Flask 默认"}, ...]）
- entry_points：入口文件列表（[{"file": "app.py", "type": "wsgi_app", "line": 15}, ...]）
- db_type：数据库类型（postgresql / mysql / sqlite / mongodb / redis / not_detected）
- raw_result：完整侦察结果（文件列表、文件类型分布、代码行数等）
- created_at / updated_at：时间戳
"""

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class RuntimeProfile(Base):
    """运行时画像表。"""

    __tablename__ = "runtime_profiles"

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    task_id: Mapped[str] = mapped_column(
        String(26),
        ForeignKey("tasks.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    project_id: Mapped[str | None] = mapped_column(
        String(26),
        ForeignKey("projects.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    language: Mapped[str] = mapped_column(String(64), nullable=False, default="unknown")
    framework: Mapped[str] = mapped_column(
        String(128), nullable=False, default="unknown"
    )
    dependencies: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    run_command: Mapped[str | None] = mapped_column(String(512), nullable=True)
    service_ports: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    entry_points: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    db_type: Mapped[str] = mapped_column(
        String(64), nullable=False, default="not_detected"
    )
    raw_result: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
