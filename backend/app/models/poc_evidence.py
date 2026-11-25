"""PoC 证据表 ORM 模型。

PocEvidence 表存储漏洞动态验证的完整证据链：
- id：ULID 主键
- finding_id：关联漏洞 ID（外键，多对一）
- task_id：任务 ID（冗余索引，便于按任务批量查询）
- poc_type：PoC 类型（http / command / file_read / dns / timing）
- request_method：HTTP 方法或命令类型
- request_url：请求 URL
- request_headers：请求头 JSONB
- request_body：请求体
- response_status：HTTP 状态码或命令退出码
- response_headers：响应头 JSONB
- response_body：响应体或命令输出
- expected_feature：预期匹配特征描述
- actual_feature：实际观察到的特征
- matched：是否匹配成功（True 表示漏洞已确认）
- validation_status：验证状态（passed / failed / error）
- error_message：执行异常信息
- executed_at：探针执行时间
- verified_at：验证完成时间
- created_at：记录创建时间
"""

from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class PocEvidence(Base):
    __tablename__ = "poc_evidence"

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    finding_id: Mapped[str] = mapped_column(
        String(26),
        ForeignKey("findings.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    task_id: Mapped[str] = mapped_column(
        String(26),
        ForeignKey("tasks.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    poc_type: Mapped[str] = mapped_column(String(32), nullable=False, default="http")

    # 请求信息
    request_method: Mapped[str | None] = mapped_column(String(16), nullable=True)
    request_url: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    request_headers: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    request_body: Mapped[str | None] = mapped_column(Text, nullable=True)

    # 响应信息
    response_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    response_headers: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    response_body: Mapped[str | None] = mapped_column(Text, nullable=True)

    # 验证结果
    expected_feature: Mapped[str | None] = mapped_column(Text, nullable=True)
    actual_feature: Mapped[str | None] = mapped_column(Text, nullable=True)
    matched: Mapped[bool] = mapped_column(
        Integer, nullable=False, default=0
    )  # SQLite 兼容：0/1
    validation_status: Mapped[str] = mapped_column(
        String(16), nullable=False, default="pending"
    )
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    # 时间戳
    executed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    # ── 关系 ──
    finding = relationship("Finding", back_populates="poc_evidences")
