"""攻击链三件套 ORM 模型。

本模块定义攻击链相关的三张表，用于存储多步攻击路径推演结果：

AttackChain（攻击链主表）：
- id：ULID 主键
- task_id：关联任务 ID
- name：攻击链名称（如"SQL注入获取凭证 -> 后台上传WebShell -> RCE"）
- final_impact：最终危害描述（如"获取宿主机执行权"）
- overall_severity：组合风险等级（critical / high / medium / low）
- overall_cvss：组合 CVSS 评分
- node_count：节点数
- edge_count：边数
- is_single_node：是否为单节点链（单个高危漏洞也需要生成攻击链）
- created_at / updated_at：时间戳

AttackChainNode（攻击链节点）：
- id：ULID 主键
- attack_chain_id：关联攻击链 ID
- finding_id：关联漏洞 ID（外键 -> findings）
- node_id：逻辑节点标识（如 "node-1"）
- label：节点标签（如 "SQL注入获取管理员凭证"）
- asset：所影响资产（如 "/api/order"）
- vuln_type：漏洞类型
- precondition：前置条件（如 "可访问订单接口"）
- post_capability：后置能力（如 "读取数据库用户表"）
- privilege_level：权限变化（如 "anonymous -> admin"）
- node_order：布局辅助序号
- created_at：时间戳

AttackChainEdge（攻击链边）：
- id：ULID 主键
- attack_chain_id：关联攻击链 ID
- source_node_id：源节点 ID（外键 -> attack_chain_nodes）
- target_node_id：目标节点 ID（外键 -> attack_chain_nodes）
- condition：串联条件描述
- action：攻击动作描述
- privilege_escalation：权限跃迁描述（如 "admin -> system"）
- step：步骤序号（1, 2, 3...）
- created_at：时间戳
"""

from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class AttackChain(Base):
    """攻击链主表：一条完整的攻击路径。"""

    __tablename__ = "attack_chains"

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    task_id: Mapped[str] = mapped_column(
        String(26),
        ForeignKey("tasks.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    final_impact: Mapped[str | None] = mapped_column(Text, nullable=True)
    overall_severity: Mapped[str] = mapped_column(
        String(16), nullable=False, default="medium"
    )
    overall_cvss: Mapped[float | None] = mapped_column(Float, nullable=True)
    node_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    edge_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    is_single_node: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
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
    task = relationship("Task", back_populates="attack_chains")
    nodes = relationship(
        "AttackChainNode",
        back_populates="attack_chain",
        lazy="selectin",
        cascade="all, delete-orphan",
        order_by="AttackChainNode.node_order",
    )
    edges = relationship(
        "AttackChainEdge",
        back_populates="attack_chain",
        lazy="selectin",
        cascade="all, delete-orphan",
        order_by="AttackChainEdge.step",
    )


class AttackChainNode(Base):
    """攻击链节点：一个节点对应一个已验证漏洞。"""

    __tablename__ = "attack_chain_nodes"

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    attack_chain_id: Mapped[str] = mapped_column(
        String(26),
        ForeignKey("attack_chains.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    finding_id: Mapped[str] = mapped_column(
        String(26),
        ForeignKey("findings.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    node_id: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    label: Mapped[str] = mapped_column(String(256), nullable=False, default="")
    asset: Mapped[str | None] = mapped_column(String(512), nullable=True)
    vuln_type: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    precondition: Mapped[str | None] = mapped_column(Text, nullable=True)
    post_capability: Mapped[str | None] = mapped_column(Text, nullable=True)
    privilege_level: Mapped[str | None] = mapped_column(String(128), nullable=True)
    node_order: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # ── 关系 ──
    attack_chain = relationship("AttackChain", back_populates="nodes")
    finding = relationship("Finding", back_populates="attack_chain_nodes")
    outgoing_edges = relationship(
        "AttackChainEdge",
        foreign_keys="AttackChainEdge.source_node_id",
        back_populates="source_node",
        lazy="selectin",
    )
    incoming_edges = relationship(
        "AttackChainEdge",
        foreign_keys="AttackChainEdge.target_node_id",
        back_populates="target_node",
        lazy="selectin",
    )


class AttackChainEdge(Base):
    """攻击链边：连接两个节点，表示漏洞之间的串联关系。"""

    __tablename__ = "attack_chain_edges"

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    attack_chain_id: Mapped[str] = mapped_column(
        String(26),
        ForeignKey("attack_chains.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    source_node_id: Mapped[str] = mapped_column(
        String(26),
        ForeignKey("attack_chain_nodes.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    target_node_id: Mapped[str] = mapped_column(
        String(26),
        ForeignKey("attack_chain_nodes.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    condition: Mapped[str | None] = mapped_column(Text, nullable=True)
    action: Mapped[str | None] = mapped_column(Text, nullable=True)
    privilege_escalation: Mapped[str | None] = mapped_column(String(128), nullable=True)
    step: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # ── 关系 ──
    attack_chain = relationship("AttackChain", back_populates="edges")
    source_node = relationship(
        "AttackChainNode",
        foreign_keys=[source_node_id],
        back_populates="outgoing_edges",
    )
    target_node = relationship(
        "AttackChainNode",
        foreign_keys=[target_node_id],
        back_populates="incoming_edges",
    )
