"""攻击链请求/响应模型。

本模块定义攻击链的 API 请求与响应模型：

- AttackChainNodeCreate：节点创建模型（内部使用）
- AttackChainEdgeCreate：边创建模型（内部使用）
- AttackChainNodeResponse：节点详情响应
- AttackChainEdgeResponse：边详情响应
- AttackChainResponse：攻击链完整响应（nodes + edges + finalImpact + overallSeverity）
- AttackChainListResponse：攻击链列表响应

攻击链以有向无环图（DAG）形式呈现，前端用于可视化展示。
"""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class AttackChainNodeResponse(BaseModel):
    """攻击链节点详情响应。"""

    id: str = Field(..., description="节点记录 ID")
    attack_chain_id: str = Field(..., description="所属攻击链 ID")
    finding_id: str = Field(..., description="关联漏洞 ID")
    node_id: str = Field(..., description="逻辑节点标识，如 node-1")
    label: str = Field(..., description="节点标签，如 SQL注入获取管理员凭证")
    asset: str | None = Field(None, description="所影响资产，如 /api/order")
    vuln_type: str = Field(..., description="漏洞类型")
    precondition: str | None = Field(None, description="前置条件，如 可访问订单接口")
    post_capability: str | None = Field(
        None, description="后置能力，如 读取数据库用户表"
    )
    privilege_level: str | None = Field(
        None, description="权限变化，如 anonymous -> admin"
    )
    node_order: int = Field(0, description="布局辅助序号")
    created_at: datetime | None = None

    class Config:
        from_attributes = True


class AttackChainEdgeResponse(BaseModel):
    """攻击链边详情响应。"""

    id: str = Field(..., description="边记录 ID")
    attack_chain_id: str = Field(..., description="所属攻击链 ID")
    source_node_id: str = Field(..., description="源节点 ID")
    target_node_id: str = Field(..., description="目标节点 ID")
    condition: str | None = Field(None, description="串联条件描述")
    action: str | None = Field(None, description="攻击动作描述")
    privilege_escalation: str | None = Field(
        None, description="权限跃迁描述，如 admin -> system"
    )
    step: int = Field(1, description="步骤序号")
    created_at: datetime | None = None

    class Config:
        from_attributes = True


class AttackChainResponse(BaseModel):
    """攻击链完整响应。"""

    id: str = Field(..., description="攻击链 ID")
    task_id: str = Field(..., description="任务 ID")
    name: str = Field("", description="攻击链名称")
    final_impact: str | None = Field(None, description="最终危害描述")
    overall_severity: str = Field(
        "medium", description="组合风险等级: critical/high/medium/low"
    )
    overall_cvss: float | None = Field(None, description="组合 CVSS 评分")
    node_count: int = Field(0, description="节点数")
    edge_count: int = Field(0, description="边数")
    is_single_node: bool = Field(False, description="是否为单节点链")
    nodes: list[AttackChainNodeResponse] = Field(
        default_factory=list, description="节点列表"
    )
    edges: list[AttackChainEdgeResponse] = Field(
        default_factory=list, description="边列表"
    )
    created_at: datetime | None = None
    updated_at: datetime | None = None

    class Config:
        from_attributes = True


class AttackChainListResponse(BaseModel):
    """攻击链列表响应。"""

    items: list[AttackChainResponse]
    total: int


class AttackChainNodeCreate(BaseModel):
    """节点创建模型（内部使用）。"""

    finding_id: str
    node_id: str
    label: str
    asset: str | None = None
    vuln_type: str = ""
    precondition: str | None = None
    post_capability: str | None = None
    privilege_level: str | None = None
    node_order: int = 0


class AttackChainEdgeCreate(BaseModel):
    """边创建模型（内部使用）。"""

    source_node_id: str
    target_node_id: str
    condition: str | None = None
    action: str | None = None
    privilege_escalation: str | None = None
    step: int = 1
