"""攻击链构建器模块。

本模块是攻击链推演的核心引擎，负责将多个已验证漏洞组合成攻击路径：

流程：
1. 读取当前任务中状态为 verified 的漏洞（低危、潜在隐患和未验证漏洞不能作为攻击链核心节点）
2. 为每个漏洞生成攻击链节点（前置条件 + 后置能力 + 权限级别）
3. 根据串联规则判断漏洞能否串联（上一个漏洞的后置能力是否满足下一个漏洞的前置条件）
4. 如果可以串联则生成有向边
5. 检查是否存在环路，确保结果是 DAG（有向无环图）
6. 计算每条链的最终影响和组合风险等级
7. 单个高危漏洞也生成单节点攻击链

输出：
- AttackChain 列表（含节点和边）
- 每条链的最终影响和组合风险等级
"""

import logging
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.chain.rules import (
    VulnTypeProfile,
    calculate_chain_severity,
    calculate_final_impact,
    can_chain,
    get_vuln_profile,
    parse_privilege_pair,
    privilege_rank,
)
from app.models import AttackChain, AttackChainEdge, AttackChainNode, Finding
from app.utils import generate_id

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────
# 中间数据结构
# ──────────────────────────────────────────────────────


@dataclass
class NodeInfo:
    """节点中间表示（尚未持久化）。"""

    finding_id: str
    vuln_type: str
    label: str
    asset: str | None
    precondition: str | None
    post_capability: str | None
    privilege_level: str | None
    node_order: int = 0
    # 持久化后的 ID（由 builder 赋值）
    db_id: str | None = None
    # 逻辑节点标识
    logical_id: str = ""


@dataclass
class EdgeInfo:
    """边中间表示（尚未持久化）。"""

    source_node_id: str
    target_node_id: str
    condition: str
    action: str
    privilege_escalation: str
    step: int


@dataclass
class ChainBuildResult:
    """一条攻击链的构建结果（含节点和边的中间表示）。"""

    name: str
    nodes: list[NodeInfo] = field(default_factory=list)
    edges: list[EdgeInfo] = field(default_factory=list)
    final_impact: str = ""
    overall_severity: str = "medium"
    overall_cvss: float | None = None
    is_single_node: bool = False
    # 用于持久化的 ORM 对象（由 build_orm 填充）
    chain_orm: AttackChain | None = None


# ──────────────────────────────────────────────────────
# 节点生成
# ──────────────────────────────────────────────────────


def _generate_node(
    finding: Finding,
    node_order: int,
) -> NodeInfo:
    """为单个已验证漏洞生成攻击链节点。

    根据漏洞类型从 rules.py 获取默认属性，并用 finding 的实际信息覆盖。

    Args:
        finding: 已验证漏洞 ORM 对象
        node_order: 节点序号

    Returns:
        NodeInfo 中间表示
    """
    profile = get_vuln_profile(finding.vuln_type)

    # 从 finding 提取资产信息
    asset = finding.file_path or finding.sink_file or profile.asset_hint
    if finding.sink_code:
        # 如果有 sink_code，尝试从中提取路由路径
        asset = _extract_asset_from_code(finding.sink_code) or asset

    # 前置条件：优先用 profile 的，如果 finding 有特定信息则补充
    precondition = profile.precondition
    if finding.source_code:
        # 如果 source_code 表明需要认证，更新前置条件
        source_lower = (finding.source_code or "").lower()
        if any(
            kw in source_lower for kw in ["auth", "login", "token", "session", "cookie"]
        ):
            precondition = "需要有效的用户认证"

    # 后置能力
    post_capability = profile.post_capability

    # 权限变化
    privilege_level = profile.privilege_level

    # 节点标签
    label = _build_node_label(finding, profile)

    return NodeInfo(
        finding_id=finding.id,
        vuln_type=finding.vuln_type,
        label=label,
        asset=asset,
        precondition=precondition,
        post_capability=post_capability,
        privilege_level=privilege_level,
        node_order=node_order,
        logical_id=f"node-{node_order + 1}",
    )


def _build_node_label(
    finding: Finding,
    profile: VulnTypeProfile,
) -> str:
    """构建节点标签。

    根据漏洞类型和 finding 信息生成描述性标签。
    """
    asset = finding.file_path or ""
    if finding.sink_code:
        extracted = _extract_asset_from_code(finding.sink_code)
        if extracted:
            asset = extracted

    impact = profile.final_impact or profile.post_capability or finding.vuln_type
    if asset:
        return f"{profile.label()} - {asset}"
    return impact


def _extract_asset_from_code(code: str) -> str | None:
    """从代码中提取资产路径（路由/接口名）。

    尝试匹配：
    - @app.route("/path") -> /path
    - path == "/path" -> /path
    - request.args.get("param") -> 提取参数名
    """
    import re

    if not code:
        return None

    # @app.route("/path")
    m = re.search(r'@app\.route\(\s*["\']([^"\']+)["\']', code)
    if m:
        return m.group(1)

    # path == "/path"
    m = re.search(r'path\s*==\s*["\']([^"\']+)["\']', code)
    if m:
        return m.group(1)

    # path.startswith("/path")
    m = re.search(r'path\.startswith\(\s*["\']([^"\']+)["\']', code)
    if m:
        return m.group(1)

    # @router.get("/path")
    m = re.search(
        r'@(?:router|app)\.(?:get|post|put|delete|patch)\(\s*["\']([^"\']+)["\']',
        code,
    )
    if m:
        return m.group(1)

    return None


# ──────────────────────────────────────────────────────
# 边生成与 DAG 构建
# ──────────────────────────────────────────────────────


def _try_chain_nodes(
    nodes: list[NodeInfo],
) -> list[EdgeInfo]:
    """尝试在节点之间生成有向边。

    遍历所有节点对 (i, j)，判断 node_i 的后置能力是否满足 node_j 的前置条件。
    如果满足且有串联规则，则生成一条有向边。

    Args:
        nodes: 所有节点列表

    Returns:
        边信息列表
    """
    edges: list[EdgeInfo] = []
    step = 1

    # 按节点顺序尝试相邻串联
    for i in range(len(nodes) - 1):
        source = nodes[i]
        target = nodes[i + 1]

        rule = can_chain(
            source.vuln_type,
            target.vuln_type,
            source.privilege_level,
        )

        if rule:
            edges.append(
                EdgeInfo(
                    source_node_id=source.logical_id,
                    target_node_id=target.logical_id,
                    condition=rule.condition,
                    action=rule.action,
                    privilege_escalation=rule.privilege_escalation,
                    step=step,
                )
            )
            step += 1
        else:
            # 尝试反向：target -> source
            rule_reverse = can_chain(
                target.vuln_type,
                source.vuln_type,
                target.privilege_level,
            )
            if rule_reverse:
                edges.append(
                    EdgeInfo(
                        source_node_id=target.logical_id,
                        target_node_id=source.logical_id,
                        condition=rule_reverse.condition,
                        action=rule_reverse.action,
                        privilege_escalation=rule_reverse.privilege_escalation,
                        step=step,
                    )
                )
                step += 1

    # 尝试非相邻串联（跳跃式连接）
    for i in range(len(nodes)):
        for j in range(len(nodes)):
            if i == j or abs(i - j) == 1:
                continue  # 跳过自身和相邻（已处理）
            source = nodes[i]
            target = nodes[j]

            # 检查是否已经有这条边
            existing = any(
                e.source_node_id == source.logical_id
                and e.target_node_id == target.logical_id
                for e in edges
            )
            if existing:
                continue

            rule = can_chain(
                source.vuln_type,
                target.vuln_type,
                source.privilege_level,
            )
            if rule:
                edges.append(
                    EdgeInfo(
                        source_node_id=source.logical_id,
                        target_node_id=target.logical_id,
                        condition=rule.condition,
                        action=rule.action,
                        privilege_escalation=rule.privilege_escalation,
                        step=step,
                    )
                )
                step += 1

    return edges


def _check_dag(
    nodes: list[NodeInfo],
    edges: list[EdgeInfo],
) -> list[EdgeInfo]:
    """检查图中是否存在环路，移除导致环路的边以确保结果是 DAG。

    使用 Kahn 算法（拓扑排序）检测环：
    1. 计算每个节点的入度
    2. 从入度为 0 的节点开始 BFS
    3. 如果无法完成拓扑排序（剩余节点 > 0），说明有环
    4. 逐条移除边直到无环

    Args:
        nodes: 节点列表
        edges: 边列表

    Returns:
        移除环路边后的边列表
    """
    # 构建邻接表和入度表
    node_ids = {n.logical_id for n in nodes}
    adj: dict[str, list[str]] = {nid: [] for nid in node_ids}
    in_degree: dict[str, int] = {nid: 0 for nid in node_ids}

    for edge in edges:
        if edge.source_node_id in adj and edge.target_node_id in adj:
            adj[edge.source_node_id].append(edge.target_node_id)
            in_degree[edge.target_node_id] += 1

    # Kahn 算法
    def _has_cycle(edges_to_check: list[EdgeInfo]) -> bool:
        adj_local = {nid: [] for nid in node_ids}
        in_deg_local = {nid: 0 for nid in node_ids}
        for e in edges_to_check:
            if e.source_node_id in adj_local and e.target_node_id in adj_local:
                adj_local[e.source_node_id].append(e.target_node_id)
                in_deg_local[e.target_node_id] += 1

        queue = [nid for nid, deg in in_deg_local.items() if deg == 0]
        visited = 0
        while queue:
            node = queue.pop(0)
            visited += 1
            for neighbor in adj_local[node]:
                in_deg_local[neighbor] -= 1
                if in_deg_local[neighbor] == 0:
                    queue.append(neighbor)
        return visited < len(node_ids)

    result_edges = list(edges)

    # 如果有环，逐条移除最后添加的边直到无环
    while _has_cycle(result_edges) and result_edges:
        result_edges.pop()
        logger.warning(
            "检测到环路，移除一条边以确保 DAG，剩余边数=%d",
            len(result_edges),
        )

    return result_edges


# ──────────────────────────────────────────────────────
# 链生成主入口
# ──────────────────────────────────────────────────────


def build_attack_chains(
    verified_findings: list[Finding],
) -> list[ChainBuildResult]:
    """根据已验证漏洞列表构建攻击链。

    算法：
    1. 如果没有已验证漏洞，返回空列表
    2. 如果只有一个已验证漏洞，生成单节点攻击链
    3. 如果有多个已验证漏洞：
       a. 为每个漏洞生成节点
       b. 尝试按漏洞类型串联规则生成有向边
       c. 检查环路确保 DAG
       d. 如果有边则生成多步攻击链
       e. 如果无法串联（无匹配规则），为每个漏洞生成单节点链

    Args:
        verified_findings: 已验证漏洞列表（status=verified）

    Returns:
        攻击链构建结果列表
    """
    if not verified_findings:
        return []

    # 按严重程度排序（critical > high > medium）
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(
        verified_findings,
        key=lambda f: (
            severity_order.get(f.severity, 5),
            -(f.cvss_score or 0),
        ),
    )

    # 单漏洞：生成单节点攻击链
    if len(sorted_findings) == 1:
        finding = sorted_findings[0]
        node = _generate_node(finding, 0)
        chain = ChainBuildResult(
            name=_build_chain_name([finding.vuln_type]),
            nodes=[node],
            edges=[],
            final_impact=get_vuln_profile(finding.vuln_type).final_impact,
            is_single_node=True,
        )
        chain.overall_severity, chain.overall_cvss = calculate_chain_severity(
            [finding.vuln_type],
            [finding.cvss_score],
        )
        chain.final_impact = calculate_final_impact([finding.vuln_type])
        return [chain]

    # 多漏洞：生成节点 + 尝试串联
    nodes = [_generate_node(f, i) for i, f in enumerate(sorted_findings)]

    # 尝试生成有向边
    edges = _try_chain_nodes(nodes)

    # 检查环路确保 DAG
    edges = _check_dag(nodes, edges)

    if edges:
        # 有串联边：生成一条多步攻击链
        # 按 edge 的 step 排序提取攻击路径
        path_vuln_types = _extract_attack_path(nodes, edges)
        cvss_scores = [f.cvss_score for f in sorted_findings]
        severity, cvss = calculate_chain_severity(path_vuln_types, cvss_scores)
        impact = calculate_final_impact(path_vuln_types)

        chain = ChainBuildResult(
            name=_build_chain_name(path_vuln_types),
            nodes=nodes,
            edges=edges,
            final_impact=impact,
            overall_severity=severity,
            overall_cvss=cvss,
            is_single_node=False,
        )
        return [chain]
    else:
        # 无串联边：为每个高危漏洞生成单节点链
        chains = []
        for i, finding in enumerate(sorted_findings):
            node = _generate_node(finding, 0)
            vuln_types = [finding.vuln_type]
            severity, cvss = calculate_chain_severity(
                vuln_types,
                [finding.cvss_score],
            )
            impact = calculate_final_impact(vuln_types)
            chain = ChainBuildResult(
                name=_build_chain_name(vuln_types),
                nodes=[node],
                edges=[],
                final_impact=impact,
                overall_severity=severity,
                overall_cvss=cvss,
                is_single_node=True,
            )
            chains.append(chain)
        return chains


def _extract_attack_path(
    nodes: list[NodeInfo],
    edges: list[EdgeInfo],
) -> list[str]:
    """从边的关系中提取攻击路径顺序的漏洞类型列表。

    算法：
    1. 找到入度为 0 的节点（攻击入口点）
    2. 按 edge 的 step 顺序遍历，得到攻击路径顺序
    3. 如果无法确定入口（无入度0的节点），按 edge 的 step 顺序提取

    Args:
        nodes: 节点列表
        edges: 边列表

    Returns:
        按攻击路径顺序排列的漏洞类型列表
    """
    if not edges:
        return [n.vuln_type for n in nodes]

    # 构建入度表
    in_degree: dict[str, int] = {n.logical_id: 0 for n in nodes}
    for e in edges:
        if e.target_node_id in in_degree:
            in_degree[e.target_node_id] += 1

    # 找入口节点（入度为0）
    entry_nodes = [nid for nid, deg in in_degree.items() if deg == 0]

    # 构建邻接表
    adj: dict[str, list[str]] = {n.logical_id: [] for n in nodes}
    for e in sorted(edges, key=lambda x: x.step):
        if e.source_node_id in adj:
            adj[e.source_node_id].append(e.target_node_id)

    # 从入口节点开始 BFS/DFS 获取路径顺序
    # 构建节点查找表
    node_map = {n.logical_id: n for n in nodes}

    path: list[str] = []
    visited: set[str] = set()

    if entry_nodes:
        # 从入口开始遍历
        queue = list(entry_nodes)
        while queue:
            nid = queue.pop(0)
            if nid in visited:
                continue
            visited.add(nid)
            if nid in node_map:
                path.append(node_map[nid].vuln_type)
            for neighbor in adj.get(nid, []):
                if neighbor not in visited:
                    queue.append(neighbor)

        # 添加未访问的节点（孤立节点）
        for n in nodes:
            if n.logical_id not in visited:
                path.append(n.vuln_type)
    else:
        # 无入口节点，按 step 顺序提取
        sorted_edges = sorted(edges, key=lambda x: x.step)
        for e in sorted_edges:
            if e.source_node_id in node_map and e.source_node_id not in visited:
                visited.add(e.source_node_id)
                path.append(node_map[e.source_node_id].vuln_type)
            if e.target_node_id in node_map and e.target_node_id not in visited:
                visited.add(e.target_node_id)
                path.append(node_map[e.target_node_id].vuln_type)

    return path if path else [n.vuln_type for n in nodes]


def _build_chain_name(vuln_types: list[str]) -> str:
    """根据漏洞类型列表生成攻击链名称。

    Args:
        vuln_types: 漏洞类型列表

    Returns:
        攻击链名称字符串
    """
    if not vuln_types:
        return "空攻击链"

    if len(vuln_types) == 1:
        profile = get_vuln_profile(vuln_types[0])
        return f"单点漏洞利用: {profile.label()}"

    parts = []
    for vt in vuln_types:
        profile = get_vuln_profile(vt)
        parts.append(profile.label())
    return " -> ".join(parts)


# ──────────────────────────────────────────────────────
# 持久化
# ──────────────────────────────────────────────────────


async def persist_attack_chains(
    db: AsyncSession,
    task_id: str,
    chains: list[ChainBuildResult],
) -> list[AttackChain]:
    """将构建的攻击链持久化到数据库。

    为每条 ChainBuildResult 创建 AttackChain + AttackChainNode + AttackChainEdge ORM 对象，
    并保存到数据库。

    Args:
        db: 数据库会话
        task_id: 任务 ID
        chains: 攻击链构建结果列表

    Returns:
        已持久化的 AttackChain ORM 对象列表
    """
    persisted: list[AttackChain] = []

    for chain_result in chains:
        # 创建攻击链主记录
        chain_id = generate_id()
        chain_orm = AttackChain(
            id=chain_id,
            task_id=task_id,
            name=chain_result.name,
            final_impact=chain_result.final_impact,
            overall_severity=chain_result.overall_severity,
            overall_cvss=chain_result.overall_cvss,
            node_count=len(chain_result.nodes),
            edge_count=len(chain_result.edges),
            is_single_node=chain_result.is_single_node,
        )
        db.add(chain_orm)
        await db.flush()

        # 创建节点
        node_id_map: dict[str, str] = {}  # logical_id -> db_id
        for node_info in chain_result.nodes:
            node_db_id = generate_id()
            node_id_map[node_info.logical_id] = node_db_id
            node_orm = AttackChainNode(
                id=node_db_id,
                attack_chain_id=chain_id,
                finding_id=node_info.finding_id,
                node_id=node_info.logical_id,
                label=node_info.label,
                asset=node_info.asset,
                vuln_type=node_info.vuln_type,
                precondition=node_info.precondition,
                post_capability=node_info.post_capability,
                privilege_level=node_info.privilege_level,
                node_order=node_info.node_order,
            )
            db.add(node_orm)
            node_info.db_id = node_db_id

        await db.flush()

        # 创建边
        for edge_info in chain_result.edges:
            edge_orm = AttackChainEdge(
                id=generate_id(),
                attack_chain_id=chain_id,
                source_node_id=node_id_map.get(edge_info.source_node_id, ""),
                target_node_id=node_id_map.get(edge_info.target_node_id, ""),
                condition=edge_info.condition,
                action=edge_info.action,
                privilege_escalation=edge_info.privilege_escalation,
                step=edge_info.step,
            )
            db.add(edge_orm)

        await db.flush()
        chain_result.chain_orm = chain_orm
        persisted.append(chain_orm)

    logger.info(
        "攻击链持久化完成: %d 条链, %d 节点, %d 边",
        len(persisted),
        sum(len(c.nodes) for c in chains),
        sum(len(c.edges) for c in chains),
    )
    return persisted


async def get_attack_chains(
    db: AsyncSession,
    task_id: str,
) -> list[AttackChain]:
    """查询任务下的所有攻击链。

    Args:
        db: 数据库会话
        task_id: 任务 ID

    Returns:
        AttackChain ORM 对象列表（含 nodes 和 edges 关系）
    """
    from sqlalchemy import select
    from sqlalchemy.orm import selectinload

    stmt = (
        select(AttackChain)
        .where(AttackChain.task_id == task_id)
        .options(
            selectinload(AttackChain.nodes),
            selectinload(AttackChain.edges),
        )
        .order_by(AttackChain.created_at.desc())
    )
    result = await db.execute(stmt)
    return list(result.scalars().all())
