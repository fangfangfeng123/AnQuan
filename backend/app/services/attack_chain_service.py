"""攻击链服务模块。

本模块封装攻击链的全部业务逻辑，作为 Agent 和 Router 的统一门面：
- build_chains_for_task(task_id)：主流程——读 verified findings -> build -> persist -> 构造 payload -> 写日志
- delete_chain(chain_id)：删除单条攻击链
- get_chain_statistics(task_id)：聚合统计
- get_attack_chains(task_id)：查询攻击链列表
- get_attack_chain(chain_id)：查询单条攻击链详情
"""

import logging
from dataclasses import dataclass, field

from redis.asyncio import Redis
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.chain.builder import build_attack_chains, persist_attack_chains
from app.enums import FindingStatus, PhaseName
from app.models.attack_chain import AttackChain, AttackChainEdge, AttackChainNode
from app.models.finding import Finding
from app.utils import append_task_log
from app.websockets.publisher import EventPublisher

logger = logging.getLogger(__name__)

EXPLOIT_CHAIN_AGENT = "exploit_chain_agent"
_EXPLOIT_CHAIN_PHASE = PhaseName.EXPLOIT_CHAIN.value

_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


# ──────────────────────────────────────────────────────
# 结果数据结构
# ──────────────────────────────────────────────────────


@dataclass
class ExploitChainResult:
    """攻击链推演结果摘要。

    Agent 和 Router 都通过这个结构获取执行结果，
    避免 Agent 直接操作 builder / DB。
    """

    success: bool
    chain_count: int = 0
    total_nodes: int = 0
    total_edges: int = 0
    single_node_chains: int = 0
    multi_step_chains: int = 0
    max_severity: str = "info"
    max_cvss: float | None = None
    final_impacts: list[str] = field(default_factory=list)
    chains_payload: list[dict] = field(default_factory=list)
    error: str | None = None


# ──────────────────────────────────────────────────────
# 主流程：构建攻击链
# ──────────────────────────────────────────────────────


async def build_chains_for_task(
    db: AsyncSession,
    redis: Redis,
    task_id: str,
) -> ExploitChainResult:
    """为任务构建攻击链的主业务流程。

    流程：
    1. 读取 task 中 status=verified 的 findings
    2. 无 verified findings -> 返回空结果（不报错）
    3. 调 chain.builder.build_attack_chains 同步构建
    4. 调 chain.builder.persist_attack_chains 持久化到 DB
    5. 构造前端 WS 事件 payload
    6. 写任务日志
    7. 返回 ExploitChainResult

    Args:
        db: 数据库会话
        redis: Redis 连接（用于发布 WS 事件）
        task_id: 任务 ID

    Returns:
        ExploitChainResult
    """
    # ── 1. 读取 verified findings ──
    stmt = select(Finding).where(
        Finding.task_id == task_id,
        Finding.status == FindingStatus.VERIFIED.value,
    )
    result = await db.execute(stmt)
    verified_findings = list(result.scalars().all())

    logger.info(
        "[attack_chain_service] Found %d verified findings for task=%s",
        len(verified_findings),
        task_id,
    )

    if not verified_findings:
        await append_task_log(
            db,
            task_id,
            _EXPLOIT_CHAIN_PHASE,
            EXPLOIT_CHAIN_AGENT,
            "info",
            "无已验证漏洞，攻击链推演跳过",
        )
        return ExploitChainResult(success=True, chain_count=0)

    # ── 2. 构建攻击链 ──
    try:
        chain_results = build_attack_chains(verified_findings)
    except Exception as e:
        logger.exception("[attack_chain_service] Failed to build chains: %s", e)
        await append_task_log(
            db,
            task_id,
            _EXPLOIT_CHAIN_PHASE,
            EXPLOIT_CHAIN_AGENT,
            "error",
            f"攻击链构建失败: {e}",
        )
        return ExploitChainResult(success=False, error=f"攻击链构建失败: {e}")

    # ── 3. 持久化 ──
    try:
        persisted_chains = await persist_attack_chains(db, task_id, chain_results)
        await db.commit()
    except Exception as e:
        logger.exception("[attack_chain_service] Failed to persist chains: %s", e)
        await db.rollback()
        await append_task_log(
            db,
            task_id,
            _EXPLOIT_CHAIN_PHASE,
            EXPLOIT_CHAIN_AGENT,
            "error",
            f"攻击链持久化失败: {e}",
        )
        return ExploitChainResult(success=False, error=f"攻击链持久化失败: {e}")

    # ── 4. 统计 + 构造 payload ──
    single_count = sum(1 for c in chain_results if c.is_single_node)
    multi_count = sum(1 for c in chain_results if not c.is_single_node)
    total_nodes = sum(len(c.nodes) for c in chain_results)
    total_edges = sum(len(c.edges) for c in chain_results)

    max_sev = "info"
    max_cvss = 0.0
    for c in chain_results:
        if _SEVERITY_RANK.get(c.overall_severity, 0) > _SEVERITY_RANK.get(max_sev, 0):
            max_sev = c.overall_severity
        if c.overall_cvss and c.overall_cvss > max_cvss:
            max_cvss = c.overall_cvss

    final_impacts = [c.final_impact or "" for c in chain_results]

    chains_payload = []
    for chain_orm, chain_result in zip(persisted_chains, chain_results):
        chains_payload.append(
            {
                "chain_id": chain_orm.id,
                "name": chain_result.name,
                "node_count": len(chain_result.nodes),
                "edge_count": len(chain_result.edges),
                "is_single_node": chain_result.is_single_node,
                "overall_severity": chain_result.overall_severity,
                "overall_cvss": chain_result.overall_cvss,
                "final_impact": chain_result.final_impact,
                "nodes": [
                    {
                        "node_id": n.logical_id,
                        "finding_id": n.finding_id,
                        "label": n.label,
                        "vuln_type": n.vuln_type,
                        "asset": n.asset,
                        "precondition": n.precondition,
                        "post_capability": n.post_capability,
                        "privilege_level": n.privilege_level,
                    }
                    for n in chain_result.nodes
                ],
                "edges": [
                    {
                        "source": e.source_node_id,
                        "target": e.target_node_id,
                        "condition": e.condition,
                        "action": e.action,
                        "privilege_escalation": e.privilege_escalation,
                        "step": e.step,
                    }
                    for e in chain_result.edges
                ],
            }
        )

    # ── 5. 写日志 ──
    await append_task_log(
        db,
        task_id,
        _EXPLOIT_CHAIN_PHASE,
        EXPLOIT_CHAIN_AGENT,
        "info",
        (
            f"攻击链推演完成: {len(chain_results)} 条链"
            f"（单节点 {single_count} 条，多步 {multi_count} 条），"
            f"共 {total_nodes} 节点 {total_edges} 边，最高风险 {max_sev}"
        ),
        detail={
            "chain_count": len(chain_results),
            "single_node_chains": single_count,
            "multi_step_chains": multi_count,
            "total_nodes": total_nodes,
            "total_edges": total_edges,
            "max_severity": max_sev,
            "max_cvss": max_cvss,
            "final_impacts": final_impacts,
        },
    )

    return ExploitChainResult(
        success=True,
        chain_count=len(chain_results),
        total_nodes=total_nodes,
        total_edges=total_edges,
        single_node_chains=single_count,
        multi_step_chains=multi_count,
        max_severity=max_sev,
        max_cvss=max_cvss if max_cvss > 0 else None,
        final_impacts=final_impacts,
        chains_payload=chains_payload,
    )


# ──────────────────────────────────────────────────────
# 删除单条攻击链
# ──────────────────────────────────────────────────────


async def delete_chain(
    db: AsyncSession,
    task_id: str,
    chain_id: str,
) -> bool:
    """删除单条攻击链（级联删除节点和边）。

    会校验 chain.task_id == task_id，防止横向越权。

    Args:
        db: 数据库会话
        task_id: 任务 ID（用于校验归属）
        chain_id: 攻击链 ID

    Returns:
        True 如果删除成功，False 如果链不存在或不属于该任务
    """
    stmt = (
        select(AttackChain)
        .where(AttackChain.id == chain_id)
        .options(
            selectinload(AttackChain.nodes),
            selectinload(AttackChain.edges),
        )
    )
    result = await db.execute(stmt)
    chain = result.scalar_one_or_none()

    if chain is None:
        await append_task_log(
            db,
            task_id,
            _EXPLOIT_CHAIN_PHASE,
            EXPLOIT_CHAIN_AGENT,
            "warning",
            f"删除攻击链失败：链 {chain_id} 不存在",
        )
        return False

    # 校验归属：防止横向越权
    if chain.task_id != task_id:
        await append_task_log(
            db,
            task_id,
            _EXPLOIT_CHAIN_PHASE,
            EXPLOIT_CHAIN_AGENT,
            "warning",
            f"删除攻击链失败：链 {chain_id} 不属于任务 {task_id}",
        )
        logger.warning(
            "[attack_chain_service] Delete rejected: chain %s belongs to task %s, not %s",
            chain_id,
            chain.task_id,
            task_id,
        )
        return False

    # 级联删除：先删子记录再删主记录
    await db.execute(
        delete(AttackChainEdge).where(AttackChainEdge.attack_chain_id == chain_id)
    )
    await db.execute(
        delete(AttackChainNode).where(AttackChainNode.attack_chain_id == chain_id)
    )
    await db.delete(chain)
    await db.commit()

    await append_task_log(
        db,
        task_id,
        _EXPLOIT_CHAIN_PHASE,
        EXPLOIT_CHAIN_AGENT,
        "info",
        f"删除攻击链 {chain_id}（{chain.name}）",
    )

    logger.info(
        "[attack_chain_service] Deleted chain %s for task=%s", chain_id, task_id
    )
    return True


async def regenerate_chains_for_task(
    db: AsyncSession,
    redis: Redis,
    task_id: str,
) -> ExploitChainResult:
    """重新生成任务下的攻击链（删旧 + 重建）。

    Args:
        db: 数据库会话
        redis: Redis 连接（保留参数对齐 build_chains_for_task）
        task_id: 任务 ID

    Returns:
        ExploitChainResult：新的构建结果
    """
    # 1. 删除该任务下所有旧攻击链（先子表再主表）
    chain_ids_subq = select(AttackChain.id).where(AttackChain.task_id == task_id)
    await db.execute(
        delete(AttackChainEdge).where(
            AttackChainEdge.attack_chain_id.in_(chain_ids_subq)
        )
    )
    await db.execute(
        delete(AttackChainNode).where(
            AttackChainNode.attack_chain_id.in_(chain_ids_subq)
        )
    )
    await db.execute(delete(AttackChain).where(AttackChain.task_id == task_id))
    await db.commit()

    await append_task_log(
        db,
        task_id,
        _EXPLOIT_CHAIN_PHASE,
        EXPLOIT_CHAIN_AGENT,
        "info",
        "重新生成攻击链：已清空旧链",
    )

    # 2. 重新构建
    return await build_chains_for_task(db, redis, task_id)


# ──────────────────────────────────────────────────────
# 统计
# ──────────────────────────────────────────────────────


async def get_chain_statistics(
    db: AsyncSession,
    task_id: str,
) -> dict:
    """获取任务下的攻击链统计信息。

    返回给前端 Dashboard 用：
    - total_chains: 总链数
    - single_node_chains: 单节点链数
    - multi_step_chains: 多步链数
    - total_nodes: 总节点数
    - total_edges: 总边数
    - max_severity: 最高风险等级
    - max_cvss: 最高 CVSS 评分
    - severity_distribution: {critical: N, high: N, ...}

    Args:
        db: 数据库会话
        task_id: 任务 ID

    Returns:
        统计字典
    """
    stmt = select(AttackChain).where(AttackChain.task_id == task_id)
    result = await db.execute(stmt)
    chains = list(result.scalars().all())

    if not chains:
        return {
            "total_chains": 0,
            "single_node_chains": 0,
            "multi_step_chains": 0,
            "total_nodes": 0,
            "total_edges": 0,
            "max_severity": "info",
            "max_cvss": None,
            "severity_distribution": {},
        }

    single_count = sum(1 for c in chains if c.is_single_node)
    multi_count = sum(1 for c in chains if not c.is_single_node)
    total_nodes = sum(c.node_count for c in chains)
    total_edges = sum(c.edge_count for c in chains)

    max_sev = "info"
    max_cvss = 0.0
    sev_dist: dict[str, int] = {}
    for c in chains:
        sev = c.overall_severity or "medium"
        sev_dist[sev] = sev_dist.get(sev, 0) + 1
        if _SEVERITY_RANK.get(sev, 0) > _SEVERITY_RANK.get(max_sev, 0):
            max_sev = sev
        if c.overall_cvss and c.overall_cvss > max_cvss:
            max_cvss = c.overall_cvss

    return {
        "total_chains": len(chains),
        "single_node_chains": single_count,
        "multi_step_chains": multi_count,
        "total_nodes": total_nodes,
        "total_edges": total_edges,
        "max_severity": max_sev,
        "max_cvss": max_cvss if max_cvss > 0 else None,
        "severity_distribution": sev_dist,
    }


# ──────────────────────────────────────────────────────
# 查询
# ──────────────────────────────────────────────────────


async def get_attack_chains(
    db: AsyncSession,
    task_id: str,
) -> list[AttackChain]:
    """查询任务下的所有攻击链（含节点和边）。

    Args:
        db: 数据库会话
        task_id: 任务 ID

    Returns:
        list[AttackChain]：攻击链 ORM 对象列表（nodes 和 edges 已预加载）
    """
    stmt = (
        select(AttackChain)
        .where(AttackChain.task_id == task_id)
        .options(
            selectinload(AttackChain.nodes),
            selectinload(AttackChain.edges),
        )
        .order_by(AttackChain.created_at)
    )
    result = await db.execute(stmt)
    return list(result.scalars().all())


async def get_attack_chain(
    db: AsyncSession,
    chain_id: str,
) -> AttackChain | None:
    """查询单条攻击链详情（含节点和边）。

    Args:
        db: 数据库会话
        chain_id: 攻击链 ID

    Returns:
        AttackChain | None：攻击链 ORM 对象，不存在返回 None
    """
    stmt = (
        select(AttackChain)
        .where(AttackChain.id == chain_id)
        .options(
            selectinload(AttackChain.nodes),
            selectinload(AttackChain.edges),
        )
    )
    result = await db.execute(stmt)
    return result.scalar_one_or_none()
