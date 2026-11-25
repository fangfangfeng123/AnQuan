"""报告数据汇编器模块。

本模块负责从 DB 聚合全部评估数据，组装为结构化的 ReportData：
- 读取 task / project / runtime_profile
- 读取 findings（按 severity 排序，含 poc_evidence + fix_patch）
- 读取 attack_chains（含 nodes + edges）
- 计算 statistics（各 severity 数量、最高 CVSS）
- 构建 5 个章节的结构化数据（dict/list，非 Markdown 字符串）

sections 设计为结构化数据，这样：
1. Jinja2 模板可以灵活控制 Markdown/HTML 语法
2. 报告详情 API 可以直接返回 JSON 给前端
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models import (
    AttackChain,
    AttackChainEdge,
    AttackChainNode,
    Finding,
    FixPatch,
    Project,
    RuntimeProfile,
    Task,
)

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class ReportData:
    """报告完整数据（传给模板渲染或 API 返回）。

    Attributes:
        task: 任务 ORM 对象
        project: 项目 ORM 对象
        runtime_profile: 运行时画像 ORM 对象（可能为 None）
        findings: 漏洞列表（按 severity 排序，每条含 poc_evidence + fix_patch）
        attack_chains: 攻击链列表（含 nodes + edges）
        statistics: 统计字典（各 severity 数量、最高 CVSS）
        overall_risk: 整体风险评级（critical/high/medium/low/secure）
        overall_cvss: 最高 CVSS 评分
        sections: 5 个章节的结构化数据
        generated_at: 报告生成时间
    """

    task: Task | None = None
    project: Project | None = None
    runtime_profile: RuntimeProfile | None = None
    findings: list[Finding] = field(default_factory=list)
    attack_chains: list[AttackChain] = field(default_factory=list)
    statistics: dict = field(default_factory=dict)
    overall_risk: str = "secure"
    overall_cvss: float | None = None
    sections: dict = field(default_factory=dict)
    generated_at: str = ""


# ──────────────────────────────────────────────────────
# 主入口
# ──────────────────────────────────────────────────────


async def assemble_report_data(
    db: AsyncSession,
    task_id: str,
) -> ReportData:
    """从 DB 聚合全部数据，组装为 ReportData。

    Args:
        db: 数据库会话
        task_id: 任务 ID

    Returns:
        ReportData：包含 5 章节结构化数据的完整报告数据
    """
    # ── 读取基础数据 ──
    task = await _get_task(db, task_id)
    project = await _get_project(db, task.project_id) if task else None
    runtime_profile = await _get_runtime_profile(db, task_id)
    findings = await _collect_findings(db, task_id)
    chains = await _collect_chains(db, task_id)
    patches = await _collect_patches(db, task_id)

    # ── 计算统计 ──
    statistics = _calculate_statistics(findings, chains)
    overall_risk = _determine_overall_risk(findings, chains)
    overall_cvss = statistics.get("max_cvss")

    # ── 组装 5 个章节 ──
    sections = {
        "executive_summary": _build_executive_summary(
            task,
            project,
            runtime_profile,
            findings,
            chains,
            overall_risk,
            statistics,
        ),
        "scope": _build_scope_section(task, project, runtime_profile),
        "findings": _build_findings_section(findings, patches),
        "attack_chains": _build_chains_section(chains),
        "remediation": _build_remediation_section(findings, patches),
    }

    return ReportData(
        task=task,
        project=project,
        runtime_profile=runtime_profile,
        findings=findings,
        attack_chains=chains,
        statistics=statistics,
        overall_risk=overall_risk,
        overall_cvss=overall_cvss,
        sections=sections,
        generated_at=datetime.now(timezone.utc).isoformat(),
    )


# ──────────────────────────────────────────────────────
# 子函数：数据读取
# ──────────────────────────────────────────────────────


async def _get_task(db: AsyncSession, task_id: str) -> Task | None:
    stmt = select(Task).where(Task.id == task_id)
    result = await db.execute(stmt)
    return result.scalar_one_or_none()


async def _get_project(db: AsyncSession, project_id: str) -> Project | None:
    stmt = select(Project).where(Project.id == project_id)
    result = await db.execute(stmt)
    return result.scalar_one_or_none()


async def _get_runtime_profile(db: AsyncSession, task_id: str) -> RuntimeProfile | None:
    stmt = select(RuntimeProfile).where(RuntimeProfile.task_id == task_id)
    result = await db.execute(stmt)
    return result.scalar_one_or_none()


async def _collect_findings(db: AsyncSession, task_id: str) -> list[Finding]:
    """读取漏洞列表，按 severity 排序（critical -> high -> medium -> low -> info）。"""
    stmt = select(Finding).where(Finding.task_id == task_id)
    result = await db.execute(stmt)
    findings = list(result.scalars().all())
    findings.sort(key=lambda f: _SEVERITY_ORDER.get(f.severity, 99))
    return findings


async def _collect_chains(db: AsyncSession, task_id: str) -> list[AttackChain]:
    """读取攻击链（含 selectinload nodes + edges）。"""
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


async def _collect_patches(db: AsyncSession, task_id: str) -> list[FixPatch]:
    """读取修复补丁列表。"""
    stmt = select(FixPatch).where(FixPatch.task_id == task_id)
    result = await db.execute(stmt)
    return list(result.scalars().all())


# ──────────────────────────────────────────────────────
# 子函数：统计计算
# ──────────────────────────────────────────────────────


def _calculate_statistics(findings: list[Finding], chains: list[AttackChain]) -> dict:
    """计算漏洞分布统计。"""
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    status_counts = {
        "verified": 0,
        "unverified": 0,
        "latent": 0,
        "false_positive": 0,
        "adopted": 0,
    }
    max_cvss = 0.0
    vuln_types: dict[str, int] = {}

    for f in findings:
        sev = (f.severity or "info").lower()
        if sev in sev_counts:
            sev_counts[sev] += 1

        status = (f.status or "unverified").lower()
        if status in status_counts:
            status_counts[status] += 1

        if f.cvss_score and f.cvss_score > max_cvss:
            max_cvss = f.cvss_score

        vt = f.vuln_type or "unknown"
        vuln_types[vt] = vuln_types.get(vt, 0) + 1

    return {
        "total_findings": len(findings),
        "severity_distribution": sev_counts,
        "status_distribution": status_counts,
        "max_cvss": max_cvss if max_cvss > 0 else None,
        "vuln_type_distribution": vuln_types,
        "total_chains": len(chains),
        "single_node_chains": sum(1 for c in chains if c.is_single_node),
        "multi_step_chains": sum(1 for c in chains if not c.is_single_node),
    }


def _determine_overall_risk(
    findings: list[Finding], chains: list[AttackChain] | None = None
) -> str:
    """根据 findings 和 chains 计算整体风险评级。

    优先级（从高到低）：
    - 有 critical severity finding 或 critical 攻击链 → critical
    - 有 high severity finding 或 high 攻击链 → high
    - 有 verified finding → medium
    - 有任何未修复的 finding（latent/unverified/false_positive）→ low
    - 无任何 finding 或全部已 adopted → secure
    """
    if not findings:
        return "secure"

    severities = {(f.severity or "info").lower() for f in findings}
    statuses = {(f.status or "unverified").lower() for f in findings}
    chain_severities = {
        (c.overall_severity or "").lower() for c in (chains or [])
    }

    # 1. critical 优先
    if "critical" in severities or "critical" in chain_severities:
        return "critical"

    # 2. high 次之
    if "high" in severities or "high" in chain_severities:
        return "high"

    # 3. 有 verified 漏洞
    if "verified" in statuses:
        return "medium"

    # 4. 还有未修复的漏洞（latent / unverified / false_positive）
    unfixed_statuses = statuses - {"adopted"}
    if unfixed_statuses:
        return "low"

    # 5. 全部 adopted 或无 status
    return "secure"


# ──────────────────────────────────────────────────────
# 子函数：章节构建
# ──────────────────────────────────────────────────────


def _build_executive_summary(
    task: Task | None,
    project: Project | None,
    runtime_profile: RuntimeProfile | None,
    findings: list[Finding],
    chains: list[AttackChain],
    overall_risk: str,
    statistics: dict,
) -> dict:
    """§1 执行摘要。"""
    sev_dist = statistics.get("severity_distribution", {})
    return {
        "task_id": task.id if task else "",
        "project_name": project.project_name if project else "未知",
        "overall_risk": overall_risk,
        "total_findings": len(findings),
        "critical_count": sev_dist.get("critical", 0),
        "high_count": sev_dist.get("high", 0),
        "medium_count": sev_dist.get("medium", 0),
        "low_count": sev_dist.get("low", 0),
        "info_count": sev_dist.get("info", 0),
        "max_cvss": statistics.get("max_cvss"),
        "total_chains": len(chains),
        "multi_step_chains": statistics.get("multi_step_chains", 0),
        "summary_text": _build_summary_text(findings, chains, overall_risk),
    }


def _build_summary_text(
    findings: list[Finding], chains: list[AttackChain], overall_risk: str
) -> str:
    """生成摘要文字描述。"""
    sev_dist = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = (f.severity or "info").lower()
        if sev in sev_dist:
            sev_dist[sev] += 1

    parts = []
    if sev_dist["critical"] > 0:
        parts.append(f"{sev_dist['critical']} 个严重漏洞")
    if sev_dist["high"] > 0:
        parts.append(f"{sev_dist['high']} 个高危漏洞")
    if sev_dist["medium"] > 0:
        parts.append(f"{sev_dist['medium']} 个中危漏洞")
    if sev_dist["low"] > 0:
        parts.append(f"{sev_dist['low']} 个低危漏洞")

    finding_summary = "、".join(parts) if parts else "未发现漏洞"
    chain_summary = (
        f"共发现 {len(chains)} 条攻击链" if chains else "未发现可组合攻击路径"
    )

    risk_labels = {
        "critical": "极高危",
        "high": "高危",
        "medium": "中危",
        "low": "低危",
        "secure": "安全",
    }
    risk_label = risk_labels.get(overall_risk, overall_risk)

    return (
        f"本次安全评估整体风险等级为「{risk_label}」。"
        f"共发现 {len(findings)} 个漏洞（{finding_summary}），"
        f"{chain_summary}。"
    )


def _build_scope_section(
    task: Task | None,
    project: Project | None,
    runtime_profile: RuntimeProfile | None,
) -> dict:
    """§2 评估范围。"""
    return {
        "project_name": project.project_name if project else "未知",
        "project_id": project.id if project else "",
        "task_id": task.id if task else "",
        "source_type": project.source_type if project else "unknown",
        "source_input": project.source_input if project else "",
        "language": runtime_profile.language if runtime_profile else "unknown",
        "framework": runtime_profile.framework if runtime_profile else "unknown",
        "dependencies": runtime_profile.dependencies if runtime_profile else {},
        "service_ports": runtime_profile.service_ports if runtime_profile else [],
        "entry_points": runtime_profile.entry_points if runtime_profile else [],
        "run_command": runtime_profile.run_command if runtime_profile else None,
        "created_at": task.created_at.isoformat() if task and task.created_at else "",
        "started_at": task.started_at.isoformat() if task and task.started_at else "",
        "completed_at": task.ended_at.isoformat() if task and task.ended_at else "",
    }


def _build_findings_section(
    findings: list[Finding], patches: list[FixPatch]
) -> list[dict]:
    """§3 漏洞详情（按 severity 分组，每条含 PoC 摘要 + 修复 patch）。"""
    patch_map: dict[str, FixPatch] = {p.finding_id: p for p in patches}
    result: list[dict] = []
    for f in findings:
        patch = patch_map.get(f.id)
        entry = {
            "id": f.id,
            "vuln_type": f.vuln_type,
            "cwe_id": f.cwe_id,
            "owasp": f.owasp,
            "severity": f.severity,
            "cvss_score": f.cvss_score,
            "cvss_vector": f.cvss_vector,
            "status": f.status,
            "confidence": f.confidence,
            "file_path": f.file_path,
            "line_start": f.line_start,
            "line_end": f.line_end,
            "snippet": f.snippet,
            "source_file": f.source_file,
            "source_line": f.source_line,
            "source_code": f.source_code,
            "sink_file": f.sink_file,
            "sink_line": f.sink_line,
            "sink_code": f.sink_code,
            "taint_path": f.taint_path,
            "remediation": f.remediation,
            "detected_by": f.detected_by,
            "patch": {
                "id": patch.id,
                "adopt_status": patch.adopt_status,
                "validated": patch.validated,
                "diff_content": patch.diff_content,
                "description": patch.description,
            }
            if patch
            else None,
            "created_at": f.created_at.isoformat() if f.created_at else "",
        }
        result.append(entry)
    return result


def _build_chains_section(chains: list[AttackChain]) -> list[dict]:
    """§4 攻击链分析（每条链的最终影响 + 节点步骤表格）。"""
    result: list[dict] = []
    for chain in chains:
        nodes_sorted = sorted(chain.nodes, key=lambda n: n.node_order)
        edges_sorted = sorted(chain.edges, key=lambda e: e.step)
        entry = {
            "id": chain.id,
            "name": chain.name,
            "final_impact": chain.final_impact,
            "overall_severity": chain.overall_severity,
            "overall_cvss": chain.overall_cvss,
            "node_count": chain.node_count,
            "edge_count": chain.edge_count,
            "is_single_node": chain.is_single_node,
            "nodes": [
                {
                    "node_id": n.node_id,
                    "label": n.label,
                    "asset": n.asset,
                    "vuln_type": n.vuln_type,
                    "precondition": n.precondition,
                    "post_capability": n.post_capability,
                    "privilege_level": n.privilege_level,
                    "node_order": n.node_order,
                    "finding_id": n.finding_id,
                }
                for n in nodes_sorted
            ],
            "edges": [
                {
                    "source_node_id": e.source_node_id,
                    "target_node_id": e.target_node_id,
                    "condition": e.condition,
                    "action": e.action,
                    "privilege_escalation": e.privilege_escalation,
                    "step": e.step,
                }
                for e in edges_sorted
            ],
        }
        result.append(entry)
    return result


def _build_remediation_section(
    findings: list[Finding], patches: list[FixPatch]
) -> list[dict]:
    """§5 修复建议汇总（按修复优先级排序的表格）。"""
    patch_map: dict[str, FixPatch] = {p.finding_id: p for p in patches}
    _rem_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    items: list[dict] = []
    for f in findings:
        patch = patch_map.get(f.id)
        items.append(
            {
                "finding_id": f.id,
                "vuln_type": f.vuln_type,
                "severity": f.severity,
                "cvss_score": f.cvss_score,
                "file_path": f.file_path,
                "line_start": f.line_start,
                "line_end": f.line_end,
                "has_patch": patch is not None,
                "patch_status": patch.adopt_status if patch else "none",
                "patch_validated": patch.validated if patch else False,
                "remediation": f.remediation or "",
                "patch_description": patch.description if patch else "",
            }
        )

    items.sort(key=lambda x: _rem_order.get(x["severity"], 99))
    return items
