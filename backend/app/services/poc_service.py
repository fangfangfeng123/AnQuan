"""PoC 验证服务模块。

本模块是 PoC 阶段的业务门面，对照 recon_service.run_recon 的设计：

- run_poc_verify(db, redis, task_id)：完整 PoC 验证主流程
  1. 读取任务下 unverified findings
  2. 过滤可动态验证的漏洞类型（其余标记为 latent）
  3. 从 RuntimeProfile 提取入口文件和端口
  4. 调用 target_service 启动临时目标服务
  5. 逐 finding 提取路由 + 参数 + 执行探针 + 验证
  6. 调用 poc_evidence_service 保存证据
  7. 调用 finding_service 更新状态
  8. 停止目标服务
  9. 返回 PocVerifyResult

- get_poc_summary(db, task_id)：统计任务的 PoC 结果分布
- list_evidences_for_finding / list_evidences_for_task：证据查询（透传）

底层的无状态工具（payloads / executor / verifier）保留在 poc/ 包内，
本 service 只做业务编排与 DB 写入。
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Any

from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import SandboxError
from app.enums import FindingStatus
from app.models import Finding
from app.poc.executor import execute_probes_batch
from app.poc.payloads import get_probes_for_vuln_type, is_verifiable
from app.poc.verifier import verify
from app.services.finding_service import get_findings, update_finding_status
from app.services.poc_evidence_service import (
    get_evidences_by_finding,
    get_evidences_by_task,
    save_evidence,
)
from app.services.recon_service import get_runtime_profile
from app.services.sandbox_service import exec_in_sandbox
from app.services.target_service import start_target_service, stop_target_service
from app.utils import append_task_log
from app.websockets.publisher import EventPublisher

logger = logging.getLogger(__name__)

# PoC 阶段标识（agent 层会复用）
POC_PHASE = "poc_verify"
POC_AGENT = "poc_verify_agent"

# 默认入口和端口（RuntimeProfile 缺失时的 fallback）
DEFAULT_ENTRY_FILE = "app.py"
DEFAULT_PORT = 5000


@dataclass
class PocVerifyResult:
    """PoC 验证服务执行结果摘要。"""

    success: bool
    verified_count: int = 0
    latent_count: int = 0
    skipped_count: int = 0
    evidence_count: int = 0
    target_started: bool = False
    error: str | None = None
    results: list[dict[str, Any]] = field(default_factory=list)


async def _publish(
    redis: Redis,
    task_id: str,
    event_type: str,
    payload: dict,
) -> None:
    """发布 WebSocket 事件。"""
    await EventPublisher.publish(redis, task_id, event_type, payload)


# ── 元数据提取：从 finding 中挖出路由 / 参数 ──


def _extract_route_path(finding: Finding) -> str | None:
    """从 finding 的 code_context/snippet 中提取 HTTP 路由路径。

    支持 Flask / FastAPI / http.server 等常见框架。
    """
    text = " ".join(filter(None, [finding.code_context or "", finding.snippet or ""]))
    if not text:
        return None

    patterns = [
        r'@app\.route\(\s*["\']([^"\']+)["\']',
        r'@bp\.route\(\s*["\']([^"\']+)["\']',
        r'(?:self\.)?path\s*==\s*["\']([^"\']+)["\']',
        r'path\.startswith\(\s*["\']([^"\']+)["\']',
        r'@(?:router|app|bp)\.(?:get|post|put|delete|patch)\(\s*["\']([^"\']+)["\']',
    ]
    for pattern in patterns:
        match = re.search(pattern, text)
        if match:
            return match.group(1)
    return None


def _extract_param_name(finding: Finding) -> str | None:
    """从 finding 中提取注入参数名（如 id）。"""
    text = " ".join(
        filter(
            None,
            [
                finding.source_code or "",
                finding.code_context or "",
                finding.snippet or "",
            ],
        )
    )
    if not text:
        return None

    patterns = [
        r'params\.get\(\s*["\']([^"\']+)["\']',
        r'request\.args\.get\(\s*["\']([^"\']+)["\']',
        r'request\.form\.get\(\s*["\']([^"\']+)["\']',
        r'request\.json\.get\(\s*["\']([^"\']+)["\']',
        r'request\.get_json\(\s*\)\.get\(\s*["\']([^"\']+)["\']',
    ]
    for pattern in patterns:
        match = re.search(pattern, text)
        if match:
            return match.group(1)
    return None


def _extract_route_method(finding: Finding, source_line: int | None = None) -> str:
    """根据源码路由装饰器判断接口 HTTP 方法，默认 GET。"""
    text = " ".join(filter(None, [finding.code_context or "", finding.snippet or ""]))
    if not text:
        return "GET"
    method_match = re.search(
        r'@(?:bp|app|router)\.route\(\s*["\']([^"\']+)["\']\s*,\s*methods\s*=\s*\[([^\]]*)\]',
        text,
        flags=re.DOTALL,
    )
    if method_match:
        methods = re.findall(r'["\'](\w+)["\']', method_match.group(2))
        if methods:
            return methods[0].upper()
    shorthand = re.search(
        r"@(?:bp|app|router)\.(get|post|put|delete|patch)\s*\(",
        text,
        flags=re.IGNORECASE,
    )
    if shorthand:
        return shorthand.group(1).upper()
    return "GET"


# ── 沙箱内源码读取（用于从源码中反查路由） ──


_ROUTE_FINDER_SCRIPT = r'''
import json
import re
import sys


def parse_route(line):
    long_match = re.search(
        r'@(?:app|bp|router)\.route\(\s*["\']([^"\']+)["\'](.*?)\)\s*$',
        line,
    )
    if long_match:
        path = long_match.group(1)
        rest = long_match.group(2)
        method_match = re.search(r'methods\s*=\s*\[([^\]]*)\]', rest)
        if method_match:
            methods = re.findall(r'["\'](\w+)["\']', method_match.group(1))
            return path, (methods[0].upper() if methods else "GET")
        return path, "GET"

    shorthand_match = re.search(
        r'@(?:app|bp|router)\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']',
        line,
        flags=re.IGNORECASE,
    )
    if shorthand_match:
        return shorthand_match.group(2), shorthand_match.group(1).upper()

    http_match = re.search(
        r'(?:self\.)?path\s*==\s*["\']([^"\']+)["\']',
        line,
    )
    if http_match:
        return http_match.group(1), "GET"
    return None


def extract_source_param(lines, start_line, end_line):
    source_patterns = [
        r'request\.(?:args|form|values)\.get\(\s*["\']([^"\']+)["\']',
        r'request\.(?:args|form|values)\[["\']([^"\']+)["\']',
        r'request\.get_json\(\)\.get\(\s*["\']([^"\']+)["\']',
        r'request\.json\.get\(\s*["\']([^"\']+)["\']',
    ]
    for line_no in range(start_line - 1, end_line):
        if line_no < 0 or line_no >= len(lines):
            continue
        line = lines[line_no]
        for pattern in source_patterns:
            match = re.search(pattern, line)
            if match:
                return match.group(1)
    return None


def main():
    filepath = sys.argv[1]
    target_line = int(sys.argv[2])
    source_line = int(sys.argv[3]) if len(sys.argv) > 3 else target_line
    with open(filepath, encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    route_info = []
    for line_no, line in enumerate(lines, 1):
        parsed = parse_route(line)
        if parsed:
            route_info.append((line_no, parsed[0], parsed[1]))

    best_route = None
    for item in route_info:
        if item[0] <= target_line:
            best_route = item
        else:
            break
    if best_route is None and route_info:
        best_route = route_info[0]

    route_path = None
    route_method = "GET"
    search_from = 1
    if best_route:
        route_path, route_method = best_route[1], best_route[2]
        search_from = best_route[0] + 1

    search_end = max(source_line, target_line)
    param_name = extract_source_param(lines, search_from, search_end)
    print(json.dumps({
        "path": route_path,
        "method": route_method,
        "param": param_name,
    }, ensure_ascii=False))


main()
'''


async def _find_route_metadata_in_file(
    db: AsyncSession,
    redis: Redis,
    task_id: str,
    file_path: str,
    source_line: int,
    target_line: int | None = None,
) -> dict | None:
    """在沙箱内从源码反查路由路径、HTTP 方法和最近参数。"""
    if not file_path:
        return None

    full_path = f"/workspace/source/{file_path}"
    script_path = "/workspace/tmp/route_finder.py"

    write_cmd = f"cat > {script_path} << 'ROUTE_EOF'\n{_ROUTE_FINDER_SCRIPT}\nROUTE_EOF"
    anchor_line = target_line or source_line
    exec_cmd = f"python {script_path} {full_path} {anchor_line} {source_line}"

    try:
        await exec_in_sandbox(
            db,
            redis,
            task_id,
            write_cmd,
            timeout=10,
            agent=POC_AGENT,
            phase=POC_PHASE,
            log_output=False,
        )
        result = await exec_in_sandbox(
            db,
            redis,
            task_id,
            exec_cmd,
            timeout=10,
            agent=POC_AGENT,
            phase=POC_PHASE,
            log_output=False,
        )
        stdout = result.get("stdout", "").strip()
        if not stdout:
            return None
        import json

        try:
            return json.loads(stdout)
        except json.JSONDecodeError:
            return {"path": stdout, "method": "GET", "param": None}
    except Exception as e:
        logger.warning("[poc_service] route_finder failed: %s", e)
        return None


# ── 主流程 ──


async def run_poc_verify(
    db: AsyncSession,
    redis: Redis,
    task_id: str,
) -> PocVerifyResult:
    """执行 PoC 验证主流程。

    这是 PoC 阶段的业务入口，由 poc_verify Agent 调用。
    Agent 只负责编排（发布 phase_started/phase_completed、catch 异常），
    实际业务逻辑全部在此函数内。

    流程：
    1. 读取任务下所有 unverified findings
    2. 过滤可动态验证的类型（其余标记为 latent）
    3. 从 RuntimeProfile 取入口文件 + 端口
    4. 启动临时目标服务
    5. 逐 finding 执行探针 + 验证 + 保存证据 + 更新状态
    6. 停止目标服务
    7. 返回 PocVerifyResult

    Args:
        db: 数据库会话
        redis: Redis 连接
        task_id: 任务 ID

    Returns:
        PocVerifyResult：验证结果摘要

    Raises:
        SandboxError: 沙箱执行失败（由 agent 层捕获）
    """
    # ── 1. 读取 unverified findings ──
    findings = await get_findings(db, task_id, status=FindingStatus.UNVERIFIED.value)
    logger.info(
        "[poc_service] Found %d unverified findings for task=%s",
        len(findings),
        task_id,
    )

    if not findings:
        await append_task_log(
            db,
            task_id,
            POC_PHASE,
            POC_AGENT,
            "info",
            "无未验证漏洞，PoC 阶段跳过",
        )
        return PocVerifyResult(success=True, verified_count=0)

    # ── 2. 过滤可验证的漏洞 ──
    verifiable: list[Finding] = []
    skipped: list[Finding] = []
    for f in findings:
        if is_verifiable(f.vuln_type):
            verifiable.append(f)
        else:
            skipped.append(f)

    # 不可验证的漏洞标记为 latent
    for f in skipped:
        await update_finding_status(
            db,
            redis,
            task_id,
            f.id,
            FindingStatus.LATENT.value,
            reason=f"漏洞类型 {f.vuln_type} 不适合动态验证，标记为潜在隐患",
        )
    if skipped:
        await db.flush()
        logger.info(
            "[poc_service] %d findings marked as latent (not verifiable)",
            len(skipped),
        )

    if not verifiable:
        await append_task_log(
            db,
            task_id,
            POC_PHASE,
            POC_AGENT,
            "info",
            f"无可验证漏洞（{len(skipped)} 个标记为潜在隐患）",
        )
        return PocVerifyResult(
            success=True,
            verified_count=0,
            latent_count=len(skipped),
            skipped_count=len(skipped),
        )

    # ── 3. 入口文件 + 端口 ──
    entry_file = DEFAULT_ENTRY_FILE
    port = DEFAULT_PORT
    profile = await get_runtime_profile(db, task_id)
    if profile:
        if profile.entry_points:
            first_entry = profile.entry_points[0] if profile.entry_points else None
            if first_entry and isinstance(first_entry, dict):
                entry_file = first_entry.get("file") or DEFAULT_ENTRY_FILE
        if profile.service_ports:
            first_port = profile.service_ports[0]
            if isinstance(first_port, dict):
                port = int(first_port.get("port") or DEFAULT_PORT)
            elif isinstance(first_port, (int, float)):
                port = int(first_port)

    await _publish(
        redis,
        task_id,
        "poc_start",
        {
            "message": "正在启动临时目标服务...",
            "verifiable_count": len(verifiable),
        },
    )

    # ── 4. 启动目标服务 ──
    target_result = await start_target_service(
        db, redis, task_id, entry_file=entry_file, port=port
    )

    if not target_result["success"]:
        error_msg = target_result.get("error", "目标服务启动失败")
        await append_task_log(
            db,
            task_id,
            POC_PHASE,
            POC_AGENT,
            "warning",
            f"目标服务启动失败，{len(verifiable)} 个漏洞保持 unverified: {error_msg[:300]}",
            detail={"error": error_msg},
        )
        return PocVerifyResult(
            success=True,
            verified_count=0,
            skipped_count=len(verifiable),
            target_started=False,
            error=error_msg,
        )

    base_url = target_result["base_url"]
    logger.info("[poc_service] Target service started: %s", base_url)

    # ── 5. 逐 finding 执行探针 ──
    verified_count = 0
    evidence_count = 0
    all_results: list[dict[str, Any]] = []

    for finding in verifiable:
        vuln_type = finding.vuln_type

        route_path = _extract_route_path(finding)
        param_name = _extract_param_name(finding)
        route_method = _extract_route_method(finding, finding.line_start)

        # finding 元数据没路由时，从沙箱源码反查
        ctx_file = finding.source_file or finding.file_path
        ctx_source_line = finding.source_line or finding.line_start
        ctx_line = finding.line_start or ctx_source_line
        route_meta = None
        if ctx_file and ctx_line:
            route_meta = await _find_route_metadata_in_file(
                db,
                redis,
                task_id,
                ctx_file,
                ctx_source_line,
                target_line=ctx_line,
            )

        if route_meta:
            route_path = route_path or route_meta.get("path")
            param_name = param_name or route_meta.get("param")
            if route_meta.get("method"):
                route_method = route_meta.get("method", route_method)

        logger.info(
            "[poc_service] Finding %s: route=%s, param=%s, method=%s",
            finding.id[:8],
            route_path,
            param_name,
            route_method,
        )

        probes = get_probes_for_vuln_type(
            vuln_type,
            base_path=route_path,
            param_name=param_name,
            http_method=route_method,
        )
        if not probes:
            await update_finding_status(
                db,
                redis,
                task_id,
                finding.id,
                FindingStatus.LATENT.value,
                reason=f"漏洞类型 {vuln_type} 没有匹配当前路由的验证探针，标记为潜在隐患",
            )
            logger.warning(
                "[poc_service] No probes for finding %s vuln_type=%s, marking latent",
                finding.id[:8],
                vuln_type,
            )
            continue

        await _publish(
            redis,
            task_id,
            "poc_start",
            {
                "finding_id": finding.id,
                "vuln_type": vuln_type,
                "probe_count": len(probes),
                "message": f"正在验证 {vuln_type} 漏洞 {finding.id[:8]}...",
            },
        )

        probe_results = await execute_probes_batch(
            db, redis, task_id, probes, base_url=base_url
        )

        # 验证
        vr = verify(vuln_type, probe_results)

        # 保存证据（每个探针一条记录）
        for pr in probe_results:
            await save_evidence(
                db,
                redis,
                task_id,
                finding.id,
                pr,
                verification_result={
                    "matched": vr.matched,
                    "validation_status": vr.validation_status,
                    "expected_feature": vr.expected_feature,
                    "actual_feature": vr.actual_feature,
                },
            )
            evidence_count += 1

        # 更新 finding 状态
        if vr.matched:
            new_status = FindingStatus.VERIFIED.value
            verified_count += 1
            await _publish(
                redis,
                task_id,
                "poc_verified",
                {
                    "finding_id": finding.id,
                    "vuln_type": vuln_type,
                    "matched": True,
                    "message": f"漏洞已验证: {vr.reason}",
                },
            )
        else:
            new_status = FindingStatus.LATENT.value
            await _publish(
                redis,
                task_id,
                "poc_failed",
                {
                    "finding_id": finding.id,
                    "vuln_type": vuln_type,
                    "matched": False,
                    "message": f"验证未通过: {vr.reason}",
                },
            )

        await update_finding_status(
            db,
            redis,
            task_id,
            finding.id,
            new_status,
            reason=vr.reason,
        )
        await db.flush()

        all_results.append(
            {
                "finding_id": finding.id,
                "vuln_type": vuln_type,
                "matched": vr.matched,
                "validation_status": vr.validation_status,
                "reason": vr.reason,
                "probe_count": len(probes),
            }
        )

        await append_task_log(
            db,
            task_id,
            POC_PHASE,
            POC_AGENT,
            "info" if vr.matched else "warning",
            f"漏洞 {finding.id[:8]} ({vuln_type}) 验证: {vr.validation_status} - {vr.reason}",
            detail={
                "finding_id": finding.id,
                "vuln_type": vuln_type,
                "matched": vr.matched,
                "probe_results": [
                    {
                        "name": pr.get("name"),
                        "status": pr.get("response_status"),
                        "body_len": len(pr.get("response_body", "")),
                        "error": pr.get("error"),
                    }
                    for pr in probe_results
                ],
            },
        )

    # ── 6. 停止目标服务 ──
    await stop_target_service(db, redis, task_id, port=port)

    latent_count = len(verifiable) - verified_count

    await append_task_log(
        db,
        task_id,
        POC_PHASE,
        POC_AGENT,
        "info",
        f"PoC 验证完成: {verified_count} 已验证, {latent_count} 潜在隐患, "
        f"{len(skipped)} 跳过, {evidence_count} 条证据",
    )

    return PocVerifyResult(
        success=True,
        verified_count=verified_count,
        latent_count=latent_count,
        skipped_count=len(skipped),
        evidence_count=evidence_count,
        target_started=True,
        results=all_results,
    )


# ── 证据查询（透传 poc_evidence_service） ──


async def list_evidences_for_finding(
    db: AsyncSession,
    finding_id: str,
) -> list:
    """获取某个 finding 的所有 PoC 证据。"""
    return await get_evidences_by_finding(db, finding_id)


async def list_evidences_for_task(
    db: AsyncSession,
    task_id: str,
) -> list:
    """获取某个任务的所有 PoC 证据。"""
    return await get_evidences_by_task(db, task_id)
