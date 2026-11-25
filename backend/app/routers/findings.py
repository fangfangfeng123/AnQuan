"""漏洞数据路由模块。

提供任务漏洞列表、统计、详情和状态更新。
"""

from redis.asyncio import Redis
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.errors import FindingNotFoundError, TaskNotFoundError
from app.core.redis import get_redis
from app.core.security import get_current_user
from app.services.poc_evidence_service import get_evidences_by_finding
from app.schemas.finding import (
    FindingListResponse,
    FindingResponse,
    FindingSummaryResponse,
    FindingUpdateRequest,
)
from app.schemas.poc_evidence import (
    PocEvidenceListResponse,
    PocEvidenceResponse,
)
from app.services.finding_service import (
    get_finding,
    get_finding_summary,
    get_findings,
    update_finding_status,
)
from app.services.task_service import get_task

router = APIRouter(tags=["漏洞数据"])


@router.get(
    "/tasks/{task_id}/findings",
    response_model=FindingListResponse,
)
async def list_task_findings(
    task_id: str,
    severity: str | None = Query(None),
    status: str | None = Query(None),
    vuln_type: str | None = Query(None),
    detected_by: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
    operator: str = Depends(get_current_user),
) -> FindingListResponse:
    """获取任务下的漏洞列表。"""
    if await get_task(db, task_id) is None:
        raise TaskNotFoundError(task_id)

    items = await get_findings(
        db,
        task_id,
        severity=severity,
        status=status,
        vuln_type=vuln_type,
        detected_by=detected_by,
    )
    summary = await get_finding_summary(db, task_id)
    return FindingListResponse(
        items=[FindingResponse.model_validate(item) for item in items],
        total=summary["total"],
        verified_count=summary["by_status"].get("verified", 0),
        unverified_count=summary["by_status"].get("unverified", 0),
    )


@router.get(
    "/tasks/{task_id}/findings/summary",
    response_model=FindingSummaryResponse,
)
async def task_finding_summary(
    task_id: str,
    db: AsyncSession = Depends(get_db),
    operator: str = Depends(get_current_user),
) -> FindingSummaryResponse:
    """获取漏洞统计摘要。"""
    if await get_task(db, task_id) is None:
        raise TaskNotFoundError(task_id)
    summary = await get_finding_summary(db, task_id)
    return FindingSummaryResponse(**summary)


@router.get("/findings/{finding_id}", response_model=FindingResponse)
async def finding_detail(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
    operator: str = Depends(get_current_user),
) -> FindingResponse:
    """获取漏洞详情。"""
    finding = await get_finding(db, finding_id)
    if finding is None:
        raise FindingNotFoundError(finding_id)
    return FindingResponse.model_validate(finding)


@router.patch("/findings/{finding_id}", response_model=FindingResponse)
async def update_finding(
    finding_id: str,
    body: FindingUpdateRequest,
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis),
    operator: str = Depends(get_current_user),
) -> FindingResponse:
    """更新漏洞验证状态。"""
    finding = await get_finding(db, finding_id)
    if finding is None:
        raise FindingNotFoundError(finding_id)

    updated = await update_finding_status(
        db=db,
        redis=redis,
        task_id=finding.task_id,
        finding_id=finding.id,
        status=body.status or finding.status,
        severity=body.severity,
        cvss_score=body.cvss_score,
        reason=body.false_positive_reason,
    )
    await db.commit()
    return FindingResponse.model_validate(updated)


@router.get(
    "/findings/{finding_id}/evidence",
    response_model=PocEvidenceListResponse,
)
async def list_finding_evidence(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
    operator: str = Depends(get_current_user),
) -> PocEvidenceListResponse:
    """获取漏洞的 PoC 验证证据列表。"""
    finding = await get_finding(db, finding_id)
    if finding is None:
        raise FindingNotFoundError(finding_id)

    evidences = await get_evidences_by_finding(db, finding_id)
    return PocEvidenceListResponse(
        items=[PocEvidenceResponse.model_validate(e) for e in evidences],
        total=len(evidences),
    )
