"""漏洞相关请求/响应模型。

本模块定义漏洞数据的 API 请求和响应模型：
- TaintStep：污点传播路径中的单步
- FindingResponse：漏洞详情响应（含 file_path / line_range / snippet / cvss / source / sink / taint_path）
- FindingDetailResponse：漏洞完整详情（含 poc_evidence / fix_patch 占位）
- FindingListResponse：漏洞分页列表
- FindingSummaryResponse：漏洞统计摘要（按严重等级和验证状态分类）
- FindingUpdateRequest：更新漏洞状态（status / false_positive_reason）
- FindingFilterRequest：漏洞过滤条件（severity / status / vuln_type / detected_by）
"""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class TaintStep(BaseModel):
    """污点传播路径中的单步。"""

    step: int = Field(..., description="步骤序号（从 1 开始）")
    type: str = Field(..., description="步骤类型：source / transfer / sink / sanitizer")
    file: str = Field(..., description="文件相对路径")
    line: int = Field(..., description="行号")
    code: str = Field(..., description="该行代码内容")
    detail: str | None = Field(None, description="该步骤的说明")


class FindingResponse(BaseModel):
    """漏洞详情响应。"""

    id: str
    task_id: str
    vuln_type: str = Field(..., description="漏洞类型")
    cwe_id: str | None = Field(None, description="CWE 编号，如 CWE-89")
    owasp: str | None = Field(None, description="OWASP Top 10 分类，如 A03:2021")
    status: str = Field(
        "unverified", description="验证状态: unverified/verified/latent/false_positive"
    )
    severity: str = Field("info", description="严重等级: critical/high/medium/low/info")
    cvss_score: float | None = Field(None, description="CVSS 3.x 分数 0-10")
    cvss_vector: str | None = Field(None, description="CVSS 向量字符串")

    # 漏洞触发位置
    file_path: str | None = Field(None, description="漏洞所在文件相对路径")
    line_start: int | None = Field(None, description="起始行号")
    line_end: int | None = Field(None, description="结束行号")
    snippet: str | None = Field(None, description="命中代码片段")

    # Source / Sink
    source_file: str | None = Field(None, description="Source 文件路径")
    source_line: int | None = Field(None, description="Source 行号")
    source_code: str | None = Field(None, description="Source 代码内容")
    sink_file: str | None = Field(None, description="Sink 文件路径")
    sink_line: int | None = Field(None, description="Sink 行号")
    sink_code: str | None = Field(None, description="Sink 代码内容")

    # 污点路径
    taint_path: list[dict] | None = Field(None, description="Source->Sink 污点传播路径")

    # 元数据
    detected_by: str = Field(
        "semgrep", description="检测工具: semgrep/bandit/taint_engine"
    )
    confidence: float = Field(0.0, description="置信度 0-1")
    remediation: str | None = Field(None, description="修复建议")
    created_at: datetime | None = None

    class Config:
        from_attributes = True


class FindingDetailResponse(FindingResponse):
    """漏洞完整详情（含 PoC 证据和修复补丁）。"""

    code_context: str | None = Field(None, description="漏洞上下文代码")
    poc_evidence: dict[str, Any] | None = Field(None, description="PoC 验证证据")
    fix_patch: dict[str, Any] | None = Field(None, description="AI 修复补丁 Diff")


class FindingListResponse(BaseModel):
    """漏洞列表响应。"""

    items: list[FindingResponse]
    total: int
    verified_count: int = 0
    unverified_count: int = 0


class FindingSummaryResponse(BaseModel):
    """漏洞统计摘要。"""

    total: int = 0
    by_severity: dict[str, int] = Field(
        default_factory=lambda: {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }
    )
    by_status: dict[str, int] = Field(
        default_factory=lambda: {
            "unverified": 0,
            "verified": 0,
            "latent": 0,
            "false_positive": 0,
        }
    )
    by_type: dict[str, int] = Field(default_factory=dict)


class FindingUpdateRequest(BaseModel):
    """更新漏洞状态请求。"""

    status: str | None = Field(
        None, description="新状态: verified/unverified/false_positive"
    )
    severity: str | None = Field(None, description="覆盖严重等级")
    cvss_score: float | None = Field(None, description="覆盖 CVSS 分数")
    false_positive_reason: str | None = Field(None, description="误报说明")


class FindingFilterParams(BaseModel):
    """漏洞过滤条件。"""

    severity: str | None = Field(None, description="按严重等级过滤")
    status: str | None = Field(None, description="按验证状态过滤")
    vuln_type: str | None = Field(None, description="按漏洞类型过滤")
    detected_by: str | None = Field(None, description="按检测工具过滤")
