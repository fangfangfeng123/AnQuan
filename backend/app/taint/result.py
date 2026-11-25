"""污点分析结果模型模块。

本模块定义污点分析引擎的输出数据结构：

- TaintStepInfo：传播路径中的单步信息（类型/文件/行号/代码/说明）
- SourceInfo：污点源信息（文件/行号/代码/规则ID/变量名）
- SinkInfo：汇聚点信息（文件/行号/代码/规则ID/CWE/OWASP/漏洞类型）
- SanitizerInfo：净化器信息（文件/行号/代码/规则ID/类型）
- TaintResult：完整分析结果（source/sink/taint_path/has_sanitizer/is_vulnerable）

TaintResult 用于转换为 Finding 记录入库。
"""

from dataclasses import dataclass, field


@dataclass
class TaintStepInfo:
    """污点传播路径中的单步信息。"""

    step: int  # 步骤序号（从 1 开始）
    type: str  # 类型：source / transfer / sink / sanitizer
    file: str  # 文件相对路径
    line: int  # 行号
    code: str  # 该行代码内容
    detail: str = ""  # 该步骤的说明


@dataclass
class SourceInfo:
    """污点源信息。"""

    file: str  # 文件相对路径
    line: int  # 行号
    code: str  # 源码行内容
    rule_id: str  # 匹配的 SourceRule ID
    var_name: str = ""  # 被赋值的变量名（如能提取）


@dataclass
class SinkInfo:
    """污点汇聚点信息。"""

    file: str  # 文件相对路径
    line: int  # 行号
    code: str  # 源码行内容
    rule_id: str  # 匹配的 SinkRule ID
    vuln_type: str  # 漏洞类型
    cwe_id: str  # CWE 编号
    owasp: str  # OWASP 分类
    sink_expr: str = ""  # Sink 表达式（如 "db.session.execute(sql)"）


@dataclass
class SanitizerInfo:
    """安全净化器信息。"""

    file: str  # 文件相对路径
    line: int  # 行号
    code: str  # 源码行内容
    rule_id: str  # 匹配的 SanitizerRule ID
    sanitizer_type: str  # 防护的漏洞类型
    description: str = ""


@dataclass
class TaintResult:
    """完整污点分析结果。

    一条 TaintResult 对应一条潜在的漏洞发现，可转换为 Finding 入库。

    Attributes:
        source_info: 污点源信息
        sink_info: 汇聚点信息
        taint_path: 传播路径（TaintStepInfo 列表）
        has_sanitizer: 路径中是否存在净化器
        sanitizer_info: 净化器信息（如有）
        is_vulnerable: 最终是否判定为漏洞
        confidence: 置信度 0-1
        detected_by: 检测来源（taint_engine / semgrep / bandit）
    """

    source_info: SourceInfo
    sink_info: SinkInfo
    taint_path: list[TaintStepInfo] = field(default_factory=list)
    has_sanitizer: bool = False
    sanitizer_info: SanitizerInfo | None = None
    is_vulnerable: bool = False
    confidence: float = 0.0
    detected_by: str = "taint_engine"

    def to_finding_dict(self) -> dict:
        """将 TaintResult 转换为 Finding ORM 可用的字典格式。

        Returns:
            包含 Finding 所需全部字段的字典
        """
        return {
            "vuln_type": self.sink_info.vuln_type,
            "cwe_id": self.sink_info.cwe_id,
            "owasp": self.sink_info.owasp,
            "status": "unverified",
            "severity": "info",  # 由 scoring/cvss.py 计算后覆盖
            "cvss_score": None,
            "cvss_vector": None,
            "file_path": self.sink_info.file,
            "line_start": self.sink_info.line,
            "line_end": self.sink_info.line,
            "snippet": self.sink_info.code,
            "source_file": self.source_info.file,
            "source_line": self.source_info.line,
            "source_code": self.source_info.code,
            "sink_file": self.sink_info.file,
            "sink_line": self.sink_info.line,
            "sink_code": self.sink_info.code,
            "taint_path": [
                {
                    "step": s.step,
                    "type": s.type,
                    "file": s.file,
                    "line": s.line,
                    "code": s.code,
                    "detail": s.detail,
                }
                for s in self.taint_path
            ],
            "code_context": None,
            "detected_by": self.detected_by,
            "confidence": self.confidence,
            "remediation": None,
        }
