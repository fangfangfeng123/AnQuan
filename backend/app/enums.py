"""全局枚举与状态定义。

本模块集中定义系统所有枚举类型，避免散落在各模块。
"""

from enum import Enum


class TaskStatus(str, Enum):
    """任务状态。"""

    CREATED = "created"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    STOPPED = "stopped"


class PhaseName(str, Enum):
    """评估阶段名称（固定五阶段流水线）。"""

    RECON = "recon"
    CODE_AUDIT = "code_audit"
    POC_VERIFY = "poc_verify"
    EXPLOIT_CHAIN = "exploit_chain"
    REPORT_GEN = "report_gen"


class PhaseStatus(str, Enum):
    """单个阶段的执行状态。"""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class FindingStatus(str, Enum):
    """漏洞状态。"""

    UNVERIFIED = "unverified"
    VERIFIED = "verified"
    LATENT = "latent"
    FALSE_POSITIVE = "false_positive"
    ADOPTED = "adopted"  # 补丁被采纳后的终态


class Severity(str, Enum):
    """严重等级（CVSS 对齐）。"""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnerabilityType(str, Enum):
    """漏洞类型。"""

    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    SSRF = "ssrf"
    DESERIALIZATION = "deserialization"
    BROKEN_ACCESS = "broken_access"
    INSECURE_CONFIG = "insecure_config"
    SENSITIVE_DATA = "sensitive_data"
    OTHER = "other"


class NetworkMode(str, Enum):
    """沙箱网络模式。"""

    ISOLATED = "isolated"
    RESTRICTED = "restricted"


class SandboxStatus(str, Enum):
    """沙箱容器生命周期状态。"""

    CREATING = "creating"
    READY = "ready"
    RUNNING = "running"
    DESTROYING = "destroying"
    DESTROYED = "destroyed"
    ERROR = "error"


class LlmMode(str, Enum):
    """LLM 调用模式。"""

    OPENAI = "openai"
    OLLAMA = "ollama"
    DEMO = "demo"


class PocType(str, Enum):
    """PoC 验证类型。"""

    HTTP = "http"
    COMMAND = "command"
    FILE_READ = "file_read"
    DNS = "dns"
    TIMING = "timing"


class ValidationStatus(str, Enum):
    """校验结果状态。"""

    PENDING = "pending"
    PASSED = "passed"
    FAILED = "failed"
    ERROR = "error"


class AdoptStatus(str, Enum):
    """补丁采纳状态。"""

    NOT_ADOPTED = "not_adopted"
    ADOPTED = "adopted"


class PrivilegeLevel(str, Enum):
    """PoC 达到的权限级别。"""

    ANONYMOUS = "anonymous"
    USER = "user"
    ADMIN = "admin"


class AgentResult(str, Enum):
    """Agent 执行结果。"""

    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    SKIPPED = "skipped"


class LogLevel(str, Enum):
    """日志级别。"""

    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class ExportFormat(str, Enum):
    """报告导出格式。"""

    MARKDOWN = "markdown"
    HTML = "html"
    PDF = "pdf"


class SourceType(str, Enum):
    """项目源码来源类型。"""

    GIT = "git"
    ARCHIVE = "archive"


class AuditAction(str, Enum):
    """审计动作类型。"""

    CREATE = "create"
    START = "start"
    STOP = "stop"
    DELETE = "delete"
    ARCHIVE = "archive"
    RESTORE = "restore"
    EXPORT = "export"
    CONFIG_UPDATE = "config_update"


class OverallRisk(str, Enum):
    """整体风险评级。"""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    SECURE = "secure"


class ProjectStatus(str, Enum):
    """项目状态。"""

    ACTIVE = "active"
    ARCHIVED = "archived"


class UserRole(str, Enum):
    """系统用户角色。"""

    SECURITY_AUDITOR = "security_auditor"
    DEVELOPER = "developer"
    ADMIN = "admin"


# ── 阶段执行顺序 ──
PHASE_ORDER: list[str] = [
    PhaseName.RECON.value,
    PhaseName.CODE_AUDIT.value,
    PhaseName.POC_VERIFY.value,
    PhaseName.EXPLOIT_CHAIN.value,
    PhaseName.REPORT_GEN.value,
]
