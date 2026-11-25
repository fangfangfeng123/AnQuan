"""统一异常类型定义模块。

本模块定义系统的业务异常层次。
所有异常都映射为 HTTP 响应，由 main.py 的全局异常处理器统一处理。
"""

from fastapi import HTTPException


class AppError(Exception):
    """所有自定义业务异常的基类。

    Attributes:
        status_code: HTTP 状态码
        code: 业务错误码（机器可读）
        message: 用户可读的错误描述
        detail: 额外上下文（可选）
    """

    def __init__(
        self,
        status_code: int = 500,
        code: str = "internal_error",
        message: str = "服务器内部错误",
        detail: dict | None = None,
    ) -> None:
        self.status_code = status_code
        self.code = code
        self.message = message
        self.detail = detail or {}
        super().__init__(message)


class TaskNotFoundError(AppError):
    def __init__(self, task_id: str) -> None:
        super().__init__(
            status_code=404,
            code="task_not_found",
            message=f"任务不存在: {task_id}",
            detail={"task_id": task_id},
        )


class ProjectNotFoundError(AppError):
    def __init__(self, project_id: str) -> None:
        super().__init__(
            status_code=404,
            code="project_not_found",
            message=f"项目不存在: {project_id}",
            detail={"project_id": project_id},
        )


class FindingNotFoundError(AppError):
    def __init__(self, finding_id: str) -> None:
        super().__init__(
            status_code=404,
            code="finding_not_found",
            message=f"漏洞不存在: {finding_id}",
            detail={"finding_id": finding_id},
        )


class SandboxError(AppError):
    def __init__(self, message: str, detail: dict | None = None) -> None:
        super().__init__(
            status_code=500, code="sandbox_error", message=message, detail=detail
        )


class ScanError(AppError):
    def __init__(self, message: str, detail: dict | None = None) -> None:
        super().__init__(
            status_code=500, code="scan_error", message=message, detail=detail
        )


class LlmError(AppError):
    def __init__(self, message: str, detail: dict | None = None) -> None:
        super().__init__(
            status_code=502, code="llm_error", message=message, detail=detail
        )


class LlmBudgetExceededError(AppError):
    def __init__(self, used: int, limit: int) -> None:
        super().__init__(
            status_code=429,
            code="llm_budget_exceeded",
            message=f"LLM token 预算超限: 已用 {used}, 上限 {limit}",
            detail={"used": used, "limit": limit},
        )


class ValidationError(AppError):
    def __init__(self, message: str, detail: dict | None = None) -> None:
        super().__init__(
            status_code=422, code="validation_error", message=message, detail=detail
        )


class ExportError(AppError):
    def __init__(self, message: str, detail: dict | None = None) -> None:
        super().__init__(
            status_code=500, code="export_error", message=message, detail=detail
        )


class TaskAlreadyRunningError(AppError):
    def __init__(self, task_id: str) -> None:
        super().__init__(
            status_code=409,
            code="task_already_running",
            message=f"任务已在运行中: {task_id}",
            detail={"task_id": task_id},
        )


class SnapshotNotFoundError(AppError):
    def __init__(self, snapshot_id: str) -> None:
        super().__init__(
            status_code=404,
            code="snapshot_not_found",
            message=f"源码快照不存在: {snapshot_id}",
            detail={"snapshot_id": snapshot_id},
        )


class AuthenticationError(AppError):
    def __init__(self, message: str = "认证失败") -> None:
        super().__init__(status_code=401, code="authentication_failed", message=message)


class AuthorizationError(AppError):
    """权限不足异常（403）。"""

    def __init__(self, message: str = "权限不足") -> None:
        super().__init__(status_code=403, code="authorization_failed", message=message)


class PatchNotFoundError(AppError):
    def __init__(self, patch_id: str) -> None:
        super().__init__(
            status_code=404,
            code="patch_not_found",
            message=f"补丁不存在: {patch_id}",
            detail={"patch_id": patch_id},
        )
