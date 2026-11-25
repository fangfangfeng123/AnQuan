"""业务逻辑服务层包。

本包是系统的核心业务逻辑层，所有数据库操作和业务编排集中于此。

分层约定：
- services/<domain>_service.py 是该领域唯一的业务门面（router/agent 都从这里调）
- services/poc_evidence_service.py 与 services/poc_service.py 拆分：
    * poc_service：PoC 主流程编排（启动目标服务/执行探针/存证据/更新 finding）
    * poc_evidence_service：纯证据 CRUD（保存/查询），便于独立复用
- 底层无状态工具（payloads/executor/verifier）保留在 poc/ 包内
"""

from app.services.audit_service import get_audit_log, list_audit_logs, log_action
from app.services.poc_evidence_service import (
    get_evidences_by_finding,
    get_evidences_by_task,
    save_evidence,
)
from app.services.poc_service import (
    PocVerifyResult,
    list_evidences_for_finding,
    list_evidences_for_task,
    run_poc_verify,
)
from app.services.project_service import (
    archive_project,
    create_project,
    get_project,
    list_projects,
    restore_project,
    update_project,
)
from app.services.task_service import (
    archive_task,
    create_task,
    get_task,
    list_task_logs,
    list_tasks,
    start_task,
    stop_task,
)

__all__ = [
    # audit
    "get_audit_log",
    "list_audit_logs",
    "log_action",
    # project
    "archive_project",
    "create_project",
    "get_project",
    "list_projects",
    "restore_project",
    "update_project",
    # task
    "archive_task",
    "create_task",
    "get_task",
    "list_task_logs",
    "list_tasks",
    "start_task",
    "stop_task",
    # poc (主流程)
    "PocVerifyResult",
    "run_poc_verify",
    # poc (证据查询)
    "list_evidences_for_finding",
    "list_evidences_for_task",
    # poc (底层)
    "get_evidences_by_finding",
    "get_evidences_by_task",
    "save_evidence",
]