"""FastAPI 路由聚合模块。

本模块导入并聚合所有子路由器，供 main.py 注册。
"""

from app.routers.attack_chains import router as attack_chains_router
from app.routers.audit_logs import router as audit_logs_router
from app.routers.auth import router as auth_router
from app.routers.dashboard import router as dashboard_router
from app.routers.findings import router as findings_router
from app.routers.llm import router as llm_router
from app.routers.patches import router as patches_router
from app.routers.projects import router as projects_router
from app.routers.recon import router as recon_router
from app.routers.reports import router as reports_router
from app.routers.sandbox import router as sandbox_router
from app.routers.targets import router as targets_router
from app.routers.tasks import router as tasks_router

__all__ = [
    "attack_chains_router",
    "audit_logs_router",
    "auth_router",
    "dashboard_router",
    "findings_router",
    "llm_router",
    "patches_router",
    "projects_router",
    "recon_router",
    "reports_router",
    "sandbox_router",
    "targets_router",
    "tasks_router",
]
