"""认证与角色路由。"""

from fastapi import APIRouter, Depends

from app.core.config import get_settings
from app.core.errors import AuthenticationError
from app.core.security import (
    DEMO_ACCOUNTS,
    get_current_role,
    get_current_user,
)
from app.enums import UserRole
from app.schemas.auth import CurrentUserResponse, LoginRequest, LoginResponse

router = APIRouter(prefix="/auth", tags=["认证"])
settings = get_settings()


@router.post("/login", response_model=LoginResponse)
async def login(
    body: LoginRequest,
) -> LoginResponse:
    """使用演示账号登录，返回带账号和角色的访问令牌。"""
    account = DEMO_ACCOUNTS.get(body.username)
    if account is None or account["password"] != body.password:
        raise AuthenticationError("账号或密码错误")

    role = account["role"]
    display_name = account["display_name"]
    permissions = {
        UserRole.ADMIN.value: [
            "project:create",
            "project:delete",
            "task:create",
            "task:delete",
            "report:delete",
            "audit:manage",
            "config:manage",
        ],
        UserRole.SECURITY_AUDITOR.value: [
            "project:create",
            "task:create",
            "report:export",
            "evidence:view",
        ],
        UserRole.DEVELOPER.value: [
            "project:view",
            "finding:view",
            "patch:adopt",
        ],
    }.get(role, [])

    token = f"{body.username}:{role}:{settings.API_TOKEN}"
    return LoginResponse(
        token=token,
        username=body.username,
        role=role,
        display_name=display_name,
        permissions=permissions,
    )


@router.get("/me", response_model=CurrentUserResponse)
async def get_me(
    operator: str = Depends(get_current_user),
    role: str = Depends(get_current_role),
) -> CurrentUserResponse:
    """返回当前 Token 对应的用户信息（用户名 + 角色）。"""
    from app.core.security import DEMO_ACCOUNTS

    display_name = DEMO_ACCOUNTS.get(operator, {}).get(
        "display_name", operator if operator not in ("admin",) else "系统管理员"
    )
    return CurrentUserResponse(
        username=operator,
        role=role,
        display_name=display_name,
    )
