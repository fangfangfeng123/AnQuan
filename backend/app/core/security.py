"""认证与授权中间件模块。

本模块负责 API 访问控制：
- MVP 阶段：静态 Token 校验（Authorization: Bearer <token> 或 X-API-Token 头）
- 从请求头提取 token，与 Settings.API_TOKEN 比对
- 校验失败返回 401 Unauthorized
- 提供 get_current_user 依赖注入（返回 operator 用户名）
- 提供 get_current_role 依赖注入（返回角色字符串）
- 提供 require_role(*roles) 依赖工厂（角色权限校验，不足返回 403）

角色体系（MVP 阶段）：
- 静态 Token 映射为 admin 角色
- 支持 token 格式 "role:token" 指定角色（如 "developer:dev-api-token-change-in-production"）
- 后续扩展：OAuth2 + JWT + 用户表
"""

from fastapi import Depends, Header
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.config import get_settings
from app.core.errors import AuthenticationError, AuthorizationError
from app.enums import UserRole

settings = get_settings()
security_scheme = HTTPBearer(auto_error=False)

# MVP 演示账号：正式环境应改为数据库或外部身份认证系统。
DEMO_ACCOUNTS: dict[str, dict] = {
    "admingcs": {
        "password": "admingcs",
        "role": UserRole.SECURITY_AUDITOR.value,
        "display_name": "安全工程师 / 审计人员",
    },
    "adminyf": {
        "password": "adminyf",
        "role": UserRole.DEVELOPER.value,
        "display_name": "研发人员",
    },
    "admingly": {
        "password": "admingly",
        "role": UserRole.ADMIN.value,
        "display_name": "系统管理员",
    },
}


def _extract_token(
    credentials: HTTPAuthorizationCredentials | None,
    x_api_token: str | None,
) -> str | None:
    """从请求头提取 token。"""
    if credentials and credentials.credentials:
        return credentials.credentials
    if x_api_token:
        return x_api_token
    return None


def _parse_token(token: str) -> tuple[str, str]:
    """解析 token，返回 (role, username)。

    支持两种格式：
    - "username:role:actual_token" → 指定账号和角色
    - "role:actual_token" → 指定角色（如 "developer:dev-api-token-xxx"）
    - "actual_token" → 默认 admin 角色

    Returns:
        (role, username) 元组
    """
    # 检查是否为 "role:token" 格式
    if ":" in token:
        parts = token.split(":")
        if len(parts) == 3:
            username, role_str, actual_token = parts
        else:
            role_str, actual_token = parts[0], ":".join(parts[1:])
            username = role_str
        # 验证 actual_token 部分是否匹配 API_TOKEN
        if actual_token != settings.API_TOKEN:
            raise AuthenticationError("认证凭据无效")
        # 验证角色是否合法
        valid_roles = {r.value for r in UserRole}
        if role_str not in valid_roles:
            raise AuthenticationError(f"无效角色: {role_str}")
        return role_str, username

    # 普通 token 格式：默认 admin 角色
    if token != settings.API_TOKEN:
        raise AuthenticationError("认证凭据无效")

    return UserRole.ADMIN.value, "admin"


async def _authenticate_token(
    credentials: HTTPAuthorizationCredentials | None,
    x_api_token: str | None,
) -> tuple[str, str]:
    """内部统一鉴权，返回 (role, username)。

    被 get_current_user 和 get_current_role 共用，避免重复解析 token。
    """
    token = _extract_token(credentials, x_api_token)
    if not token:
        raise AuthenticationError("缺少认证凭据，请提供 Bearer Token 或 X-API-Token")
    return _parse_token(token)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(security_scheme),
    x_api_token: str | None = Header(default=None, alias="X-API-Token"),
) -> str:
    """认证依赖：返回当前操作人用户名。

    支持两种传递方式：
    - Bearer Token（标准 HTTP Bearer 认证）
    - X-API-Token 请求头（方便前端调试）

    返回值：operator（操作人标识）
    """
    _role, username = await _authenticate_token(credentials, x_api_token)
    return username


async def get_current_role(
    credentials: HTTPAuthorizationCredentials | None = Depends(security_scheme),
    x_api_token: str | None = Header(default=None, alias="X-API-Token"),
) -> str:
    """认证依赖：返回当前用户角色。

    MVP 阶段静态 token → admin 角色。
    支持 "role:token" 格式指定其他角色。

    返回值：role 字符串（admin / security_auditor / developer）
    """
    role, _username = await _authenticate_token(credentials, x_api_token)
    return role


def require_role(*allowed_roles: str):
    """依赖工厂：检查当前用户角色是否在允许列表里。

    用法：
        @router.put("/config", dependencies=[Depends(require_role("admin"))])

    或作为参数依赖：
        async def handler(role: str = Depends(require_role("admin"))):
            ...

    Args:
        allowed_roles: 允许的角色列表

    Returns:
        依赖函数，校验通过时返回 role 字符串

    Raises:
        AuthorizationError: 角色不在允许列表中（403）
    """

    async def _check_role(
        role: str = Depends(get_current_role),
    ) -> str:
        if role not in allowed_roles:
            raise AuthorizationError(
                f"需要角色 {list(allowed_roles)}，当前角色: {role}"
            )
        return role

    return _check_role
