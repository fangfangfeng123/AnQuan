"""认证与当前用户相关请求/响应模型。"""

from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    """登录请求。"""

    username: str = Field(..., min_length=1, max_length=128)
    password: str = Field(..., min_length=1, max_length=128)


class LoginResponse(BaseModel):
    """登录成功响应。"""

    token: str
    username: str
    role: str
    display_name: str
    permissions: list[str] = []


class CurrentUserResponse(BaseModel):
    """当前登录用户响应。"""

    username: str
    role: str
    auth_mode: str = "static_token"
    display_name: str = ""
