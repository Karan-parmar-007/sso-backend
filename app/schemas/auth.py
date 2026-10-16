from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, EmailStr, Field


class MessageResponse(BaseModel):
    message: str


class UserInfoResponse(BaseModel):
    id: str
    name: str
    email: EmailStr
    email_verified: bool
    role_name: Optional[str] = None
    app_roles: dict[str, list[str]] = Field(default_factory=dict)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class SessionResponse(BaseModel):
    authenticated: bool
    user: Optional[UserInfoResponse] = None
    session_id: Optional[str] = None
    # Set when this call refreshed the session.
    access_token_expires_in: Optional[int] = None


class SignupRequest(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)
    remember_me: bool = False


class AuthResponse(BaseModel):
    user: UserInfoResponse
    access_token_expires_in: int
    message: str


class TokenResponse(BaseModel):
    access_token_expires_in: int
    message: str


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str = Field(min_length=8, max_length=128)
    confirm_password: str = Field(min_length=8, max_length=128)


class ChangePasswordRequest(BaseModel):
    old_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=8, max_length=128)
    confirm_password: str = Field(min_length=8, max_length=128)


class RequestEmailChangeRequest(BaseModel):
    new_email: EmailStr
    current_password: str = Field(min_length=1, max_length=256)


class ResendVerificationRequest(BaseModel):
    email: EmailStr


class ConfirmEmailChangeRequest(BaseModel):
    token: str


class VerifyEmailRequest(BaseModel):
    token: str


class AdminUserListItem(BaseModel):
    id: str
    name: str
    email: EmailStr
    email_verified: bool
    role_name: Optional[str] = None
    app_roles: dict[str, list[str]] = Field(default_factory=dict)
    created_at: Optional[datetime] = None


class AdminUsersResponse(BaseModel):
    total_count: int
    page: int
    page_size: int
    total_pages: int
    users: list[AdminUserListItem]


class AdminChangeRoleRequest(BaseModel):
    role_name: str = Field(min_length=1, max_length=50)


class AdminResetPasswordResponse(BaseModel):
    message: str
    email_sent: bool
    reset_link: Optional[str] = None


class AdminSetAppRolesRequest(BaseModel):
    roles: list[str] = Field(default_factory=list, max_length=20)


_CLIENT_ID_PATTERN = r"^[a-z][a-z0-9_-]{1,39}$"


class AdminClientBase(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=100)
    first_party: Optional[bool] = None
    roles: Optional[list[str]] = Field(default=None, max_length=50)
    redirect_uris: Optional[list[str]] = Field(default=None, max_length=20)
    post_logout_redirect_uris: Optional[list[str]] = Field(default=None, max_length=20)
    allowed_scopes: Optional[list[str]] = None


class AdminCreateClientRequest(AdminClientBase):
    client_id: str = Field(pattern=_CLIENT_ID_PATTERN)
    name: str = Field(min_length=1, max_length=100)
    confidential: bool = False


class AdminUpdateClientRequest(AdminClientBase):
    pass


class AdminClientItem(BaseModel):
    client_id: str
    name: str
    first_party: bool
    roles: list[str]
    redirect_uris: list[str]
    post_logout_redirect_uris: list[str]
    allowed_scopes: list[str]
    confidential: bool
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class AdminClientWithSecret(AdminClientItem):
    # Shown exactly once, on creation / rotation.
    client_secret: Optional[str] = None


class AdminClientsResponse(BaseModel):
    total_count: int
    clients: list[AdminClientItem]


class AuditEventItem(BaseModel):
    id: str
    event: str
    created_at: datetime
    user_id: Optional[str] = None
    email: Optional[str] = None
    actor_id: Optional[str] = None
    session_id: Optional[str] = None
    ip: Optional[str] = None
    user_agent: Optional[str] = None
    meta: Optional[dict[str, Any]] = None


class AuditEventsResponse(BaseModel):
    total_count: int
    page: int
    page_size: int
    events: list[AuditEventItem]


class AdminRoleItem(BaseModel):
    id: str
    name: str
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class AdminRolesResponse(BaseModel):
    total_count: int
    roles: list[AdminRoleItem]


class AdminCreateRoleRequest(BaseModel):
    name: str = Field(min_length=1, max_length=50, pattern=r"^[a-z][a-z0-9_]*$")


class AdminUpdateUserRequest(BaseModel):
    email: Optional[EmailStr] = None
    email_verified: Optional[bool] = None


class SessionItem(BaseModel):
    id: str
    device_info: Optional[str] = None
    ip_address: Optional[str] = None
    created_at: Optional[datetime] = None
    last_seen_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    is_current: bool = False


class SessionsResponse(BaseModel):
    total_count: int
    sessions: list[SessionItem]
