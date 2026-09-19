from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr, Field


class MessageResponse(BaseModel):
    message: str


class UserInfoResponse(BaseModel):
    id: str
    name: str
    email: EmailStr
    email_verified: bool
    role_name: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class SignupRequest(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str
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
    old_password: str
    new_password: str = Field(min_length=8, max_length=128)
    confirm_password: str = Field(min_length=8, max_length=128)


class RequestEmailChangeRequest(BaseModel):
    new_email: EmailStr


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
    created_at: Optional[datetime] = None


class AdminUsersResponse(BaseModel):
    total_count: int
    page: int
    page_size: int
    total_pages: int
    users: list[AdminUserListItem]


class AdminChangeRoleRequest(BaseModel):
    role_name: str = Field(min_length=1, max_length=50)


class AdminResetPasswordRequest(BaseModel):
    password: Optional[str] = Field(default=None, min_length=8, max_length=128)
    send_email: bool = False


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
