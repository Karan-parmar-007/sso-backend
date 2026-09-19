from typing import Annotated, Any, Dict, Optional

from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status

from app.config import security_settings
from app.api.dependencies import AuthServiceDep
from app.dependencies.jwt_auth import require_auth
from app.middleware.csrf import CSRF_COOKIE_NAME, cookie_domain, generate_csrf_token
from app.schemas.auth import (
    AuthResponse,
    ChangePasswordRequest,
    ConfirmEmailChangeRequest,
    ForgotPasswordRequest,
    LoginRequest,
    MessageResponse,
    RequestEmailChangeRequest,
    ResetPasswordRequest,
    SessionItem,
    SessionsResponse,
    SignupRequest,
    TokenResponse,
    UserInfoResponse,
    VerifyEmailRequest,
)
from app.services.auth_service import RateLimitError
from app.utils.security import ACCESS_TOKEN_EXPIRE_SECONDS, REFRESH_TOKEN_EXPIRE_SECONDS

router = APIRouter()


def _set_csrf_cookie(response: Response) -> None:
    domain = cookie_domain()
    token = generate_csrf_token()
    response.set_cookie(
        key=CSRF_COOKIE_NAME,
        value=token,
        httponly=False,
        secure=(security_settings.ENVIRONMENT == "production"),
        samesite="lax",
        domain=domain,
        max_age=60 * 60 * 24 * 7,
    )


def _set_auth_cookies(
    response: Response,
    access_token: str,
    refresh_token: Optional[str] = None,
    remember_me: bool = True,
) -> None:
    domain = cookie_domain()
    is_prod = security_settings.ENVIRONMENT == "production"

    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=is_prod,
        samesite="lax",
        domain=domain,
        max_age=ACCESS_TOKEN_EXPIRE_SECONDS,
    )
    if refresh_token:
        cookie_kwargs: dict = {
            "key": "refresh_token",
            "value": refresh_token,
            "httponly": True,
            "secure": is_prod,
            "samesite": "lax",
            "domain": domain,
            "path": "/api/auth",
        }
        if remember_me:
            cookie_kwargs["max_age"] = REFRESH_TOKEN_EXPIRE_SECONDS
        response.set_cookie(**cookie_kwargs)
    else:
        response.delete_cookie(
            key="refresh_token",
            path="/api/auth",
            domain=domain,
        )
    _set_csrf_cookie(response)


def _clear_auth_cookies(response: Response) -> None:
    domain = cookie_domain()
    is_prod = security_settings.ENVIRONMENT == "production"
    response.delete_cookie(
        key="access_token",
        secure=is_prod,
        httponly=True,
        samesite="lax",
        domain=domain,
    )
    response.delete_cookie(
        key="refresh_token",
        path="/api/auth",
        secure=is_prod,
        httponly=True,
        samesite="lax",
        domain=domain,
    )
    response.delete_cookie(
        key=CSRF_COOKIE_NAME,
        secure=is_prod,
        httponly=False,
        samesite="lax",
        domain=domain,
    )


def _device_info(request: Request) -> str:
    return (request.headers.get("User-Agent") or "Unknown")[:500]


def _client_ip(request: Request) -> Optional[str]:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()[:64]
    if request.client:
        return (request.client.host or "")[:64] or None
    return None


async def _to_user_info(service, user) -> UserInfoResponse:
    info = await service.user_info(user)
    return UserInfoResponse(**info)


@router.post("/signup", response_model=MessageResponse, status_code=status.HTTP_201_CREATED)
async def signup(
    data: SignupRequest,
    service: AuthServiceDep,
):
    """Create account and send verification email. Does not log the user in."""
    try:
        await service.signup(data.name, data.email, data.password)
    except ValueError as e:
        code = (
            status.HTTP_409_CONFLICT
            if "already" in str(e).lower()
            else status.HTTP_400_BAD_REQUEST
        )
        raise HTTPException(status_code=code, detail=str(e))
    except RateLimitError as e:
        raise HTTPException(status_code=429, detail=str(e))

    return MessageResponse(
        message="Account created. A verification email has been sent. Please sign in."
    )


@router.post("/login", response_model=AuthResponse)
async def login(
    request: Request,
    response: Response,
    data: LoginRequest,
    service: AuthServiceDep,
):
    try:
        user, access, refresh = await service.login(
            data.email,
            data.password,
            _device_info(request),
            data.remember_me,
            _client_ip(request),
        )
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))

    _set_auth_cookies(response, access, refresh, remember_me=data.remember_me)
    return AuthResponse(
        user=await _to_user_info(service, user),
        access_token_expires_in=ACCESS_TOKEN_EXPIRE_SECONDS,
        message="Login successful",
    )


@router.post("/logout", response_model=MessageResponse)
async def logout(
    response: Response,
    service: AuthServiceDep,
    user: Annotated[Dict[str, Any], Depends(require_auth)],
    refresh_token: Optional[str] = Cookie(None),
):
    user_id = user.get("user_id") or user.get("sub")
    await service.logout(user_id, refresh_token)
    _clear_auth_cookies(response)
    return MessageResponse(message="Logged out successfully")


@router.post("/refresh", response_model=TokenResponse)
async def refresh(
    request: Request,
    response: Response,
    service: AuthServiceDep,
    refresh_token: Optional[str] = Cookie(None),
):
    if not refresh_token:
        raise HTTPException(status_code=401, detail="Refresh token missing")
    try:
        user, access, new_refresh = await service.refresh_tokens(
            refresh_token, _device_info(request), _client_ip(request)
        )
    except ValueError as e:
        _clear_auth_cookies(response)
        raise HTTPException(status_code=401, detail=str(e))

    _set_auth_cookies(response, access, new_refresh, remember_me=True)
    return TokenResponse(
        access_token_expires_in=ACCESS_TOKEN_EXPIRE_SECONDS,
        message="Token refreshed successfully",
    )


@router.get("/sessions", response_model=SessionsResponse)
async def list_sessions(
    service: AuthServiceDep,
    user: Annotated[Dict[str, Any], Depends(require_auth)],
    refresh_token: Optional[str] = Cookie(None),
):
    user_id = user.get("user_id") or user.get("sub")
    sessions = await service.list_sessions(user_id, refresh_token)
    return SessionsResponse(
        total_count=len(sessions),
        sessions=[SessionItem(**s) for s in sessions],
    )


@router.delete("/sessions/others", response_model=MessageResponse)
async def revoke_other_sessions(
    service: AuthServiceDep,
    user: Annotated[Dict[str, Any], Depends(require_auth)],
    refresh_token: Optional[str] = Cookie(None),
):
    user_id = user.get("user_id") or user.get("sub")
    count = await service.revoke_other_sessions(user_id, refresh_token)
    return MessageResponse(message=f"Logged out {count} other session(s)")


@router.delete("/sessions/{session_id}", response_model=MessageResponse)
async def revoke_session(
    session_id: str,
    response: Response,
    service: AuthServiceDep,
    user: Annotated[Dict[str, Any], Depends(require_auth)],
    refresh_token: Optional[str] = Cookie(None),
):
    user_id = user.get("user_id") or user.get("sub")
    try:
        was_current = await service.revoke_session(
            user_id, session_id, refresh_token
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

    if was_current:
        _clear_auth_cookies(response)
        return MessageResponse(message="Current session ended")
    return MessageResponse(message="Session logged out")


@router.get("/me", response_model=UserInfoResponse)
async def me(
    service: AuthServiceDep,
    user: Annotated[Dict[str, Any], Depends(require_auth)],
):
    user_id = user.get("user_id") or user.get("sub")
    db_user = await service.get_user_by_id(user_id)
    if not db_user:
        raise HTTPException(status_code=401, detail="User not found")
    return await _to_user_info(service, db_user)


@router.post("/forgot-password", response_model=MessageResponse)
async def forgot_password(data: ForgotPasswordRequest, service: AuthServiceDep):
    try:
        await service.forgot_password(data.email)
    except RateLimitError as e:
        raise HTTPException(status_code=429, detail=str(e))
    return MessageResponse(
        message="If the email exists, a reset link has been sent"
    )


@router.post("/reset-password", response_model=MessageResponse)
async def reset_password(data: ResetPasswordRequest, service: AuthServiceDep):
    try:
        await service.reset_password(
            data.token, data.new_password, data.confirm_password
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return MessageResponse(message="Password reset successful")


@router.post("/verify-email", response_model=UserInfoResponse)
async def verify_email(data: VerifyEmailRequest, service: AuthServiceDep):
    try:
        user = await service.verify_email(data.token)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return await _to_user_info(service, user)


@router.post("/resend-verification", response_model=MessageResponse)
async def resend_verification(
    service: AuthServiceDep,
    user: Annotated[Dict[str, Any], Depends(require_auth)],
):
    user_id = user.get("user_id") or user.get("sub")
    db_user = await service.get_user_by_id(user_id)
    if not db_user:
        raise HTTPException(status_code=401, detail="User not found")
    try:
        await service.send_verification_email(db_user)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except RateLimitError as e:
        raise HTTPException(status_code=429, detail=str(e))
    return MessageResponse(message="Verification email sent")


@router.post("/change-password", response_model=MessageResponse)
async def change_password(
    data: ChangePasswordRequest,
    service: AuthServiceDep,
    user: Annotated[Dict[str, Any], Depends(require_auth)],
):
    user_id = user.get("user_id") or user.get("sub")
    try:
        await service.change_password(
            user_id, data.old_password, data.new_password, data.confirm_password
        )
    except RateLimitError as e:
        raise HTTPException(status_code=429, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return MessageResponse(message="Password changed successfully")


@router.post("/request-email-change", response_model=MessageResponse)
async def request_email_change(
    data: RequestEmailChangeRequest,
    service: AuthServiceDep,
    user: Annotated[Dict[str, Any], Depends(require_auth)],
):
    user_id = user.get("user_id") or user.get("sub")
    try:
        await service.request_email_change(user_id, data.new_email)
    except RateLimitError as e:
        raise HTTPException(status_code=429, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return MessageResponse(message="Confirmation link sent to the new email")


@router.post("/confirm-email-change", response_model=UserInfoResponse)
async def confirm_email_change(
    data: ConfirmEmailChangeRequest, service: AuthServiceDep
):
    try:
        user = await service.confirm_email_change(data.token)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return await _to_user_info(service, user)
