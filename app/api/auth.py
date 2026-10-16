from typing import Annotated, Any, Dict, Optional

from fastapi import APIRouter, Body, Cookie, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import JSONResponse

from app.api.cookies import clear_auth_cookies, set_auth_cookies, ensure_csrf_cookie
from app.api.dependencies import AuditServiceDep, AuthServiceDep
from app.dependencies.jwt_auth import optional_access_payload, require_auth
from app.schemas.auth import (
    AuditEventsResponse,
    AuthResponse,
    ChangePasswordRequest,
    ConfirmEmailChangeRequest,
    ForgotPasswordRequest,
    LoginRequest,
    MessageResponse,
    RequestEmailChangeRequest,
    ResendVerificationRequest,
    ResetPasswordRequest,
    SessionItem,
    SessionResponse,
    SessionsResponse,
    SignupRequest,
    TokenResponse,
    UserInfoResponse,
    VerifyEmailRequest,
)
from app.services.auth_service import (
    EmailNotVerifiedError,
    InvalidRefreshTokenError,
    RateLimitError,
)
from app.utils.request_context import request_context
from app.utils.security import ACCESS_TOKEN_EXPIRE_SECONDS

router = APIRouter()

AuthPayload = Annotated[Dict[str, Any], Depends(require_auth)]


def _rate_limited(e: RateLimitError) -> HTTPException:
    headers = (
        {"Retry-After": str(e.retry_after_seconds)} if e.retry_after_seconds else None
    )
    return HTTPException(status_code=429, detail=str(e), headers=headers)


def _uid(payload: Dict[str, Any]) -> str:
    return payload.get("user_id") or payload["sub"]


async def _to_user_info(service, user) -> UserInfoResponse:
    return UserInfoResponse(**await service.user_info(user))


# --------------------------------------------------------------------------
# Signup / login / session
# --------------------------------------------------------------------------


@router.post("/signup", response_model=MessageResponse, status_code=status.HTTP_201_CREATED)
async def signup(request: Request, data: SignupRequest, service: AuthServiceDep):
    """Create account and send verification email. Does not log the user in.

    The response is identical whether or not the email is already registered.
    """
    try:
        await service.signup(data.name, data.email, data.password, request_context(request))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except RateLimitError as e:
        raise _rate_limited(e)

    return MessageResponse(
        message="Check your inbox to verify your email, then sign in."
    )


@router.post("/login", response_model=AuthResponse)
async def login(
    request: Request,
    response: Response,
    data: LoginRequest,
    service: AuthServiceDep,
    refresh_token: Optional[str] = Cookie(None),
):
    try:
        issued = await service.login(
            data.email, data.password, data.remember_me, request_context(request)
        )
    except RateLimitError as e:
        raise _rate_limited(e)
    except EmailNotVerifiedError as e:
        return JSONResponse(
            status_code=403, content={"detail": str(e), "code": "email_not_verified"}
        )
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))

    # Re-authentication in a browser that had a session replaces it.
    await service.retire_session(refresh_token, issued.session_id)
    set_auth_cookies(request, response, issued, new_session=True)
    return AuthResponse(
        user=await _to_user_info(service, issued.user),
        access_token_expires_in=ACCESS_TOKEN_EXPIRE_SECONDS,
        message="Login successful",
    )


@router.get("/session", response_model=SessionResponse)
async def session(
    request: Request,
    response: Response,
    service: AuthServiceDep,
    access_token: Optional[str] = Cookie(None),
    refresh_token: Optional[str] = Cookie(None),
):
    """Who is signed in? Always 200.

    Served under /api/auth on every app host, so the browser sends the
    refresh cookie here: an expired access token is refreshed server-side and
    apps never have to show a signed-in user as signed out.
    """
    resolved = await service.resolve_session(
        access_token, refresh_token, request_context(request)
    )
    if resolved.issued:
        set_auth_cookies(request, response, resolved.issued)
    elif resolved.clear_cookies:
        clear_auth_cookies(response)
    if not resolved.user:
        return SessionResponse(authenticated=False)
    if not resolved.issued:
        ensure_csrf_cookie(request, response)
    return SessionResponse(
        authenticated=True,
        user=await _to_user_info(service, resolved.user),
        session_id=resolved.session_id,
        access_token_expires_in=ACCESS_TOKEN_EXPIRE_SECONDS if resolved.issued else None,
    )


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
        issued = await service.refresh_tokens(refresh_token, request_context(request))
    except InvalidRefreshTokenError as e:
        failure = JSONResponse(status_code=401, content={"detail": str(e)})
        clear_auth_cookies(failure)
        return failure

    set_auth_cookies(request, response, issued)
    return TokenResponse(
        access_token_expires_in=ACCESS_TOKEN_EXPIRE_SECONDS,
        message="Token refreshed successfully",
    )


@router.post("/logout", response_model=MessageResponse)
async def logout(
    request: Request,
    response: Response,
    service: AuthServiceDep,
    everywhere: bool = Query(False, description="Sign out every session of this user"),
    refresh_token: Optional[str] = Cookie(None),
):
    """Works even after the access token expired: the refresh cookie
    identifies the session. Cookies are always cleared."""
    await service.logout(
        refresh_token,
        optional_access_payload(request),
        request_context(request),
        everywhere=everywhere,
    )
    clear_auth_cookies(response)
    return MessageResponse(message="Logged out successfully")


# --------------------------------------------------------------------------
# Sessions & activity
# --------------------------------------------------------------------------


@router.get("/sessions", response_model=SessionsResponse)
async def list_sessions(service: AuthServiceDep, user: AuthPayload):
    sessions = await service.list_sessions(_uid(user), user.get("sid"))
    return SessionsResponse(
        total_count=len(sessions),
        sessions=[SessionItem(**s) for s in sessions],
    )


@router.delete("/sessions/others", response_model=MessageResponse)
async def revoke_other_sessions(request: Request, service: AuthServiceDep, user: AuthPayload):
    count = await service.revoke_other_sessions(
        _uid(user), user.get("sid"), request_context(request)
    )
    return MessageResponse(message=f"Logged out {count} other session(s)")


@router.delete("/sessions/{session_id}", response_model=MessageResponse)
async def revoke_session(
    session_id: str,
    request: Request,
    response: Response,
    service: AuthServiceDep,
    user: AuthPayload,
):
    try:
        was_current = await service.revoke_session(
            _uid(user), session_id, user.get("sid"), request_context(request)
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

    if was_current:
        clear_auth_cookies(response)
        return MessageResponse(message="Current session ended")
    return MessageResponse(message="Session logged out")


@router.get("/activity", response_model=AuditEventsResponse)
async def my_activity(
    audit: AuditServiceDep,
    user: AuthPayload,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
):
    """The signed-in user's own security events."""
    return AuditEventsResponse(**await audit.list_page(page, page_size, user_id=_uid(user)))


@router.get("/me", response_model=UserInfoResponse)
async def me(service: AuthServiceDep, user: AuthPayload):
    db_user = await service.get_user_by_id(_uid(user))
    if not db_user:
        raise HTTPException(status_code=401, detail="User not found")
    return await _to_user_info(service, db_user)


# --------------------------------------------------------------------------
# Email verification & passwords
# --------------------------------------------------------------------------


@router.post("/forgot-password", response_model=MessageResponse)
async def forgot_password(request: Request, data: ForgotPasswordRequest, service: AuthServiceDep):
    await service.forgot_password(data.email, request_context(request))
    return MessageResponse(
        message="If the email exists, a reset link has been sent"
    )


@router.post("/reset-password", response_model=MessageResponse)
async def reset_password(request: Request, data: ResetPasswordRequest, service: AuthServiceDep):
    try:
        await service.reset_password(
            data.token, data.new_password, data.confirm_password, request_context(request)
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return MessageResponse(message="Password reset successful")


@router.post("/verify-email", response_model=UserInfoResponse)
async def verify_email(request: Request, data: VerifyEmailRequest, service: AuthServiceDep):
    try:
        user = await service.verify_email(data.token, request_context(request))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return await _to_user_info(service, user)


@router.post("/resend-verification", response_model=MessageResponse)
async def resend_verification(
    request: Request,
    service: AuthServiceDep,
    data: Optional[ResendVerificationRequest] = Body(None),
):
    """Signed in: resend for the current user. Signed out (login screen):
    pass `email`; the response never reveals whether it exists."""
    payload = optional_access_payload(request)
    if payload is None:
        if data is not None:
            await service.resend_verification_by_email(data.email)
        return MessageResponse(
            message="If the account exists and is unverified, a verification email has been sent"
        )

    db_user = await service.get_user_by_id(_uid(payload))
    if not db_user:
        raise HTTPException(status_code=401, detail="User not found")
    try:
        await service.send_verification_email(db_user)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except RateLimitError as e:
        raise _rate_limited(e)
    return MessageResponse(message="Verification email sent")


@router.post("/change-password", response_model=MessageResponse)
async def change_password(
    request: Request,
    data: ChangePasswordRequest,
    service: AuthServiceDep,
    user: AuthPayload,
):
    try:
        revoked = await service.change_password(
            _uid(user),
            user.get("sid"),
            data.old_password,
            data.new_password,
            data.confirm_password,
            request_context(request),
        )
    except RateLimitError as e:
        raise _rate_limited(e)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    suffix = f"; signed out {revoked} other session(s)" if revoked else ""
    return MessageResponse(message=f"Password changed successfully{suffix}")


@router.post("/request-email-change", response_model=MessageResponse)
async def request_email_change(
    request: Request,
    data: RequestEmailChangeRequest,
    service: AuthServiceDep,
    user: AuthPayload,
):
    try:
        await service.request_email_change(
            _uid(user), data.new_email, data.current_password, request_context(request)
        )
    except RateLimitError as e:
        raise _rate_limited(e)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return MessageResponse(message="Confirmation link sent to the new email")


@router.post("/confirm-email-change", response_model=UserInfoResponse)
async def confirm_email_change(
    request: Request,
    response: Response,
    data: ConfirmEmailChangeRequest,
    service: AuthServiceDep,
):
    """Changing the email signs the account out everywhere."""
    try:
        user = await service.confirm_email_change(data.token, request_context(request))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    clear_auth_cookies(response)
    return await _to_user_info(service, user)
