"""Session cookies (access / refresh / CSRF), shared by every route that
starts, refreshes or ends a browser session."""

from fastapi import Request, Response

from app.config import security_settings
from app.middleware.csrf import CSRF_COOKIE_NAME, cookie_domain, generate_csrf_token
from app.services.auth_service import IssuedSession
from app.utils.security import ACCESS_TOKEN_EXPIRE_SECONDS, utcnow


def cookie_kwargs() -> dict:
    return {
        "secure": security_settings.is_production,
        "samesite": "lax",
        "domain": cookie_domain(),
    }


def set_auth_cookies(
    request: Request,
    response: Response,
    issued: IssuedSession,
    new_session: bool = False,
) -> None:
    """Access + refresh cookies. A new session (login) gets a fresh CSRF token,
    so a token planted before login is useless; refreshes keep it stable so
    in-flight requests from other tabs don't fail."""
    session_max_age = max(
        60, int((issued.refresh_expires_at - utcnow()).total_seconds())
    )
    persistent = {"max_age": session_max_age} if issued.remember_me else {}

    response.set_cookie(
        key="access_token",
        value=issued.access_token,
        httponly=True,
        max_age=ACCESS_TOKEN_EXPIRE_SECONDS,
        **cookie_kwargs(),
    )
    response.set_cookie(
        key="refresh_token",
        value=issued.refresh_token,
        httponly=True,
        path="/api/auth",
        **persistent,
        **cookie_kwargs(),
    )
    response.set_cookie(
        key=CSRF_COOKIE_NAME,
        value=(None if new_session else request.cookies.get(CSRF_COOKIE_NAME))
        or generate_csrf_token(),
        httponly=False,
        **persistent,
        **cookie_kwargs(),
    )


def clear_auth_cookies(response: Response) -> None:
    kwargs = cookie_kwargs()
    response.delete_cookie(key="access_token", httponly=True, **kwargs)
    response.delete_cookie(key="refresh_token", path="/api/auth", httponly=True, **kwargs)
    response.delete_cookie(key=CSRF_COOKIE_NAME, httponly=False, **kwargs)


def ensure_csrf_cookie(request: Request, response: Response) -> None:
    """Re-issue a missing CSRF cookie for a live session (session-lifetime cookie)."""
    if not request.cookies.get(CSRF_COOKIE_NAME):
        response.set_cookie(
            key=CSRF_COOKIE_NAME,
            value=generate_csrf_token(),
            httponly=False,
            **cookie_kwargs(),
        )
