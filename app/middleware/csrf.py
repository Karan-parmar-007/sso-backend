import secrets
from typing import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.config import security_settings

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
CSRF_COOKIE_NAME = "csrf_token"
CSRF_HEADER_NAME = "X-CSRF-Token"
CSRF_TOKEN_BYTES = 32


def cookie_domain() -> str | None:
    if security_settings.is_production:
        return security_settings.COOKIE_DOMAIN
    return None


class CSRFMiddleware(BaseHTTPMiddleware):
    """Double-submit cookie check for cookie-authenticated mutations.

    Requests that carry no session cookie (e.g. app backends calling with
    `Authorization: Bearer`) cannot be forged by a browser, so they skip it.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if request.method.upper() in SAFE_METHODS:
            return await call_next(request)
        if self._is_exempt_path(request.url.path):
            return await call_next(request)
        if not self._uses_cookie_auth(request):
            return await call_next(request)
        if not self._validate_csrf_token(request):
            return JSONResponse(
                status_code=403,
                content={
                    "detail": "CSRF token missing or invalid. Include X-CSRF-Token header."
                },
            )
        return await call_next(request)

    @staticmethod
    def _is_exempt_path(path: str) -> bool:
        return any(
            path == exempt or path.startswith(exempt.rstrip("/") + "/")
            for exempt in security_settings.CSRF_EXEMPT_PATHS
        )

    @staticmethod
    def _uses_cookie_auth(request: Request) -> bool:
        return bool(
            request.cookies.get("access_token")
            or request.cookies.get("refresh_token")
            or request.cookies.get(CSRF_COOKIE_NAME)
        )

    @staticmethod
    def _validate_csrf_token(request: Request) -> bool:
        cookie_token = request.cookies.get(CSRF_COOKIE_NAME)
        header_token = request.headers.get(CSRF_HEADER_NAME)
        if not cookie_token or not header_token:
            return False
        return secrets.compare_digest(cookie_token, header_token)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """API-level headers; site-wide headers (HSTS, CSP, …) are set in Caddy."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        if "/.well-known/" not in request.url.path:
            response.headers.setdefault("Cache-Control", "no-store")
        return response


def generate_csrf_token() -> str:
    return secrets.token_hex(CSRF_TOKEN_BYTES)
