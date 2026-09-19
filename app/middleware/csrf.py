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
    if security_settings.ENVIRONMENT == "production":
        return security_settings.COOKIE_DOMAIN
    return None


class CSRFMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        method = request.method.upper()
        path = request.url.path

        has_access_token = "access_token" in request.cookies
        has_csrf_token = CSRF_COOKIE_NAME in request.cookies

        if has_access_token and not has_csrf_token:
            domain = cookie_domain()
            response = JSONResponse(
                status_code=401,
                content={"detail": "Session invalid. Please login again."},
            )
            response.delete_cookie("access_token", domain=domain)
            response.delete_cookie(
                "refresh_token", path="/api/auth", domain=domain
            )
            response.delete_cookie(CSRF_COOKIE_NAME, domain=domain)
            return response

        if method in SAFE_METHODS:
            return await call_next(request)

        if self._is_exempt_path(path, request):
            return await call_next(request)

        if not self._validate_csrf_token(request):
            return JSONResponse(
                status_code=403,
                content={
                    "detail": "CSRF token missing or invalid. Include X-CSRF-Token header."
                },
            )

        return await call_next(request)

    def _is_exempt_path(self, path: str, request: Request) -> bool:
        if any(
            path.startswith(exempt)
            for exempt in security_settings.CSRF_EXEMPT_PATHS
        ):
            return True
        referer = request.headers.get("referer", "")
        if "/docs" in referer or "/redoc" in referer:
            return True
        return False

    def _validate_csrf_token(self, request: Request) -> bool:
        cookie_token = request.cookies.get(CSRF_COOKIE_NAME)
        header_token = request.headers.get(CSRF_HEADER_NAME)
        if not cookie_token or not header_token:
            return False
        return secrets.compare_digest(cookie_token, header_token)


def generate_csrf_token() -> str:
    return secrets.token_hex(CSRF_TOKEN_BYTES)
