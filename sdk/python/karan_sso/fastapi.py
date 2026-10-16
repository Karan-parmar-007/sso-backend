"""FastAPI dependencies and middleware.

    from karan_sso.fastapi import IdentityDep, AdminDep, CSRFMiddleware

    @router.get("/things")
    async def things(user: IdentityDep): ...

Token-only checks (`IdentityDep`) are local and fast. Privileged checks
(`AdminDep`, `OwnerDep`, `require_role`, `require_app_role`) confirm the role
and session with SSO live (cached briefly), so demotions and revocations
apply immediately. SSO outages surface as 503, never as 403.
"""

from __future__ import annotations

import secrets
from typing import Annotated, Awaitable, Callable, Iterable, Optional

from fastapi import Depends, HTTPException, Request, status
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from .errors import InvalidTokenError, SsoUnavailableError
from .identity import SsoIdentity
from .live import LiveUserClient
from .settings import SsoSettings, get_settings
from .verifier import HttpClientFactory, TokenVerifier

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def _unauthorized(detail: str = "Not authenticated") -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


def _unavailable() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Authentication service unavailable, try again shortly",
    )


class SsoAuth:
    def __init__(self, settings: Optional[SsoSettings] = None, http: Optional[HttpClientFactory] = None):
        self.settings = settings or get_settings()
        self.verifier = TokenVerifier(self.settings, http)
        self.live = LiveUserClient(self.settings, http)

    def token_from_request(self, request: Request) -> Optional[str]:
        """Cookie wins; `Authorization: Bearer` is the fallback for API clients."""
        token = request.cookies.get(self.settings.ACCESS_TOKEN_COOKIE_NAME)
        if token:
            return token
        auth = request.headers.get("authorization") or ""
        if auth.lower().startswith("bearer "):
            return auth[7:].strip() or None
        return None

    async def optional_identity(self, request: Request) -> Optional[SsoIdentity]:
        token = self.token_from_request(request)
        if not token:
            return None
        try:
            return SsoIdentity.from_claims(await self.verifier.verify(token))
        except InvalidTokenError:
            return None
        except SsoUnavailableError:
            raise _unavailable()

    async def identity(self, request: Request) -> SsoIdentity:
        token = self.token_from_request(request)
        if not token:
            raise _unauthorized()
        try:
            claims = await self.verifier.verify(token)
        except InvalidTokenError as exc:
            raise _unauthorized(str(exc))
        except SsoUnavailableError:
            raise _unavailable()
        identity = SsoIdentity.from_claims(claims)
        request.state.sso_identity = identity
        return identity

    async def live_identity(self, request: Request) -> SsoIdentity:
        identity = await self.identity(request)
        token = self.token_from_request(request)
        assert token is not None
        try:
            me = await self.live.fetch(token)
        except InvalidTokenError as exc:
            raise _unauthorized(str(exc))
        except SsoUnavailableError:
            raise _unavailable()
        live = identity.with_live(me)
        request.state.sso_identity = live
        return live

    # -- privileged checks (live) -----------------------------------------

    def require(self, predicate: Callable[[SsoIdentity], bool], message: str) -> Callable[[Request], Awaitable[SsoIdentity]]:
        async def _dependency(request: Request) -> SsoIdentity:
            identity = await self.live_identity(request)
            if not predicate(identity):
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=message)
            return identity

        return _dependency

    def require_role(self, *roles: str) -> Callable[[Request], Awaitable[SsoIdentity]]:
        allowed = {r.strip().lower() for r in roles if r.strip()}
        if not allowed:
            raise ValueError("require_role needs at least one role")
        needed = "', '".join(sorted(allowed))
        return self.require(lambda i: i.role in allowed, f"One of these roles required: '{needed}'")

    def require_app_role(self, role: str, app_id: Optional[str] = None) -> Callable[[Request], Awaitable[SsoIdentity]]:
        app = app_id or self.settings.SSO_APP_ID
        if not app:
            raise ValueError("Set SSO_APP_ID or pass app_id")
        return self.require(lambda i: i.has_app_role(app, role), f"'{role}' access to {app} required")

    def is_app_admin(self, identity: SsoIdentity) -> bool:
        """Global owner/super_admin, or the `admin` role in this app."""
        app = self.settings.SSO_APP_ID
        return identity.is_admin or bool(app and identity.has_app_role(app, "admin"))


_default: Optional[SsoAuth] = None


def get_sso() -> SsoAuth:
    global _default
    if _default is None:
        _default = SsoAuth()
    return _default


def configure(settings: Optional[SsoSettings] = None, http: Optional[HttpClientFactory] = None) -> SsoAuth:
    """Replace the default instance (tests, custom HTTP transport)."""
    global _default
    _default = SsoAuth(settings, http)
    return _default


async def get_optional_identity(request: Request) -> Optional[SsoIdentity]:
    return await get_sso().optional_identity(request)


async def get_identity(request: Request) -> SsoIdentity:
    return await get_sso().identity(request)


async def get_live_identity(request: Request) -> SsoIdentity:
    return await get_sso().live_identity(request)


async def require_admin(request: Request) -> SsoIdentity:
    sso = get_sso()
    identity = await sso.live_identity(request)
    if not sso.is_app_admin(identity):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    return identity


async def require_owner(request: Request) -> SsoIdentity:
    identity = await get_sso().live_identity(request)
    if not identity.is_owner:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Owner access required")
    return identity


def require_role(*roles: str) -> Callable[[Request], Awaitable[SsoIdentity]]:
    async def _dependency(request: Request) -> SsoIdentity:
        return await get_sso().require_role(*roles)(request)

    return _dependency


def require_app_role(role: str, app_id: Optional[str] = None) -> Callable[[Request], Awaitable[SsoIdentity]]:
    async def _dependency(request: Request) -> SsoIdentity:
        return await get_sso().require_app_role(role, app_id)(request)

    return _dependency


OptionalIdentityDep = Annotated[Optional[SsoIdentity], Depends(get_optional_identity)]
IdentityDep = Annotated[SsoIdentity, Depends(get_identity)]
LiveIdentityDep = Annotated[SsoIdentity, Depends(get_live_identity)]
AdminDep = Annotated[SsoIdentity, Depends(require_admin)]
OwnerDep = Annotated[SsoIdentity, Depends(require_owner)]


class CSRFMiddleware:
    """Double-submit CSRF check for cookie-authenticated mutations.

    No Referer/Origin shortcuts. Requests without any session cookie (pure
    bearer API clients) can't be forged by a browser and pass through.
    """

    def __init__(
        self,
        app: ASGIApp,
        exempt_prefixes: Iterable[str] = (),
        settings: Optional[SsoSettings] = None,
    ):
        self.app = app
        self.exempt_prefixes = tuple(p.rstrip("/") for p in exempt_prefixes)
        self.settings = settings or get_settings()

    def _exempt(self, path: str) -> bool:
        return any(path == p or path.startswith(p + "/") for p in self.exempt_prefixes)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["method"].upper() in SAFE_METHODS:
            await self.app(scope, receive, send)
            return
        request = Request(scope)
        s = self.settings
        cookie_token = request.cookies.get(s.CSRF_COOKIE_NAME)
        uses_cookies = bool(request.cookies.get(s.ACCESS_TOKEN_COOKIE_NAME) or cookie_token)
        if self._exempt(request.url.path) or not uses_cookies:
            await self.app(scope, receive, send)
            return
        header_token = request.headers.get(s.CSRF_HEADER_NAME)
        if not cookie_token or not header_token or not secrets.compare_digest(cookie_token, header_token):
            response = JSONResponse(status_code=403, content={"detail": "CSRF token missing or invalid"})
            await response(scope, receive, send)
            return
        await self.app(scope, receive, send)
