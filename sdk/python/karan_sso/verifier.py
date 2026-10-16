"""Access-token verification against SSO's published keys (JWKS)."""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Callable, Optional

import httpx
import jwt

from .errors import InvalidTokenError, SsoUnavailableError
from .settings import SsoSettings

logger = logging.getLogger(__name__)

HttpClientFactory = Callable[[], httpx.AsyncClient]


class JwksCache:
    def __init__(self, settings: SsoSettings, http: Optional[HttpClientFactory] = None):
        self._settings = settings
        self._http = http or (lambda: httpx.AsyncClient(timeout=settings.SSO_HTTP_TIMEOUT_SECONDS))
        self._keys: dict[str, Any] = {}
        self._fetched_at = 0.0
        self._lock = asyncio.Lock()

    async def _fetch(self) -> None:
        async with self._http() as client:
            response = await client.get(self._settings.jwks_url)
        response.raise_for_status()
        keys: dict[str, Any] = {}
        for jwk in response.json().get("keys", []):
            if jwk.get("kty") == "RSA" and jwk.get("kid"):
                keys[jwk["kid"]] = jwt.PyJWK(jwk, algorithm="RS256").key
        self._keys = keys
        self._fetched_at = time.monotonic()

    async def get(self, kid: Optional[str]) -> Any:
        age = time.monotonic() - self._fetched_at
        stale = age > self._settings.SSO_JWKS_MAX_AGE_SECONDS
        unknown = kid is None or kid not in self._keys
        may_refetch = age > self._settings.SSO_JWKS_MIN_REFRESH_SECONDS or not self._keys
        if stale or (unknown and may_refetch):
            async with self._lock:
                age = time.monotonic() - self._fetched_at
                if age > self._settings.SSO_JWKS_MIN_REFRESH_SECONDS or not self._keys:
                    try:
                        await self._fetch()
                    except (httpx.HTTPError, ValueError) as exc:
                        logger.warning("SSO JWKS fetch failed: %s", exc)
                        if not self._keys:
                            raise SsoUnavailableError("SSO signing keys unavailable") from exc
        if kid is None and len(self._keys) == 1:
            return next(iter(self._keys.values()))
        key = self._keys.get(kid) if kid else None
        if key is None:
            raise InvalidTokenError("Unknown signing key")
        return key


class TokenVerifier:
    """Verifies first-party SSO access tokens.

    - RS256 only with keys from SSO's JWKS (never with a shared secret).
    - HS256 only while SSO_JWT_SECRET is configured (rollout).
    - `exp` required; `iss` checked when SSO_ISSUER is set.
    - A token carrying an `aud` other than SSO_AUDIENCE (e.g. an OAuth
      client token) is rejected; tokens without `aud` are rejected once
      SSO_REQUIRE_AUDIENCE is on.
    """

    def __init__(self, settings: SsoSettings, http: Optional[HttpClientFactory] = None):
        self.settings = settings
        self.jwks = JwksCache(settings, http)

    async def verify(self, token: str) -> dict[str, Any]:
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise InvalidTokenError("Malformed token") from exc

        alg = header.get("alg")
        options: dict[str, Any] = {"require": ["exp"], "verify_aud": False}
        try:
            if alg == "RS256":
                key = await self.jwks.get(header.get("kid"))
                claims = jwt.decode(token, key, algorithms=["RS256"], options=options, leeway=10)
            elif alg == "HS256" and self.settings.SSO_JWT_SECRET:
                claims = jwt.decode(
                    token,
                    self.settings.SSO_JWT_SECRET,
                    algorithms=["HS256"],
                    options=options,
                    leeway=10,
                )
            else:
                raise InvalidTokenError("Unsupported token algorithm")
        except jwt.PyJWTError as exc:
            raise InvalidTokenError("Invalid or expired token") from exc

        self._check_claims(claims)
        return claims

    def _check_claims(self, claims: dict[str, Any]) -> None:
        if claims.get("type") != "access":
            raise InvalidTokenError("Not an access token")
        if not claims.get("email") or not (claims.get("user_id") or claims.get("sub")):
            raise InvalidTokenError("Token missing identity claims")
        if not claims.get("sid"):
            raise InvalidTokenError("Token has no session id")
        issuer = self.settings.SSO_ISSUER
        if issuer and claims.get("iss") != issuer:
            raise InvalidTokenError("Invalid issuer")
        aud = claims.get("aud")
        if aud is None:
            if self.settings.SSO_REQUIRE_AUDIENCE:
                raise InvalidTokenError("Token has no audience")
            return
        audiences = [aud] if isinstance(aud, str) else list(aud)
        if self.settings.SSO_AUDIENCE not in audiences:
            raise InvalidTokenError("Invalid audience")
