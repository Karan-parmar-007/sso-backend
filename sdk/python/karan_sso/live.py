"""Live user lookup via SSO GET /auth/me.

Used for privileged routes: it reflects role changes and session
revocation immediately, where the access token can be up to 15 minutes stale.
"""

from __future__ import annotations

import hashlib
import time
from typing import Any, Optional

import httpx

from .errors import InvalidTokenError, SsoUnavailableError
from .settings import SsoSettings
from .verifier import HttpClientFactory


class LiveUserClient:
    def __init__(self, settings: SsoSettings, http: Optional[HttpClientFactory] = None):
        self._settings = settings
        self._http = http or (lambda: httpx.AsyncClient(timeout=settings.SSO_HTTP_TIMEOUT_SECONDS))
        self._cache: dict[str, tuple[float, Optional[dict[str, Any]]]] = {}

    def _cached(self, key: str) -> tuple[bool, Optional[dict[str, Any]]]:
        hit = self._cache.get(key)
        if hit and hit[0] > time.monotonic():
            return True, hit[1]
        return False, None

    def _store(self, key: str, value: Optional[dict[str, Any]]) -> None:
        if len(self._cache) > 5000:
            now = time.monotonic()
            self._cache = {k: v for k, v in self._cache.items() if v[0] > now}
        ttl = self._settings.SSO_LIVE_CHECK_CACHE_SECONDS
        self._cache[key] = (time.monotonic() + ttl, value)

    async def fetch(self, access_token: str) -> dict[str, Any]:
        """Current user for this token. InvalidTokenError when SSO says the
        session is gone; SsoUnavailableError when SSO can't answer."""
        key = hashlib.sha256(access_token.encode()).hexdigest()
        found, value = self._cached(key)
        if not found:
            try:
                async with self._http() as client:
                    response = await client.get(
                        self._settings.me_url,
                        headers={"Authorization": f"Bearer {access_token}"},
                    )
            except httpx.HTTPError as exc:
                raise SsoUnavailableError("SSO unreachable") from exc
            if response.status_code == 401:
                value = None
            elif response.status_code == 200:
                try:
                    value = response.json()
                except ValueError as exc:
                    raise SsoUnavailableError("SSO returned invalid JSON") from exc
            else:
                raise SsoUnavailableError(f"SSO /auth/me returned {response.status_code}")
            self._store(key, value)
        if value is None:
            raise InvalidTokenError("Session is no longer valid")
        return value
