"""SDK settings, read from the app's environment / .env."""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class SsoSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", env_ignore_empty=True, extra="ignore"
    )

    # Internal URL of the SSO API, e.g. http://sso-backend:8000/api
    SSO_BASE_URL: str = "http://localhost:8000/api"
    # Defaults to {SSO_BASE_URL}/auth/.well-known/jwks.json
    SSO_JWKS_URL: str = ""
    # Public issuer (JWT `iss`). Empty = don't check.
    SSO_ISSUER: str = ""
    # Expected `aud` of first-party session tokens. Tokens carrying a
    # different audience (OAuth client tokens) are always rejected.
    SSO_AUDIENCE: str = "karanparmar-apps"
    # Reject tokens without `aud` (enable once SSO sets JWT_AUDIENCE).
    SSO_REQUIRE_AUDIENCE: bool = False
    # Legacy shared secret: accept HS256 tokens during the rollout only.
    SSO_JWT_SECRET: str = ""
    # This application's client_id in SSO, for app-scoped roles.
    SSO_APP_ID: str = ""

    ACCESS_TOKEN_COOKIE_NAME: str = "access_token"
    CSRF_COOKIE_NAME: str = "csrf_token"
    CSRF_HEADER_NAME: str = "X-CSRF-Token"

    # Live role/revocation check cache (admin routes).
    SSO_LIVE_CHECK_CACHE_SECONDS: int = 30
    SSO_HTTP_TIMEOUT_SECONDS: float = 5.0
    # Minimum seconds between JWKS re-fetches triggered by an unknown `kid`.
    SSO_JWKS_MIN_REFRESH_SECONDS: int = 30
    SSO_JWKS_MAX_AGE_SECONDS: int = 3600

    @property
    def jwks_url(self) -> str:
        return self.SSO_JWKS_URL or f"{self.SSO_BASE_URL.rstrip('/')}/auth/.well-known/jwks.json"

    @property
    def me_url(self) -> str:
        return f"{self.SSO_BASE_URL.rstrip('/')}/auth/me"


@lru_cache(maxsize=1)
def get_settings() -> SsoSettings:
    return SsoSettings()
