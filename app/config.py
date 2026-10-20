from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_base_config = SettingsConfigDict(
    env_file=".env",
    env_file_encoding="utf-8",
    env_ignore_empty=True,
    extra="ignore",
)

_DEV_ORIGINS = [
    "http://localhost:5173",
    "http://localhost:4173",
    "http://localhost:5174",
    "http://localhost:4174",
    "http://localhost:5175",
    "http://localhost:4175",
    "http://localhost:1576",
    "http://localhost:1577",
    "http://localhost:3000",
]

_PROD_ORIGINS = [
    "https://auth.karanparmar.in",
    "https://karanparmar.in",
    "https://www.karanparmar.in",
    "https://familyos.karanparmar.in",
    "https://app.karanparmar.in",
    "https://studio.karanparmar.in",
]


class DatabaseSettings(BaseSettings):
    MONGO_URI: str = "mongodb://localhost:27017"
    MONGO_DB_NAME: str = "sso_auth"

    model_config = _base_config


class SecuritySettings(BaseSettings):
    ENVIRONMENT: str = "development"
    COOKIE_DOMAIN: str = ".karanparmar.in"

    # --- Access-token signing -------------------------------------------
    # RS256 (asymmetric, published via JWKS) is the target. HS256 exists only
    # for the rollout window while app backends still verify with the shared
    # secret — see docs/ROLLOUT.md.
    JWT_SIGNING_ALG: str = "RS256"
    # Legacy shared secret (HS256 signing during rollout only).
    JWT_SECRET: str = ""
    # Base64 of a PEM private key ("-----BEGIN PRIVATE KEY-----...").
    JWT_PRIVATE_KEY_B64: str = ""
    JWT_ACTIVE_KID: str = ""
    # Extra public keys still published in JWKS after a rotation:
    # "kid1:<b64 pem>,kid2:<b64 pem>"
    JWT_PREVIOUS_PUBLIC_KEYS: str = ""
    # Issuer = public URL of the auth API (OIDC discovery lives under it).
    JWT_ISSUER: str = "http://localhost:8000/api/auth"
    # Audience for first-party session tokens. Empty = omit `aud` (rollout).
    JWT_AUDIENCE: str = ""

    ACCESS_TOKEN_EXPIRY_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRY_DAYS: int = 7
    # Non-"remember me" sessions
    SHORT_SESSION_HOURS: int = 24
    # Parallel refreshes with the same token inside this window share the
    # session instead of tripping reuse detection (tabs / sibling apps).
    REFRESH_REUSE_GRACE_SECONDS: int = 30
    # /session refreshes proactively when the access token is this close to expiry.
    SESSION_REFRESH_LEEWAY_SECONDS: int = 60

    # Token / link expiry
    EMAIL_VERIFICATION_EXPIRY_HOURS: int = 24
    PASSWORD_RESET_EXPIRY_HOURS: int = 1
    ADMIN_PASSWORD_RESET_EXPIRY_HOURS: int = 24
    EMAIL_CHANGE_EXPIRY_HOURS: int = 24

    # Password policy
    PASSWORD_MIN_LENGTH: int = 8
    REQUIRE_EMAIL_VERIFICATION: bool = True

    # Daily limits
    MAX_FORGOT_PASSWORD_PER_DAY: int = 3
    MAX_CHANGE_PASSWORD_PER_DAY: int = 3
    MAX_EMAILS_PER_TOKEN: int = 3
    MAX_EMAIL_CHANGE_PER_DAY: int = 1
    MAX_VERIFY_EMAIL_SENDS_PER_DAY: int = 3

    # Brute-force protection (fixed windows)
    # Per (email, client IP): stops guessing without letting strangers lock
    # the owner out from elsewhere.
    LOGIN_MAX_FAILURES_PER_EMAIL: int = 5
    # Per account across all IPs: stops distributed guessing.
    LOGIN_MAX_ATTEMPTS_PER_ACCOUNT: int = 50
    LOGIN_MAX_FAILURES_PER_IP: int = 30
    LOGIN_FAILURE_WINDOW_MINUTES: int = 15
    PASSWORD_CHECK_MAX_FAILURES: int = 5  # change-password / email-change
    SIGNUP_MAX_PER_IP_PER_HOUR: int = 10

    # Number of reverse proxies in front of the API that append to
    # X-Forwarded-For (Caddy = 1). The client IP is taken that many hops
    # from the right, so a spoofed left-most entry is ignored.
    TRUSTED_PROXY_HOPS: int = 1

    AUDIT_RETENTION_DAYS: int = 365
    NEW_DEVICE_ALERTS: bool = True

    CSRF_EXEMPT_PATHS: list[str] = [
        "/api/auth/login",
        "/api/auth/signup",
        "/api/auth/refresh",
        "/api/auth/forgot-password",
        "/api/auth/reset-password",
        "/api/auth/verify-email",
        "/api/auth/resend-verification",
        "/api/auth/confirm-email-change",
        "/api/auth/oauth/token",
        "/api/auth/oauth/revoke",
        "/api/auth/oauth/userinfo",
        "/health",
    ]

    # Empty = derived from ENVIRONMENT (localhost origins only outside production).
    CORS_ORIGINS: list[str] = []

    AUTH_FRONTEND_URL: str = "http://localhost:5173"
    OWNER_EMAIL: str = ""
    OWNER_PASSWORD: str = ""
    OWNER_NAME: str = "Owner"

    # APScheduler: cleanup expired tokens once daily
    TOKEN_CLEANUP_ENABLED: bool = True
    TOKEN_CLEANUP_HOUR: int = 0  # 0 = midnight
    TOKEN_CLEANUP_TIMEZONE: str = "Asia/Kolkata"

    model_config = _base_config

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT == "production"

    @model_validator(mode="after")
    def _derive(self) -> "SecuritySettings":
        if not self.CORS_ORIGINS:
            self.CORS_ORIGINS = (
                list(_PROD_ORIGINS)
                if self.is_production
                else _DEV_ORIGINS + _PROD_ORIGINS
            )
        self.JWT_SIGNING_ALG = self.JWT_SIGNING_ALG.upper()
        if self.JWT_SIGNING_ALG not in {"RS256", "HS256"}:
            raise ValueError("JWT_SIGNING_ALG must be RS256 or HS256")
        if self.JWT_SIGNING_ALG == "HS256" and not self.JWT_SECRET:
            raise ValueError("JWT_SIGNING_ALG=HS256 requires JWT_SECRET")
        if self.is_production and not self.JWT_PRIVATE_KEY_B64:
            raise ValueError(
                "JWT_PRIVATE_KEY_B64 is required in production "
                "(generate with: python -m scripts.generate_signing_key)"
            )
        return self


class EmailSettings(BaseSettings):
    SMTP_HOST: str = "smtp.gmail.com"
    SMTP_PORT: int = 587
    SMTP_USERNAME: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM_EMAIL: str = ""
    SMTP_FROM_NAME: str = "Auth SSO"

    model_config = _base_config


db_settings = DatabaseSettings()  # type: ignore
security_settings = SecuritySettings()  # type: ignore
email_settings = EmailSettings()  # type: ignore
