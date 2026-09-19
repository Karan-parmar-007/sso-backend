from pydantic_settings import BaseSettings, SettingsConfigDict

_base_config = SettingsConfigDict(
    env_file=".env",
    env_file_encoding="utf-8",
    env_ignore_empty=True,
    extra="ignore",
)


class DatabaseSettings(BaseSettings):
    MONGO_URI: str = "mongodb://localhost:27017"
    MONGO_DB_NAME: str = "sso_auth"

    model_config = _base_config


class SecuritySettings(BaseSettings):
    JWT_SECRET: str
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRY_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRY_DAYS: int = 7
    ENVIRONMENT: str = "development"
    COOKIE_DOMAIN: str = ".karanparmar.in"

    # Token / link expiry
    EMAIL_VERIFICATION_EXPIRY_HOURS: int = 24
    PASSWORD_RESET_EXPIRY_HOURS: int = 1
    EMAIL_CHANGE_EXPIRY_HOURS: int = 24

    # Password policy
    PASSWORD_MIN_LENGTH: int = 8

    # Rate limits (from env)
    MAX_FORGOT_PASSWORD_PER_DAY: int = 3
    MAX_CHANGE_PASSWORD_PER_DAY: int = 3
    MAX_EMAILS_PER_TOKEN: int = 3
    MAX_EMAIL_CHANGE_PER_DAY: int = 1
    MAX_VERIFY_EMAIL_SENDS_PER_DAY: int = 3

    CSRF_EXEMPT_PATHS: list[str] = [
        "/api/auth/login",
        "/api/auth/signup",
        "/api/auth/refresh",
        "/api/auth/forgot-password",
        "/api/auth/reset-password",
        "/api/auth/verify-email",
        "/api/auth/confirm-email-change",
        "/docs",
        "/redoc",
        "/openapi.json",
        "/health",
    ]

    CORS_ORIGINS: list[str] = [
        "http://localhost:5173",
        "http://localhost:4173",
        "http://localhost:5174",
        "http://localhost:4174",
        "http://localhost:5175",
        "http://localhost:4175",
        "http://localhost:1576",
        "http://localhost:1577",
        "http://localhost:3000",
        "https://auth.karanparmar.in",
        "https://karanparmar.in",
        "https://www.karanparmar.in",
        "https://familyos.karanparmar.in",
        "https://app.karanparmar.in",
    ]

    AUTH_FRONTEND_URL: str = "http://localhost:5173"
    OWNER_EMAIL: str = ""
    OWNER_PASSWORD: str = ""
    OWNER_NAME: str = "Owner"

    # APScheduler: cleanup expired tokens once daily
    TOKEN_CLEANUP_ENABLED: bool = True
    TOKEN_CLEANUP_HOUR: int = 0  # 0 = midnight
    TOKEN_CLEANUP_TIMEZONE: str = "Asia/Kolkata"

    model_config = _base_config


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
