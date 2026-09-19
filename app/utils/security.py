from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple
import hashlib
import re
import secrets

from fastapi import HTTPException, status
from jose import jwt
from jose.exceptions import ExpiredSignatureError, JWTError
from passlib.context import CryptContext

from app.config import security_settings

SECRET_KEY = security_settings.JWT_SECRET
ALGORITHM = security_settings.JWT_ALGORITHM

ACCESS_TOKEN_EXPIRE = timedelta(minutes=security_settings.ACCESS_TOKEN_EXPIRY_MINUTES)
ACCESS_TOKEN_EXPIRE_SECONDS = int(ACCESS_TOKEN_EXPIRE.total_seconds())
REFRESH_TOKEN_EXPIRE = timedelta(days=security_settings.REFRESH_TOKEN_EXPIRY_DAYS)
REFRESH_TOKEN_EXPIRE_SECONDS = int(REFRESH_TOKEN_EXPIRE.total_seconds())

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def validate_password_strength(password: str) -> None:
    min_len = security_settings.PASSWORD_MIN_LENGTH
    if len(password) < min_len:
        raise ValueError(f"Password must be at least {min_len} characters")
    if not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
        raise ValueError("Password must contain at least one letter and one number")


def create_access_token(
    subject: str,
    expires_delta: Optional[timedelta] = None,
    additional_claims: Optional[Dict[str, Any]] = None,
) -> str:
    payload: Dict[str, Any] = {"sub": subject, "type": "access"}
    if additional_claims:
        payload.update(additional_claims)
    expires = utcnow() + (expires_delta or ACCESS_TOKEN_EXPIRE)
    payload["exp"] = expires
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> Optional[Dict[str, Any]]:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except (ExpiredSignatureError, JWTError):
        return None


def verify_token(token: str, expected_type: Optional[str] = None) -> Dict[str, Any]:
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing token"
        )
    payload = decode_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )
    if expected_type and payload.get("type") != expected_type:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type"
        )
    return payload


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_opaque_token() -> Tuple[str, str]:
    """Return (plain_token, token_hash)."""
    plain = secrets.token_urlsafe(48)
    return plain, hash_token(plain)


def create_refresh_token(
    expires_delta: Optional[timedelta] = None,
) -> Tuple[str, str, datetime]:
    plain, token_hash = create_opaque_token()
    expires_at = utcnow() + (expires_delta or REFRESH_TOKEN_EXPIRE)
    return plain, token_hash, expires_at


def generate_temp_password(length: int = 16) -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%"
    return "".join(secrets.choice(alphabet) for _ in range(length))
