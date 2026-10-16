from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple
import hashlib
import re
import secrets
import uuid

import jwt
from fastapi import HTTPException, status
from passlib.context import CryptContext

from app.config import security_settings
from app.utils.keys import active_signing_key, public_key_for_kid

ACCESS_TOKEN_EXPIRE = timedelta(minutes=security_settings.ACCESS_TOKEN_EXPIRY_MINUTES)
ACCESS_TOKEN_EXPIRE_SECONDS = int(ACCESS_TOKEN_EXPIRE.total_seconds())
REFRESH_TOKEN_EXPIRE = timedelta(days=security_settings.REFRESH_TOKEN_EXPIRY_DAYS)
REFRESH_TOKEN_EXPIRE_SECONDS = int(REFRESH_TOKEN_EXPIRE.total_seconds())

# bcrypt silently ignores everything after 72 bytes.
MAX_PASSWORD_BYTES = 72

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Verified against when the account does not exist, so login timing does not
# reveal which emails are registered.
_DUMMY_PASSWORD_HASH = pwd_context.hash(secrets.token_urlsafe(16))


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: Optional[str]) -> bool:
    if not hashed_password:
        pwd_context.verify(plain_password, _DUMMY_PASSWORD_HASH)
        return False
    return pwd_context.verify(plain_password, hashed_password)


def burn_password_check(plain_password: str) -> None:
    """Spend the same time as a real check (unknown account)."""
    pwd_context.verify(plain_password, _DUMMY_PASSWORD_HASH)


def validate_password_strength(password: str) -> None:
    min_len = security_settings.PASSWORD_MIN_LENGTH
    if len(password) < min_len:
        raise ValueError(f"Password must be at least {min_len} characters")
    if len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
        raise ValueError(f"Password must be at most {MAX_PASSWORD_BYTES} bytes")
    if not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
        raise ValueError("Password must contain at least one letter and one number")


# --------------------------------------------------------------------------
# JWT
# --------------------------------------------------------------------------


def sign_jwt(payload: Dict[str, Any], *, force_rs256: bool = False) -> str:
    """Sign with the active RS256 key (or the legacy HS256 secret during rollout)."""
    if force_rs256 or security_settings.JWT_SIGNING_ALG == "RS256":
        key = active_signing_key()
        return jwt.encode(
            payload, key.private_key, algorithm="RS256", headers={"kid": key.kid}
        )
    return jwt.encode(payload, security_settings.JWT_SECRET, algorithm="HS256")


def create_access_token(
    subject: str,
    *,
    session_id: Optional[str],
    additional_claims: Optional[Dict[str, Any]] = None,
    expires_delta: Optional[timedelta] = None,
) -> str:
    now = utcnow()
    payload: Dict[str, Any] = {
        "iss": security_settings.JWT_ISSUER,
        "sub": subject,
        "type": "access",
        "jti": uuid.uuid4().hex,
        "iat": now,
        "exp": now + (expires_delta or ACCESS_TOKEN_EXPIRE),
    }
    if security_settings.JWT_AUDIENCE:
        payload["aud"] = security_settings.JWT_AUDIENCE
    if session_id:
        payload["sid"] = session_id
    if additional_claims:
        payload.update(additional_claims)
    return sign_jwt(payload)


def decode_jwt(
    token: str,
    *,
    audience: Optional[str] = None,
    require_audience: bool = False,
    allow_expired: bool = False,
) -> Dict[str, Any]:
    """Verify signature + exp (+ iss when present, aud when given).

    The algorithm is pinned per key type: RS256 only with our published keys,
    HS256 only with the legacy secret. Raises jwt.PyJWTError on failure.
    `allow_expired` skips the exp check (OIDC `id_token_hint` only).
    """
    header = jwt.get_unverified_header(token)
    alg = header.get("alg")
    options: Dict[str, Any] = {"require": ["exp"]}
    if not audience:
        options["verify_aud"] = False
    if allow_expired:
        options["verify_exp"] = False
    if alg == "RS256":
        key = public_key_for_kid(header.get("kid"))
        if key is None:
            raise jwt.InvalidKeyError("Unknown signing key")
        payload = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            audience=audience,
            options=options,
            leeway=10,
        )
    elif (
        alg == "HS256"
        and security_settings.JWT_SIGNING_ALG == "HS256"
        and security_settings.JWT_SECRET
    ):
        # Rollout only: accepted while SSO itself still signs HS256.
        payload = jwt.decode(
            token,
            security_settings.JWT_SECRET,
            algorithms=["HS256"],
            audience=audience,
            options=options,
            leeway=10,
        )
    else:
        raise jwt.InvalidAlgorithmError("Unsupported token algorithm")

    if "iss" in payload and payload["iss"] != security_settings.JWT_ISSUER:
        raise jwt.InvalidIssuerError("Invalid issuer")
    if require_audience and "aud" not in payload:
        raise jwt.MissingRequiredClaimError("aud")
    return payload


def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    """First-party session token (cookie / bearer). None when invalid."""
    audience = security_settings.JWT_AUDIENCE or None
    try:
        payload = decode_jwt(token, audience=audience)
    except jwt.PyJWTError:
        return None
    if payload.get("type") != "access" or not payload.get("sid"):
        # Every session token names its session; without `sid` it can't be
        # checked for revocation (pre-release or forged), so it's refused.
        return None
    if audience is None and "aud" in payload:
        # OAuth client tokens carry an audience; they are not session tokens.
        return None
    return payload


def verify_token(token: str, expected_type: Optional[str] = "access") -> Dict[str, Any]:
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing token"
        )
    payload = decode_access_token(token)
    if not payload or (expected_type and payload.get("type") != expected_type):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )
    return payload


# --------------------------------------------------------------------------
# Opaque tokens
# --------------------------------------------------------------------------


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


def new_session_id() -> str:
    return uuid.uuid4().hex
