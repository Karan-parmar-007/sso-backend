"""Access-token signing keys and the public JWKS.

Production keys come from env (JWT_PRIVATE_KEY_B64 + JWT_ACTIVE_KID). Outside
production a key is generated once and persisted under `.keys/` so tokens
survive restarts. Rotation: move the old public key into
JWT_PREVIOUS_PUBLIC_KEYS, set the new private key + kid, and keep the old one
published until every token it signed has expired (> access-token TTL).
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from jwt.algorithms import RSAAlgorithm

from app.config import security_settings

logger = logging.getLogger(__name__)

_DEV_KEY_PATH = Path(__file__).resolve().parents[2] / ".keys" / "dev_signing_key.pem"


@dataclass(frozen=True)
class SigningKey:
    kid: str
    private_key: RSAPrivateKey
    public_key: RSAPublicKey


def generate_private_key_pem() -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _thumbprint_kid(public_key: RSAPublicKey) -> str:
    der = public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(der).hexdigest()[:16]


def _decode_b64_pem(value: str) -> bytes:
    value = value.strip()
    if value.startswith("-----BEGIN"):
        return value.encode()
    return base64.b64decode(value)


def _load_private_pem() -> bytes:
    if security_settings.JWT_PRIVATE_KEY_B64:
        return _decode_b64_pem(security_settings.JWT_PRIVATE_KEY_B64)
    if _DEV_KEY_PATH.exists():
        return _DEV_KEY_PATH.read_bytes()
    pem = generate_private_key_pem()
    _DEV_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    _DEV_KEY_PATH.write_bytes(pem)
    logger.warning("Generated a development signing key at %s", _DEV_KEY_PATH)
    return pem


@lru_cache(maxsize=1)
def active_signing_key() -> SigningKey:
    private_key = serialization.load_pem_private_key(_load_private_pem(), password=None)
    if not isinstance(private_key, RSAPrivateKey):
        raise RuntimeError("JWT_PRIVATE_KEY_B64 must be an RSA private key")
    public_key = private_key.public_key()
    kid = security_settings.JWT_ACTIVE_KID or _thumbprint_kid(public_key)
    return SigningKey(kid=kid, private_key=private_key, public_key=public_key)


@lru_cache(maxsize=1)
def previous_public_keys() -> dict[str, RSAPublicKey]:
    keys: dict[str, RSAPublicKey] = {}
    raw = security_settings.JWT_PREVIOUS_PUBLIC_KEYS.strip()
    if not raw:
        return keys
    for entry in raw.split(","):
        kid, _, b64 = entry.strip().partition(":")
        if not kid or not b64:
            continue
        loaded = serialization.load_pem_public_key(_decode_b64_pem(b64))
        if not isinstance(loaded, RSAPublicKey):
            raise RuntimeError(f"Previous key {kid} is not an RSA public key")
        keys[kid] = loaded
    return keys


def public_key_for_kid(kid: str | None) -> RSAPublicKey | None:
    active = active_signing_key()
    if kid is None or kid == active.kid:
        return active.public_key
    return previous_public_keys().get(kid)


def _jwk(kid: str, public_key: RSAPublicKey) -> dict[str, Any]:
    jwk = json.loads(RSAAlgorithm.to_jwk(public_key))
    jwk.update({"kid": kid, "use": "sig", "alg": "RS256"})
    return jwk


def jwks() -> dict[str, Any]:
    active = active_signing_key()
    keys = [_jwk(active.kid, active.public_key)]
    keys += [_jwk(kid, key) for kid, key in previous_public_keys().items()]
    return {"keys": keys}
