"""Shared SSO client for karanparmar.in app backends.

Vendored: the source of truth is sso-backend/sdk/python/karan_sso. Do not
edit copies inside app repos — change it there and run `sdk/sync.sh`.
"""

from pathlib import Path

from .errors import InvalidTokenError, SsoError, SsoUnavailableError
from .identity import ADMIN_ROLES, SsoIdentity
from .settings import SsoSettings, get_settings
from .verifier import TokenVerifier

__version__ = (Path(__file__).with_name("VERSION").read_text().strip())

__all__ = [
    "ADMIN_ROLES",
    "InvalidTokenError",
    "SsoError",
    "SsoIdentity",
    "SsoSettings",
    "SsoUnavailableError",
    "TokenVerifier",
    "get_settings",
]
