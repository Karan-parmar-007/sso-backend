class SsoError(Exception):
    """Base class for SDK errors."""


class InvalidTokenError(SsoError):
    """Token is missing, malformed, expired, revoked or not ours (→ 401)."""


class SsoUnavailableError(SsoError):
    """SSO could not be reached or answered unexpectedly (→ 503)."""
