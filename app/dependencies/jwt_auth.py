"""FastAPI dependencies: auth, role, owner, and service injectors."""
from typing import Any, Dict, Optional

from fastapi import Depends, HTTPException, Request, status

from app.api.dependencies import get_auth_service
from app.services.auth_service import AuthService
from app.utils.security import decode_access_token

ACCESS_TOKEN_COOKIE = "access_token"


def extract_access_token(request: Request) -> Optional[str]:
    """Cookie for browsers; `Authorization: Bearer` for app backends calling /me."""
    token = request.cookies.get(ACCESS_TOKEN_COOKIE)
    if token:
        return token
    auth = request.headers.get("authorization") or ""
    if auth.lower().startswith("bearer "):
        return auth[7:].strip() or None
    return None


def optional_access_payload(request: Request) -> Optional[Dict[str, Any]]:
    """Signature/expiry-checked payload, or None. No session lookup."""
    token = extract_access_token(request)
    return decode_access_token(token) if token else None


class AuthDependency:
    """Validate the access token and that its session has not been revoked."""

    async def __call__(
        self,
        request: Request,
        auth_service: AuthService = Depends(get_auth_service),
    ) -> Dict[str, Any]:
        token = extract_access_token(request)
        if not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not authenticated",
            )
        payload = decode_access_token(token)
        if not payload:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token",
            )
        if not await auth_service.session_is_active(payload.get("sid")):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session has been revoked",
            )
        request.state.user = payload
        return payload


require_auth = AuthDependency()
