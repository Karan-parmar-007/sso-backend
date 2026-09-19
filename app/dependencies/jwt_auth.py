from typing import Any, Dict, Optional

from fastapi import Cookie, HTTPException, Request, Response, status

from app.middleware.csrf import CSRF_COOKIE_NAME, cookie_domain
from app.utils.security import verify_token


def _clear_all_auth_cookies(response: Response) -> None:
    domain = cookie_domain()
    response.delete_cookie("access_token", domain=domain)
    response.delete_cookie("refresh_token", path="/api/auth", domain=domain)
    response.delete_cookie(CSRF_COOKIE_NAME, domain=domain)


class AuthDependency:
    """Validate access + CSRF cookies and return the JWT payload."""

    async def __call__(
        self,
        request: Request,
        response: Response,
        access_token: Optional[str] = Cookie(None),
        csrf_token: Optional[str] = Cookie(None, alias=CSRF_COOKIE_NAME),
    ) -> Dict[str, Any]:
        if not access_token:
            _clear_all_auth_cookies(response)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not authenticated",
            )
        if not csrf_token:
            _clear_all_auth_cookies(response)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Security token missing. Please login again.",
            )
        try:
            payload = verify_token(access_token, expected_type="access")
            request.state.user = payload
            return payload
        except HTTPException:
            _clear_all_auth_cookies(response)
            raise
        except Exception:
            _clear_all_auth_cookies(response)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
            )


require_auth = AuthDependency()
