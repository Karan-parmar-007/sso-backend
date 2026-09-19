from collections.abc import Sequence
from typing import Annotated, Any, Callable, Dict

from fastapi import Depends, HTTPException, status

from app.api.dependencies import get_auth_service
from app.dependencies.jwt_auth import require_auth
from app.services.auth_service import AuthService


def _normalize_roles(role_name: str | Sequence[str]) -> list[str]:
    names = [role_name] if isinstance(role_name, str) else list(role_name)
    allowed = [n.strip().lower() for n in names if n and str(n).strip()]
    if not allowed:
        raise ValueError("require_role needs at least one role name")
    return allowed


def require_role(role_name: str | Sequence[str]) -> Callable:
    """Require a valid session first, then one of the given role names.

    Pass a single role (`"owner"`) or a list (`["owner", "super_admin"]`).
    """
    allowed = _normalize_roles(role_name)

    async def _dependency(
        user_data: Annotated[Dict[str, Any], Depends(require_auth)],
        auth_service: AuthService = Depends(get_auth_service),
    ) -> Dict[str, Any]:
        user_id = user_data.get("user_id") or user_data.get("sub")
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token: user_id missing",
            )

        user = await auth_service.get_user_by_id(user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found",
            )

        role = None
        if user.get("role_id") is not None:
            role = await auth_service.get_role_by_id(user["role_id"])
        if not role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User has no role assigned",
            )

        current = str(role["name"]).strip().lower()
        if current not in allowed:
            needed = "', '".join(allowed)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: one of '{needed}' roles required",
            )

        return user_data

    return _dependency
