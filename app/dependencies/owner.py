from typing import Annotated, Any, Dict

from fastapi import Depends, HTTPException, status

from app.api.dependencies import get_auth_service
from app.dependencies.jwt_auth import require_auth
from app.services.auth_service import AuthService


async def require_owner(
    user_data: Annotated[Dict[str, Any], Depends(require_auth)],
    auth_service: AuthService = Depends(get_auth_service),
) -> Dict[str, Any]:
    """Require a valid session first, then the owner role."""
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

    if role["name"].lower() != "owner":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Owner access required",
        )

    return user_data
