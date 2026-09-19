from typing import Annotated, Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Query

from app.api.dependencies import AdminServiceDep
from app.dependencies.role import require_role
from app.schemas.auth import (
    AdminChangeRoleRequest,
    AdminCreateRoleRequest,
    AdminResetPasswordRequest,
    AdminRoleItem,
    AdminRolesResponse,
    AdminUpdateUserRequest,
    AdminUsersResponse,
    UserInfoResponse,
)
from app.utils.cleanup_tokens import cleanup_expired_tokens, summarize_cleanup

router = APIRouter()

# Owner manages users; owner + super_admin can list roles for apps admin.
_ADMIN_ROLES = require_role(["owner", "super_admin"])
_OWNER = require_role("owner")


@router.get("/users", response_model=AdminUsersResponse)
async def list_users(
    service: AdminServiceDep,
    user: Annotated[Dict[str, Any], Depends(_OWNER)],
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=100),
):
    data = await service.list_users(page=page, page_size=page_size)
    return AdminUsersResponse(**data)


@router.get("/roles", response_model=AdminRolesResponse)
async def list_roles(
    service: AdminServiceDep,
    user: Annotated[Dict[str, Any], Depends(_ADMIN_ROLES)],
):
    data = await service.list_roles()
    return AdminRolesResponse(**data)


@router.post("/roles", response_model=AdminRoleItem, status_code=201)
async def create_role(
    data: AdminCreateRoleRequest,
    service: AdminServiceDep,
    user: Annotated[Dict[str, Any], Depends(_OWNER)],
):
    try:
        role = await service.create_role(data.name)
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))
    return AdminRoleItem(**role)


@router.patch("/users/{user_id}/role", response_model=UserInfoResponse)
async def change_role(
    user_id: str,
    data: AdminChangeRoleRequest,
    service: AdminServiceDep,
    user: Annotated[Dict[str, Any], Depends(_OWNER)],
):
    try:
        user_doc = await service.change_role(user_id, data.role_name)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return UserInfoResponse(**user_doc)


@router.patch("/users/{user_id}", response_model=UserInfoResponse)
async def update_user(
    user_id: str,
    data: AdminUpdateUserRequest,
    service: AdminServiceDep,
    user: Annotated[Dict[str, Any], Depends(_OWNER)],
):
    try:
        user_doc = await service.update_user(
            user_id,
            email=str(data.email) if data.email is not None else None,
            email_verified=data.email_verified,
        )
    except ValueError as e:
        detail = str(e)
        code = 409 if "already" in detail.lower() else 400
        raise HTTPException(status_code=code, detail=detail)
    return UserInfoResponse(**user_doc)


@router.post("/users/{user_id}/reset-password")
async def reset_user_password(
    user_id: str,
    data: AdminResetPasswordRequest,
    service: AdminServiceDep,
    user: Annotated[Dict[str, Any], Depends(_OWNER)],
):
    try:
        result = await service.reset_password(
            user_id,
            send_email=data.send_email,
            password=data.password,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return result


@router.post("/cleanup-tokens")
async def run_token_cleanup(
    user: Annotated[Dict[str, Any], Depends(_OWNER)],
):
    """Run the same cleanup logic used by the midnight cron."""
    counts = await cleanup_expired_tokens()
    return summarize_cleanup(counts)
