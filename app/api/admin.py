from typing import Annotated, Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.api.dependencies import AdminServiceDep, AuditServiceDep
from app.dependencies.role import require_role
from app.schemas.auth import (
    AdminChangeRoleRequest,
    AdminClientItem,
    AdminClientWithSecret,
    AdminClientsResponse,
    AdminCreateClientRequest,
    AdminCreateRoleRequest,
    AdminResetPasswordResponse,
    AdminRoleItem,
    AdminRolesResponse,
    AdminSetAppRolesRequest,
    AdminUpdateClientRequest,
    AdminUpdateUserRequest,
    AdminUsersResponse,
    AuditEventsResponse,
    MessageResponse,
    UserInfoResponse,
)
from app.utils.cleanup_tokens import cleanup_expired_tokens, summarize_cleanup
from app.utils.request_context import request_context

router = APIRouter()

# Owner manages users; owner + super_admin can list roles for apps admin.
_ADMIN_ROLES = require_role(["owner", "super_admin"])
_OWNER = require_role("owner")

OwnerPayload = Annotated[Dict[str, Any], Depends(_OWNER)]


def _actor(payload: Dict[str, Any]) -> str:
    return payload.get("user_id") or payload["sub"]


def _bad_request(e: ValueError) -> HTTPException:
    detail = str(e)
    code = 409 if "already" in detail.lower() else (404 if "not found" in detail.lower() else 400)
    return HTTPException(status_code=code, detail=detail)


# --------------------------------------------------------------------------
# Users & roles
# --------------------------------------------------------------------------


@router.get("/users", response_model=AdminUsersResponse)
async def list_users(
    service: AdminServiceDep,
    user: OwnerPayload,
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
    request: Request,
    data: AdminCreateRoleRequest,
    service: AdminServiceDep,
    user: OwnerPayload,
):
    try:
        role = await service.create_role(data.name, _actor(user), request_context(request))
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))
    return AdminRoleItem(**role)


@router.patch("/users/{user_id}/role", response_model=UserInfoResponse)
async def change_role(
    user_id: str,
    request: Request,
    data: AdminChangeRoleRequest,
    service: AdminServiceDep,
    user: OwnerPayload,
):
    try:
        user_doc = await service.change_role(
            user_id, data.role_name, _actor(user), request_context(request)
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return UserInfoResponse(**user_doc)


@router.put("/users/{user_id}/app-roles/{client_id}", response_model=UserInfoResponse)
async def set_app_roles(
    user_id: str,
    client_id: str,
    request: Request,
    data: AdminSetAppRolesRequest,
    service: AdminServiceDep,
    user: OwnerPayload,
):
    """Replace the user's roles in one application (empty list = remove)."""
    try:
        user_doc = await service.set_app_roles(
            user_id, client_id, data.roles, _actor(user), request_context(request)
        )
    except ValueError as e:
        raise _bad_request(e)
    return UserInfoResponse(**user_doc)


@router.patch("/users/{user_id}", response_model=UserInfoResponse)
async def update_user(
    user_id: str,
    request: Request,
    data: AdminUpdateUserRequest,
    service: AdminServiceDep,
    user: OwnerPayload,
):
    try:
        user_doc = await service.update_user(
            user_id,
            _actor(user),
            request_context(request),
            email=str(data.email) if data.email is not None else None,
            email_verified=data.email_verified,
        )
    except ValueError as e:
        raise _bad_request(e)
    return UserInfoResponse(**user_doc)


@router.post("/users/{user_id}/reset-password", response_model=AdminResetPasswordResponse)
async def reset_user_password(
    user_id: str,
    request: Request,
    service: AdminServiceDep,
    user: OwnerPayload,
):
    """Invalidate the password, end all sessions, email a single-use reset link."""
    try:
        result = await service.reset_password(user_id, _actor(user), request_context(request))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return AdminResetPasswordResponse(**result)


# --------------------------------------------------------------------------
# Applications (first-party apps + OAuth/OIDC clients)
# --------------------------------------------------------------------------


@router.get("/clients", response_model=AdminClientsResponse)
async def list_clients(service: AdminServiceDep, user: OwnerPayload):
    clients = await service.list_clients()
    return AdminClientsResponse(total_count=len(clients), clients=clients)


@router.post("/clients", response_model=AdminClientWithSecret, status_code=201)
async def create_client(
    request: Request,
    data: AdminCreateClientRequest,
    service: AdminServiceDep,
    user: OwnerPayload,
):
    try:
        client, secret = await service.create_client(
            data.model_dump(), _actor(user), request_context(request)
        )
    except ValueError as e:
        raise _bad_request(e)
    return AdminClientWithSecret(**client, client_secret=secret)


@router.patch("/clients/{client_id}", response_model=AdminClientItem)
async def update_client(
    client_id: str,
    request: Request,
    data: AdminUpdateClientRequest,
    service: AdminServiceDep,
    user: OwnerPayload,
):
    try:
        client = await service.update_client(
            client_id, data.model_dump(exclude_unset=True), _actor(user), request_context(request)
        )
    except ValueError as e:
        raise _bad_request(e)
    return AdminClientItem(**client)


@router.post("/clients/{client_id}/rotate-secret", response_model=AdminClientWithSecret)
async def rotate_client_secret(
    client_id: str,
    request: Request,
    service: AdminServiceDep,
    user: OwnerPayload,
):
    try:
        secret = await service.rotate_client_secret(client_id, _actor(user), request_context(request))
    except ValueError as e:
        raise _bad_request(e)
    client = next(c for c in await service.list_clients() if c["client_id"] == client_id)
    return AdminClientWithSecret(**client, client_secret=secret)


@router.delete("/clients/{client_id}", response_model=MessageResponse)
async def delete_client(
    client_id: str,
    request: Request,
    service: AdminServiceDep,
    user: OwnerPayload,
):
    try:
        await service.delete_client(client_id, _actor(user), request_context(request))
    except ValueError as e:
        raise _bad_request(e)
    return MessageResponse(message="Application deleted")


# --------------------------------------------------------------------------
# Audit & maintenance
# --------------------------------------------------------------------------


@router.get("/audit", response_model=AuditEventsResponse)
async def list_audit_events(
    audit: AuditServiceDep,
    user: OwnerPayload,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    user_id: Optional[str] = Query(None),
    event: Optional[str] = Query(None, max_length=64),
):
    try:
        data = await audit.list_page(page, page_size, user_id=user_id, event=event)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid user_id")
    return AuditEventsResponse(**data)


@router.post("/cleanup-tokens")
async def run_token_cleanup(user: OwnerPayload):
    """Run the same cleanup logic used by the midnight cron."""
    counts = await cleanup_expired_tokens()
    return summarize_cleanup(counts)
