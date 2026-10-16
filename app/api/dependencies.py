"""DB + service injection (same role as portfolio `app/api/dependencies.py`).

Auth/role/owner guards live in `app/dependencies/` — they are API access checks.
This file only wires Mongo and services into routes.
"""

from typing import Annotated

from fastapi import Depends
from pymongo.asynchronous.database import AsyncDatabase

from app.db.mongo import get_mongo_db
from app.services.admin_service import AdminService
from app.services.audit_service import AuditService
from app.services.auth_service import AuthService
from app.services.oauth_service import OAuthService

MongoDBDep = Annotated[AsyncDatabase, Depends(get_mongo_db)]


async def get_auth_service(db: MongoDBDep) -> AuthService:
    return AuthService(db)


async def get_admin_service(db: MongoDBDep) -> AdminService:
    return AdminService(db)


async def get_audit_service(db: MongoDBDep) -> AuditService:
    return AuditService(db)


async def get_oauth_service(db: MongoDBDep) -> OAuthService:
    return OAuthService(db)


AuthServiceDep = Annotated[AuthService, Depends(get_auth_service)]
AuditServiceDep = Annotated[AuditService, Depends(get_audit_service)]
AdminServiceDep = Annotated[AdminService, Depends(get_admin_service)]
OAuthServiceDep = Annotated[OAuthService, Depends(get_oauth_service)]
