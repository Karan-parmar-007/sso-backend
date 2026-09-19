"""DB + service injection (same role as portfolio `app/api/dependencies.py`).

Auth/role/owner guards live in `app/dependencies/` — they are API access checks.
This file only wires Mongo and services into routes.
"""

from typing import Annotated

from fastapi import Depends
from pymongo.asynchronous.database import AsyncDatabase

from app.db.mongo import get_mongo_db
from app.services.admin_service import AdminService
from app.services.auth_service import AuthService

MongoDBDep = Annotated[AsyncDatabase, Depends(get_mongo_db)]


async def get_auth_service(db: MongoDBDep) -> AuthService:
    return AuthService(db)


async def get_admin_service(db: MongoDBDep) -> AdminService:
    return AdminService(db)


AuthServiceDep = Annotated[AuthService, Depends(get_auth_service)]
AdminServiceDep = Annotated[AdminService, Depends(get_admin_service)]
