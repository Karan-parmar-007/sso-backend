from fastapi import APIRouter

from app.api.auth import router as auth_router
from app.api.admin import router as admin_router

api_router = APIRouter()
api_router.include_router(auth_router, prefix="/api/auth", tags=["auth"])
api_router.include_router(admin_router, prefix="/api/auth/admin", tags=["admin"])
