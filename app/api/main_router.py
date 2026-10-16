from fastapi import APIRouter

from app.api.auth import router as auth_router
from app.api.admin import router as admin_router
from app.api.oauth import router as oauth_router
from app.api.wellknown import router as wellknown_router

api_router = APIRouter()
api_router.include_router(auth_router, prefix="/api/auth", tags=["auth"])
api_router.include_router(admin_router, prefix="/api/auth/admin", tags=["admin"])
api_router.include_router(wellknown_router, prefix="/api/auth", tags=["discovery"])
api_router.include_router(oauth_router, prefix="/api/auth/oauth", tags=["oauth"])
