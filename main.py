from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.main_router import api_router
from app.config import security_settings
from app.cron import start_scheduler, stop_scheduler
from app.db.indexes import ensure_indexes
from app.db.mongo import (
    close_mongo_connection,
    connect_to_mongo,
    get_mongo_db,
)
from app.middleware.csrf import CSRF_HEADER_NAME, CSRFMiddleware, SecurityHeadersMiddleware
from app.utils.keys import active_signing_key
from bootstrap import seed_roles_and_owner


@asynccontextmanager
async def lifespan(app: FastAPI):
    active_signing_key()  # fail fast on a bad key
    await connect_to_mongo()
    db = get_mongo_db()
    await ensure_indexes(db)
    await seed_roles_and_owner(db)
    start_scheduler()
    yield
    stop_scheduler()
    await close_mongo_connection()


_docs = {} if not security_settings.is_production else {
    "docs_url": None,
    "redoc_url": None,
    "openapi_url": None,
}

app = FastAPI(title="SSO Auth", lifespan=lifespan, **_docs)
app.include_router(api_router)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}

app.add_middleware(CSRFMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=security_settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", CSRF_HEADER_NAME],
)
