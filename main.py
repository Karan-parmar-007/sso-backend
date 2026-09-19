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
from app.middleware.csrf import CSRFMiddleware


@asynccontextmanager
async def lifespan(app: FastAPI):
    await connect_to_mongo()
    db = get_mongo_db()
    await ensure_indexes(db)
    start_scheduler()
    yield
    stop_scheduler()
    await close_mongo_connection()


app = FastAPI(title="SSO Auth", lifespan=lifespan)
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_origins=security_settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(CSRFMiddleware)
