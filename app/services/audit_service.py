"""Security audit trail. Recording never breaks the request that triggered it."""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any, Optional

from bson import ObjectId
from pymongo.asynchronous.database import AsyncDatabase

from app.config import security_settings
from app.db.indexes import utcnow
from app.db.oids import id_str, to_object_id
from app.models.audit_event import AuditEventModel
from app.utils.request_context import RequestContext

logger = logging.getLogger(__name__)


class AuditService:
    def __init__(self, db: AsyncDatabase):
        self.events = AuditEventModel(db)

    async def record(
        self,
        event: str,
        *,
        user_id: Optional[str | ObjectId] = None,
        email: Optional[str] = None,
        actor_id: Optional[str | ObjectId] = None,
        ctx: Optional[RequestContext] = None,
        session_id: Optional[str] = None,
        **meta: Any,
    ) -> None:
        now = utcnow()
        doc: dict[str, Any] = {
            "event": event,
            "created_at": now,
            "expire_at": now + timedelta(days=security_settings.AUDIT_RETENTION_DAYS),
            "user_id": to_object_id(user_id) if user_id else None,
            "email": email,
            "actor_id": to_object_id(actor_id) if actor_id else None,
            "session_id": session_id,
            "ip": ctx.ip if ctx else None,
            "user_agent": ctx.user_agent if ctx else None,
            "meta": meta or None,
        }
        try:
            await self.events.insert(doc)
        except Exception:
            logger.exception("Failed to record audit event %s", event)
        logger.info("audit %s user=%s actor=%s %s", event, user_id, actor_id, meta or "")

    async def list_page(
        self,
        page: int,
        page_size: int,
        user_id: Optional[str] = None,
        event: Optional[str] = None,
    ) -> dict:
        page = max(1, page)
        page_size = min(max(1, page_size), 100)
        total = await self.events.count(user_id, event)
        docs = await self.events.list_page((page - 1) * page_size, page_size, user_id, event)
        return {
            "total_count": total,
            "page": page,
            "page_size": page_size,
            "events": [serialize_event(d) for d in docs],
        }


def serialize_event(doc: dict) -> dict:
    return {
        "id": id_str(doc),
        "event": doc["event"],
        "created_at": doc["created_at"],
        "user_id": id_str(doc["user_id"]) if doc.get("user_id") else None,
        "email": doc.get("email"),
        "actor_id": id_str(doc["actor_id"]) if doc.get("actor_id") else None,
        "session_id": doc.get("session_id"),
        "ip": doc.get("ip"),
        "user_agent": doc.get("user_agent"),
        "meta": doc.get("meta"),
    }
