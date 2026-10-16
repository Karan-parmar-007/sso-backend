from datetime import datetime
from typing import Any, Optional

from pymongo.asynchronous.database import AsyncDatabase

from app.db.oids import to_object_id


class AuditEventModel:
    """Append-only security log in `audit_events` (TTL on `expire_at`)."""

    def __init__(self, db: AsyncDatabase):
        self.col = db.audit_events

    async def insert(self, doc: dict) -> None:
        await self.col.insert_one(doc)

    @staticmethod
    def _query(user_id: Optional[str], event: Optional[str]) -> dict[str, Any]:
        query: dict[str, Any] = {}
        if user_id:
            query["user_id"] = to_object_id(user_id)
        if event:
            query["event"] = event
        return query

    async def count(self, user_id: Optional[str] = None, event: Optional[str] = None) -> int:
        return await self.col.count_documents(self._query(user_id, event))

    async def list_page(
        self,
        skip: int,
        limit: int,
        user_id: Optional[str] = None,
        event: Optional[str] = None,
    ) -> list[dict]:
        cursor = (
            self.col.find(self._query(user_id, event))
            .sort("created_at", -1)
            .skip(skip)
            .limit(limit)
        )
        return [doc async for doc in cursor]

    async def delete_expired(self, now: datetime) -> int:
        result = await self.col.delete_many({"expire_at": {"$lte": now}})
        return result.deleted_count
