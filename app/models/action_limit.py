from datetime import datetime, timedelta
from typing import Optional

from pymongo.asynchronous.database import AsyncDatabase

from app.db.indexes import utcnow


class ActionLimitModel:
    """Mongo access for the `action_limits` collection."""

    def __init__(self, db: AsyncDatabase):
        self.col = db.action_limits

    async def find(self, key: str, action: str) -> Optional[dict]:
        return await self.col.find_one({"key": key, "action": action})

    async def increment(self, doc_id, now: datetime) -> None:
        await self.col.update_one(
            {"_id": doc_id},
            {"$inc": {"count": 1}, "$set": {"updated_at": now}},
        )

    async def start_window(self, key: str, action: str, now: datetime) -> None:
        expire_at = now + timedelta(days=1)
        await self.col.update_one(
            {"key": key, "action": action},
            {
                "$set": {
                    "key": key,
                    "action": action,
                    "count": 1,
                    "window_start": now,
                    "expire_at": expire_at,
                    "updated_at": now,
                }
            },
            upsert=True,
        )

    async def delete_expired(self, now: datetime | None = None) -> int:
        now = now or utcnow()
        result = await self.col.delete_many({"expire_at": {"$lte": now}})
        return result.deleted_count
