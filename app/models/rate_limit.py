from datetime import datetime, timedelta

from pymongo import ReturnDocument
from pymongo.asynchronous.database import AsyncDatabase


class RateLimitModel:
    """Atomic fixed-window counters in the `rate_limits` collection.

    One document per (action, key, window); `$inc` + upsert makes concurrent
    hits safe. Documents expire via the TTL index on `expire_at`.
    """

    def __init__(self, db: AsyncDatabase):
        self.col = db.rate_limits

    @staticmethod
    def _bucket(action: str, key: str, window: timedelta, now: datetime) -> tuple[str, datetime]:
        seconds = int(window.total_seconds())
        start = int(now.timestamp()) // seconds * seconds
        window_end = datetime.fromtimestamp(start + seconds, tz=now.tzinfo)
        return f"{action}:{key}:{start}", window_end

    async def hit(self, action: str, key: str, window: timedelta, now: datetime) -> int:
        count, _ = await self.hit_window(action, key, window, now)
        return count

    async def hit_window(
        self, action: str, key: str, window: timedelta, now: datetime
    ) -> tuple[int, datetime]:
        """Atomically count one attempt; returns (count incl. this one, window end)."""
        bucket_id, window_end = self._bucket(action, key, window, now)
        doc = await self.col.find_one_and_update(
            {"_id": bucket_id},
            {
                "$inc": {"count": 1},
                "$setOnInsert": {"action": action, "key": key, "expire_at": window_end},
            },
            upsert=True,
            return_document=ReturnDocument.AFTER,
        )
        return int(doc["count"]), window_end

    async def peek(self, action: str, key: str, window: timedelta, now: datetime) -> tuple[int, datetime]:
        bucket_id, window_end = self._bucket(action, key, window, now)
        doc = await self.col.find_one({"_id": bucket_id})
        return (int(doc["count"]) if doc else 0), window_end

    async def reset(self, action: str, key: str, window: timedelta, now: datetime) -> None:
        bucket_id, _ = self._bucket(action, key, window, now)
        await self.col.delete_one({"_id": bucket_id})

    async def delete_expired(self, now: datetime) -> int:
        result = await self.col.delete_many({"expire_at": {"$lte": now}})
        return result.deleted_count
