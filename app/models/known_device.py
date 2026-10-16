from datetime import datetime

from bson import ObjectId
from pymongo.asynchronous.database import AsyncDatabase


class KnownDeviceModel:
    """Browsers a user has signed in from (`known_devices`), for new-device alerts."""

    def __init__(self, db: AsyncDatabase):
        self.col = db.known_devices

    async def touch(self, user_id: ObjectId, fingerprint: str, label: str, now: datetime) -> bool:
        """Record a sign-in. True when this device was not known before."""
        result = await self.col.update_one(
            {"user_id": user_id, "fingerprint": fingerprint},
            {
                "$set": {"last_seen_at": now, "label": label},
                "$setOnInsert": {"first_seen_at": now},
            },
            upsert=True,
        )
        return result.upserted_id is not None

    async def count_for_user(self, user_id: ObjectId) -> int:
        return await self.col.count_documents({"user_id": user_id})

    async def delete_for_user(self, user_id: ObjectId) -> None:
        await self.col.delete_many({"user_id": user_id})
