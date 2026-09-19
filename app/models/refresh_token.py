from datetime import datetime
from typing import Optional

from bson import ObjectId
from pymongo.asynchronous.database import AsyncDatabase

from app.db.oids import to_object_id


class RefreshTokenModel:
    """Mongo access for the `refresh_tokens` collection (sessions)."""

    def __init__(self, db: AsyncDatabase):
        self.col = db.refresh_tokens

    async def insert(self, doc: dict) -> dict:
        result = await self.col.insert_one(doc)
        doc["_id"] = result.inserted_id
        return doc

    async def find_by_hash(self, token_hash: str) -> Optional[dict]:
        return await self.col.find_one({"token_hash": token_hash})

    async def find_by_id_and_user(
        self, session_id: str | ObjectId, user_id: str | ObjectId
    ) -> Optional[dict]:
        return await self.col.find_one(
            {"_id": to_object_id(session_id), "user_id": to_object_id(user_id)}
        )

    async def list_active(self, user_id: str | ObjectId, now: datetime) -> list[dict]:
        cursor = self.col.find(
            {"user_id": to_object_id(user_id), "expires_at": {"$gt": now}}
        ).sort("last_seen_at", -1)
        return [doc async for doc in cursor]

    async def delete_by_id(self, session_id: str | ObjectId) -> None:
        await self.col.delete_one({"_id": to_object_id(session_id)})

    async def delete_by_user_and_hash(
        self, user_id: str | ObjectId, token_hash: str
    ) -> None:
        await self.col.delete_one(
            {"user_id": to_object_id(user_id), "token_hash": token_hash}
        )

    async def delete_all_for_user(self, user_id: str | ObjectId) -> int:
        result = await self.col.delete_many({"user_id": to_object_id(user_id)})
        return result.deleted_count

    async def delete_others(self, user_id: str | ObjectId, keep_hash: str) -> int:
        result = await self.col.delete_many(
            {"user_id": to_object_id(user_id), "token_hash": {"$ne": keep_hash}}
        )
        return result.deleted_count

    async def delete_expired(self, now: datetime) -> int:
        result = await self.col.delete_many({"expires_at": {"$lte": now}})
        return result.deleted_count
