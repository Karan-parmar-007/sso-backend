from datetime import datetime
from typing import Optional

from bson import ObjectId
from pymongo.asynchronous.database import AsyncDatabase

from app.db.oids import to_object_id


class _TokenCollection:
    def __init__(self, db: AsyncDatabase, name: str):
        self.col = db[name]

    async def find_by_hash(self, token_hash: str, extra: dict | None = None) -> Optional[dict]:
        query = {"token_hash": token_hash, **(extra or {})}
        return await self.col.find_one(query)

    async def find_latest_for_user(
        self, user_id: str | ObjectId, extra: dict | None = None
    ) -> Optional[dict]:
        query = {"user_id": to_object_id(user_id), **(extra or {})}
        return await self.col.find_one(query, sort=[("created_at", -1)])

    async def insert(self, doc: dict) -> dict:
        result = await self.col.insert_one(doc)
        doc["_id"] = result.inserted_id
        return doc

    async def update_resend(self, doc_id: ObjectId, fields: dict) -> None:
        await self.col.update_one(
            {"_id": doc_id},
            {"$set": fields, "$inc": {"resend_count": 1}},
        )

    async def delete_for_user(
        self, user_id: str | ObjectId, extra: dict | None = None
    ) -> None:
        query = {"user_id": to_object_id(user_id), **(extra or {})}
        await self.col.delete_many(query)

    async def delete_by_id(self, doc_id: ObjectId) -> None:
        await self.col.delete_one({"_id": doc_id})

    async def delete_expired(self, now: datetime) -> int:
        result = await self.col.delete_many({"expires_at": {"$lte": now}})
        return result.deleted_count


class EmailVerificationTokenModel(_TokenCollection):
    def __init__(self, db: AsyncDatabase):
        super().__init__(db, "email_verification_tokens")


class PasswordResetTokenModel(_TokenCollection):
    def __init__(self, db: AsyncDatabase):
        super().__init__(db, "password_reset_tokens")

    async def mark_used(self, doc_id: ObjectId) -> None:
        await self.col.update_one({"_id": doc_id}, {"$set": {"used": True}})

    async def delete_used(self) -> int:
        result = await self.col.delete_many({"used": True})
        return result.deleted_count


class EmailChangeTokenModel(_TokenCollection):
    def __init__(self, db: AsyncDatabase):
        super().__init__(db, "email_change_tokens")
