from datetime import datetime
from typing import Any, Optional

from bson import ObjectId
from pymongo.asynchronous.database import AsyncDatabase

from app.db.indexes import serialize_user, utcnow
from app.db.oids import id_str, to_object_id


class UserModel:
    """Mongo access for the `users` collection."""

    def __init__(self, db: AsyncDatabase):
        self.col = db.users

    async def find_by_id(self, user_id: str | ObjectId) -> Optional[dict]:
        return await self.col.find_one({"_id": to_object_id(user_id)})

    async def find_by_email(self, email: str) -> Optional[dict]:
        return await self.col.find_one({"email": email.lower().strip()})

    async def find_by_email_except_id(
        self, email: str, user_id: str | ObjectId
    ) -> Optional[dict]:
        return await self.col.find_one(
            {"email": email.lower().strip(), "_id": {"$ne": to_object_id(user_id)}}
        )

    async def insert(self, doc: dict) -> dict:
        result = await self.col.insert_one(doc)
        doc["_id"] = result.inserted_id
        return doc

    async def update_fields(self, user_id: str | ObjectId, fields: dict) -> None:
        fields = {**fields, "updated_at": utcnow()}
        await self.col.update_one(
            {"_id": to_object_id(user_id)}, {"$set": fields}
        )

    async def count(self) -> int:
        return await self.col.count_documents({})

    async def list_page(self, skip: int, limit: int) -> list[dict]:
        cursor = self.col.find({}).sort("created_at", -1).skip(skip).limit(limit)
        return [doc async for doc in cursor]

    @staticmethod
    def serialize(doc: dict, role_name: str | None = None) -> dict[str, Any]:
        return serialize_user(doc, role_name)

    @staticmethod
    def id_str(doc_or_id: Any) -> str:
        return id_str(doc_or_id)
