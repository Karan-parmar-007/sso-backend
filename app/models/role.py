from typing import Optional

from bson import ObjectId
from pymongo.asynchronous.database import AsyncDatabase

from app.db.indexes import utcnow
from app.db.oids import id_str, to_object_id


class RoleModel:
    """Mongo access for the `roles` collection."""

    def __init__(self, db: AsyncDatabase):
        self.col = db.roles

    async def find_by_id(self, role_id: str | ObjectId) -> Optional[dict]:
        return await self.col.find_one({"_id": to_object_id(role_id)})

    async def find_by_name(self, name: str) -> Optional[dict]:
        return await self.col.find_one({"name": name.strip().lower()})

    async def find_all(self) -> list[dict]:
        return [doc async for doc in self.col.find({}).sort("name", 1)]

    async def id_name_map(self) -> dict[str, str]:
        return {id_str(r): r["name"] async for r in self.col.find({})}

    async def insert(self, name: str) -> dict:
        now = utcnow()
        doc = {"name": name.strip().lower(), "created_at": now, "updated_at": now}
        result = await self.col.insert_one(doc)
        doc["_id"] = result.inserted_id
        return doc
