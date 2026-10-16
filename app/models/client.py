from typing import Optional

from pymongo import ReturnDocument
from pymongo.asynchronous.database import AsyncDatabase

from app.db.indexes import utcnow


class ClientModel:
    """Registered applications (`clients`): first-party apps and OAuth/OIDC clients.

    Fields: client_id (slug), name, first_party, roles (app-scoped role names),
    redirect_uris, post_logout_redirect_uris, allowed_scopes,
    client_secret_hash (None = public client, PKCE only), created_at, updated_at.
    """

    def __init__(self, db: AsyncDatabase):
        self.col = db.clients

    async def find(self, client_id: str) -> Optional[dict]:
        return await self.col.find_one({"client_id": client_id})

    async def list_all(self) -> list[dict]:
        return [doc async for doc in self.col.find({}).sort("client_id", 1)]

    async def insert(self, doc: dict) -> dict:
        now = utcnow()
        doc = {**doc, "created_at": now, "updated_at": now}
        result = await self.col.insert_one(doc)
        doc["_id"] = result.inserted_id
        return doc

    async def update(self, client_id: str, fields: dict) -> Optional[dict]:
        return await self.col.find_one_and_update(
            {"client_id": client_id},
            {"$set": {**fields, "updated_at": utcnow()}},
            return_document=ReturnDocument.AFTER,
        )

    async def delete(self, client_id: str) -> bool:
        result = await self.col.delete_one({"client_id": client_id})
        return result.deleted_count == 1
