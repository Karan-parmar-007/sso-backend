"""Mongo access for the OAuth / OIDC provider collections.

- `oauth_codes`: authorization codes (hashed). Valid for ~60 s (`expires_at`),
  single use (`consumed_at`); kept until `purge_at` so a replayed code can
  still be recognised and the grant it produced revoked.
- `oauth_requests`: authorize requests waiting for the user's consent (10 min).
- `oauth_consents`: scopes a user has granted to a third-party client.
"""

from datetime import datetime, timezone
from typing import Optional

from bson import ObjectId
from pymongo import ReturnDocument
from pymongo.asynchronous.database import AsyncDatabase

from app.db.oids import to_object_id


class OAuthCodeModel:
    def __init__(self, db: AsyncDatabase):
        self.col = db.oauth_codes

    async def insert(self, doc: dict) -> dict:
        doc.setdefault("consumed_at", None)
        doc.setdefault("grant_id", None)
        result = await self.col.insert_one(doc)
        doc["_id"] = result.inserted_id
        return doc

    async def consume(
        self, code_hash: str, client_id: str, grant_id: str, now: datetime
    ) -> Optional[dict]:
        """Atomically mark an unused code of this client consumed (single use).

        `grant_id` is stored so a later replay can revoke what this exchange
        issued. None when the code is unknown, used, or bound to another client.
        """
        return await self.col.find_one_and_update(
            {"code_hash": code_hash, "client_id": client_id, "consumed_at": None},
            {"$set": {"consumed_at": now, "grant_id": grant_id}},
            return_document=ReturnDocument.AFTER,
        )

    async def find_by_hash(self, code_hash: str) -> Optional[dict]:
        return await self.col.find_one({"code_hash": code_hash})

    async def mark_replayed(self, code_hash: str) -> None:
        await self.col.update_one(
            {"code_hash": code_hash, "replayed_at": None},
            {"$set": {"replayed_at": datetime.now(timezone.utc)}},
        )

    async def delete_expired(self, now: datetime) -> int:
        result = await self.col.delete_many({"purge_at": {"$lte": now}})
        return result.deleted_count


class OAuthRequestModel:
    """Pending authorize requests; `_id` is the opaque request id."""

    def __init__(self, db: AsyncDatabase):
        self.col = db.oauth_requests

    async def insert(self, doc: dict) -> dict:
        await self.col.insert_one(doc)
        return doc

    async def find_for_user(
        self, request_id: str, user_id: str | ObjectId, now: datetime
    ) -> Optional[dict]:
        return await self.col.find_one(
            {"_id": request_id, "user_id": to_object_id(user_id), "expires_at": {"$gt": now}}
        )

    async def take_for_user(
        self, request_id: str, user_id: str | ObjectId, now: datetime
    ) -> Optional[dict]:
        """Atomically remove and return the request (a decision is final)."""
        return await self.col.find_one_and_delete(
            {"_id": request_id, "user_id": to_object_id(user_id), "expires_at": {"$gt": now}}
        )

    async def delete_expired(self, now: datetime) -> int:
        result = await self.col.delete_many({"expires_at": {"$lte": now}})
        return result.deleted_count


class OAuthConsentModel:
    def __init__(self, db: AsyncDatabase):
        self.col = db.oauth_consents

    async def find(self, user_id: str | ObjectId, client_id: str) -> Optional[dict]:
        return await self.col.find_one(
            {"user_id": to_object_id(user_id), "client_id": client_id}
        )

    async def grant(
        self, user_id: str | ObjectId, client_id: str, scopes: list[str], now: datetime
    ) -> None:
        """Add scopes to the user's consent for this client (never narrows it)."""
        await self.col.update_one(
            {"user_id": to_object_id(user_id), "client_id": client_id},
            {
                "$addToSet": {"scopes": {"$each": scopes}},
                "$set": {"updated_at": now},
                "$setOnInsert": {"created_at": now},
            },
            upsert=True,
        )

    async def delete_for_client(self, client_id: str) -> int:
        result = await self.col.delete_many({"client_id": client_id})
        return result.deleted_count
