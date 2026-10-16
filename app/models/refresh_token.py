from datetime import datetime
from typing import Optional

from bson import ObjectId
from pymongo import ReturnDocument
from pymongo.asynchronous.database import AsyncDatabase

from app.db.oids import to_object_id


def family_of(doc: dict) -> str:
    """Session id. Records created before families existed use their own _id."""
    return doc.get("family_id") or str(doc["_id"])


def _session_filter(user_id: str | ObjectId, session_id: str) -> dict:
    clauses: list[dict] = [{"family_id": session_id}]
    if ObjectId.is_valid(session_id):
        clauses.append({"_id": ObjectId(session_id), "family_id": None})
    return {"user_id": to_object_id(user_id), "$or": clauses}


class RefreshTokenModel:
    """Mongo access for the `refresh_tokens` collection.

    One login = one session ("family", `family_id`, exposed as `sid`). Each
    refresh rotates the token: the old record gets `rotated_at` and a new
    record is inserted into the same family. Exactly one record per family
    has `rotated_at: None` (the current token), except inside the reuse grace
    window where concurrent refreshes may briefly add siblings.
    """

    def __init__(self, db: AsyncDatabase):
        self.col = db.refresh_tokens

    async def insert(self, doc: dict) -> dict:
        doc.setdefault("rotated_at", None)
        result = await self.col.insert_one(doc)
        doc["_id"] = result.inserted_id
        return doc

    async def find_by_hash(self, token_hash: str) -> Optional[dict]:
        return await self.col.find_one({"token_hash": token_hash})

    async def claim_rotation(self, record_id: ObjectId, now: datetime) -> Optional[dict]:
        """Atomically mark a current token as rotated. None if someone else won."""
        return await self.col.find_one_and_update(
            {"_id": record_id, "rotated_at": None},
            {"$set": {"rotated_at": now}},
            return_document=ReturnDocument.AFTER,
        )

    async def set_family(self, record_id: ObjectId, family_id: str) -> None:
        await self.col.update_one(
            {"_id": record_id, "family_id": None}, {"$set": {"family_id": family_id}}
        )

    async def family_is_active(self, family_id: str, now: datetime) -> bool:
        doc = await self.col.find_one(
            {
                "$or": [
                    {"family_id": family_id},
                    *(
                        [{"_id": ObjectId(family_id), "family_id": None}]
                        if ObjectId.is_valid(family_id)
                        else []
                    ),
                ],
                "rotated_at": None,
                "expires_at": {"$gt": now},
            },
            projection={"_id": 1},
        )
        return doc is not None

    async def find_session(
        self, user_id: str | ObjectId, session_id: str
    ) -> Optional[dict]:
        return await self.col.find_one(
            {**_session_filter(user_id, session_id), "rotated_at": None}
        )

    async def list_active(self, user_id: str | ObjectId, now: datetime) -> list[dict]:
        """Current token of every live first-party session."""
        cursor = self.col.find(
            {
                "user_id": to_object_id(user_id),
                "rotated_at": None,
                "client_id": None,
                "expires_at": {"$gt": now},
            }
        ).sort("last_seen_at", -1)
        docs = [doc async for doc in cursor]
        seen: set[str] = set()
        unique = []
        for doc in docs:
            fam = family_of(doc)
            if fam not in seen:
                seen.add(fam)
                unique.append(doc)
        return unique

    async def count_for_user(self, user_id: str | ObjectId) -> int:
        return await self.col.count_documents({"user_id": to_object_id(user_id)})

    async def revoke_family(self, family_id: str) -> int:
        clauses: list[dict] = [{"family_id": family_id}]
        if ObjectId.is_valid(family_id):
            clauses.append({"_id": ObjectId(family_id), "family_id": None})
        result = await self.col.delete_many({"$or": clauses})
        return result.deleted_count

    async def revoke_session(self, user_id: str | ObjectId, session_id: str) -> int:
        result = await self.col.delete_many(_session_filter(user_id, session_id))
        return result.deleted_count

    async def delete_all_for_user(
        self, user_id: str | ObjectId, keep_family: Optional[str] = None
    ) -> int:
        query: dict = {"user_id": to_object_id(user_id)}
        if keep_family:
            keep: list[dict] = [{"family_id": keep_family}]
            if ObjectId.is_valid(keep_family):
                keep.append({"_id": ObjectId(keep_family), "family_id": None})
            query["$nor"] = keep
        result = await self.col.delete_many(query)
        return result.deleted_count

    async def delete_for_client(self, client_id: str) -> int:
        """Drop every OAuth refresh token issued to a (deleted) client."""
        result = await self.col.delete_many({"client_id": client_id})
        return result.deleted_count

    async def delete_expired(self, now: datetime) -> int:
        result = await self.col.delete_many({"expires_at": {"$lte": now}})
        return result.deleted_count
