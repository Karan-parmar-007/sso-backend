from datetime import datetime, timezone
from typing import Any

from pymongo import ASCENDING, DESCENDING
from pymongo.asynchronous.database import AsyncDatabase

from app.db.oids import id_str


async def ensure_indexes(db: AsyncDatabase) -> None:
    """Create unique + TTL indexes for all SSO collections."""
    await db.roles.create_index([("name", ASCENDING)], unique=True)

    await db.users.create_index([("email", ASCENDING)], unique=True)
    await db.users.create_index([("role_id", ASCENDING)])

    await db.refresh_tokens.create_index([("token_hash", ASCENDING)], unique=True)
    await db.refresh_tokens.create_index([("user_id", ASCENDING)])
    await db.refresh_tokens.create_index(
        [("expires_at", ASCENDING)], expireAfterSeconds=0
    )

    await db.email_verification_tokens.create_index(
        [("token_hash", ASCENDING)], unique=True
    )
    await db.email_verification_tokens.create_index([("user_id", ASCENDING)])
    await db.email_verification_tokens.create_index(
        [("expires_at", ASCENDING)], expireAfterSeconds=0
    )

    await db.password_reset_tokens.create_index(
        [("token_hash", ASCENDING)], unique=True
    )
    await db.password_reset_tokens.create_index([("user_id", ASCENDING)])
    await db.password_reset_tokens.create_index(
        [("expires_at", ASCENDING)], expireAfterSeconds=0
    )

    await db.email_change_tokens.create_index(
        [("token_hash", ASCENDING)], unique=True
    )
    await db.email_change_tokens.create_index([("user_id", ASCENDING)])
    await db.email_change_tokens.create_index(
        [("expires_at", ASCENDING)], expireAfterSeconds=0
    )

    await db.action_limits.create_index(
        [("key", ASCENDING), ("action", ASCENDING)], unique=True
    )
    await db.action_limits.create_index(
        [("expire_at", ASCENDING)], expireAfterSeconds=0
    )

    await db.users.create_index([("created_at", DESCENDING)])
    print("Mongo indexes ensured")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def serialize_user(doc: dict[str, Any], role_name: str | None = None) -> dict[str, Any]:
    """API uses `id` = string of Mongo `_id`. DB has no custom `id` field."""
    role_id = doc.get("role_id")
    return {
        "id": id_str(doc),
        "name": doc["name"],
        "email": doc["email"],
        "email_verified": doc.get("email_verified", False),
        "role_id": id_str(role_id) if role_id is not None else None,
        "role_name": role_name,
        "created_at": doc.get("created_at"),
        "updated_at": doc.get("updated_at"),
    }
