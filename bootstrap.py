"""Bootstrap roles and owner account from env. Uses Mongo `_id` only."""

import asyncio

from app.config import security_settings
from app.db.indexes import ensure_indexes, utcnow
from app.db.mongo import close_mongo_connection, connect_to_mongo, get_mongo_db
from app.utils.security import hash_password, validate_password_strength


async def seed_roles_and_owner(db) -> None:
    now = utcnow()
    for role_name in ("owner", "super_admin", "user"):
        existing = await db.roles.find_one({"name": role_name})
        if not existing:
            await db.roles.insert_one(
                {
                    "name": role_name,
                    "created_at": now,
                    "updated_at": now,
                }
            )
            print(f"Created role: {role_name}")
        else:
            print(f"Role exists: {role_name}")

    owner_email = (security_settings.OWNER_EMAIL or "").lower().strip()
    owner_password = security_settings.OWNER_PASSWORD
    owner_name = security_settings.OWNER_NAME or "Owner"

    await seed_first_party_clients(db)

    if owner_email:
        # The configured owner must never be locked out by REQUIRE_EMAIL_VERIFICATION.
        await db.users.update_one(
            {"email": owner_email, "email_verified": {"$ne": True}},
            {"$set": {"email_verified": True, "updated_at": now}},
        )

    if not owner_email or not owner_password:
        print("OWNER_EMAIL / OWNER_PASSWORD not set — skipping owner user")
        return

    try:
        validate_password_strength(owner_password)
    except ValueError as e:
        print(f"OWNER_PASSWORD invalid: {e}")
        return

    owner_role = await db.roles.find_one({"name": "owner"})
    existing_user = await db.users.find_one({"email": owner_email})
    if existing_user:
        print(f"Owner user already exists: {owner_email}")
        return

    await db.users.insert_one(
        {
            "name": owner_name,
            "email": owner_email,
            "password_hash": hash_password(owner_password),
            "role_id": owner_role["_id"],
            "app_roles": {},
            "email_verified": True,
            "created_at": now,
            "updated_at": now,
        }
    )
    print(f"Created owner user: {owner_email}")


FIRST_PARTY_CLIENTS = (
    ("portfolio", "Portfolio"),
    ("familyos", "Family OS"),
    ("allprojects", "All Projects"),
    ("studio", "Studio"),
)


async def seed_first_party_clients(db) -> None:
    """Register the first-party apps so per-app roles can be granted."""
    now = utcnow()
    for client_id, name in FIRST_PARTY_CLIENTS:
        await db.clients.update_one(
            {"client_id": client_id},
            {
                "$setOnInsert": {
                    "client_id": client_id,
                    "name": name,
                    "first_party": True,
                    "roles": ["admin"],
                    "redirect_uris": [],
                    "post_logout_redirect_uris": [],
                    "allowed_scopes": ["openid", "profile", "email"],
                    "client_secret_hash": None,
                    "created_at": now,
                    "updated_at": now,
                }
            },
            upsert=True,
        )


async def bootstrap() -> None:
    await connect_to_mongo()
    db = get_mongo_db()
    await ensure_indexes(db)
    await seed_roles_and_owner(db)
    await close_mongo_connection()
    print("Bootstrap complete")


if __name__ == "__main__":
    asyncio.run(bootstrap())
