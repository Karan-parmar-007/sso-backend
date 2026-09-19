"""Bootstrap roles and owner account from env. Uses Mongo `_id` only."""

import asyncio

from app.config import security_settings
from app.db.indexes import ensure_indexes, utcnow
from app.db.mongo import close_mongo_connection, connect_to_mongo, get_mongo_db
from app.utils.security import hash_password, validate_password_strength


async def seed_roles_and_owner(db) -> None:
    now = utcnow()
    for role_name in ("owner", "user"):
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
            "email_verified": True,
            "created_at": now,
            "updated_at": now,
        }
    )
    print(f"Created owner user: {owner_email}")


async def bootstrap() -> None:
    await connect_to_mongo()
    db = get_mongo_db()
    await ensure_indexes(db)
    await seed_roles_and_owner(db)
    await close_mongo_connection()
    print("Bootstrap complete")


if __name__ == "__main__":
    asyncio.run(bootstrap())
