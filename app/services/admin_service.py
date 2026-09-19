from math import ceil

from pymongo.asynchronous.database import AsyncDatabase

from app.db.oids import id_str
from app.models.refresh_token import RefreshTokenModel
from app.models.role import RoleModel
from app.models.token import EmailChangeTokenModel, EmailVerificationTokenModel
from app.models.user import UserModel
from app.utils.email import admin_temp_password_email, email_service
from app.utils.security import generate_temp_password, hash_password


class AdminService:
    """Admin business logic. Mongo I/O goes through models."""

    def __init__(self, db: AsyncDatabase):
        self.users = UserModel(db)
        self.roles = RoleModel(db)
        self.sessions = RefreshTokenModel(db)
        self.verify_tokens = EmailVerificationTokenModel(db)
        self.email_change_tokens = EmailChangeTokenModel(db)

    async def list_users(self, page: int = 1, page_size: int = 10) -> dict:
        page = max(1, page)
        page_size = min(max(1, page_size), 100)

        total_count = await self.users.count()
        total_pages = max(1, ceil(total_count / page_size)) if total_count else 1
        if page > total_pages:
            page = total_pages

        skip = (page - 1) * page_size
        role_names = await self.roles.id_name_map()

        users = []
        for doc in await self.users.list_page(skip, page_size):
            role_key = (
                id_str(doc["role_id"]) if doc.get("role_id") is not None else None
            )
            info = UserModel.serialize(
                doc, role_names.get(role_key) if role_key else None
            )
            users.append(
                {
                    "id": info["id"],
                    "name": info["name"],
                    "email": info["email"],
                    "email_verified": info["email_verified"],
                    "role_name": info["role_name"],
                    "created_at": info["created_at"],
                }
            )
        return {
            "total_count": total_count,
            "page": page,
            "page_size": page_size,
            "total_pages": total_pages,
            "users": users,
        }

    async def list_roles(self) -> dict:
        roles = []
        for doc in await self.roles.find_all():
            roles.append(
                {
                    "id": id_str(doc),
                    "name": doc["name"],
                    "created_at": doc.get("created_at"),
                    "updated_at": doc.get("updated_at"),
                }
            )
        return {"total_count": len(roles), "roles": roles}

    async def create_role(self, name: str) -> dict:
        name = name.strip().lower()
        if await self.roles.find_by_name(name):
            raise ValueError("Role already exists")
        doc = await self.roles.insert(name)
        return {
            "id": str(doc["_id"]),
            "name": name,
            "created_at": doc["created_at"],
            "updated_at": doc["updated_at"],
        }

    async def change_role(self, user_id: str, role_name: str) -> dict:
        role = await self.roles.find_by_name(role_name)
        if not role:
            raise ValueError("Role not found")
        user = await self.users.find_by_id(user_id)
        if not user:
            raise ValueError("User not found")

        await self.users.update_fields(user_id, {"role_id": role["_id"]})
        user["role_id"] = role["_id"]
        return UserModel.serialize(user, role["name"])

    async def reset_password(
        self,
        user_id: str,
        send_email: bool = False,
        password: str | None = None,
    ) -> dict:
        from app.utils.security import validate_password_strength

        user = await self.users.find_by_id(user_id)
        if not user:
            raise ValueError("User not found")

        if password:
            validate_password_strength(password)
            new_password = password
        else:
            new_password = generate_temp_password()

        await self.users.update_fields(
            user_id, {"password_hash": hash_password(new_password)}
        )
        await self.sessions.delete_all_for_user(user_id)

        email_sent = False
        if send_email:
            subject, plain, html = admin_temp_password_email(new_password)
            email_sent = email_service.send(user["email"], subject, plain, html)

        return {
            "message": "Password reset successfully",
            "email_sent": email_sent,
            "temporary_password": None if email_sent else new_password,
        }

    async def update_user(
        self,
        user_id: str,
        email: str | None = None,
        email_verified: bool | None = None,
    ) -> dict:
        user = await self.users.find_by_id(user_id)
        if not user:
            raise ValueError("User not found")

        if email is None and email_verified is None:
            raise ValueError("No fields to update")

        updates: dict = {}

        if email is not None:
            new_email = str(email).strip().lower()
            if not new_email:
                raise ValueError("Email is required")
            if new_email != user["email"]:
                conflict = await self.users.find_by_email_except_id(new_email, user_id)
                if conflict:
                    raise ValueError("Email already in use")
                updates["email"] = new_email
                await self.email_change_tokens.delete_for_user(user_id)
                await self.verify_tokens.delete_for_user(user_id)

        if email_verified is not None:
            updates["email_verified"] = bool(email_verified)

        await self.users.update_fields(user_id, updates)
        user.update(updates)

        role = None
        if user.get("role_id") is not None:
            role = await self.roles.find_by_id(user["role_id"])
        return UserModel.serialize(user, role["name"] if role else None)
