import secrets
from datetime import timedelta
from math import ceil
from typing import Any, Optional
from urllib.parse import urlsplit

from pymongo.asynchronous.database import AsyncDatabase

from app.config import security_settings
from app.db.oids import id_str
from app.models.client import ClientModel
from app.models.oauth import OAuthConsentModel
from app.models.refresh_token import RefreshTokenModel
from app.models.role import RoleModel
from app.models.token import EmailChangeTokenModel, EmailVerificationTokenModel
from app.models.user import UserModel
from app.services.audit_service import AuditService
from app.services.auth_service import AuthService
from app.utils.email import admin_reset_link_email, email_service
from app.utils.request_context import RequestContext
from app.utils.security import hash_token

OWNER_ROLE = "owner"
SUPPORTED_SCOPES = {"openid", "profile", "email", "offline_access"}


def validate_redirect_uri(uri: str) -> str:
    uri = uri.strip()
    parts = urlsplit(uri)
    if parts.fragment:
        raise ValueError(f"Redirect URI must not contain a fragment: {uri}")
    if parts.scheme == "https" and parts.netloc:
        return uri
    if (
        parts.scheme == "http"
        and parts.hostname in {"localhost", "127.0.0.1"}
        and not security_settings.is_production
    ):
        return uri
    raise ValueError(f"Redirect URI must be absolute https: {uri}")


def serialize_client(doc: dict) -> dict[str, Any]:
    return {
        "client_id": doc["client_id"],
        "name": doc["name"],
        "first_party": bool(doc.get("first_party")),
        "roles": doc.get("roles") or [],
        "redirect_uris": doc.get("redirect_uris") or [],
        "post_logout_redirect_uris": doc.get("post_logout_redirect_uris") or [],
        "allowed_scopes": doc.get("allowed_scopes") or ["openid", "profile", "email"],
        "confidential": bool(doc.get("client_secret_hash")),
        "created_at": doc.get("created_at"),
        "updated_at": doc.get("updated_at"),
    }


class AdminService:
    """Admin business logic. Mongo I/O goes through models."""

    def __init__(self, db: AsyncDatabase):
        self.users = UserModel(db)
        self.roles = RoleModel(db)
        self.sessions = RefreshTokenModel(db)
        self.verify_tokens = EmailVerificationTokenModel(db)
        self.email_change_tokens = EmailChangeTokenModel(db)
        self.clients = ClientModel(db)
        self.consents = OAuthConsentModel(db)
        self.audit = AuditService(db)
        self.auth = AuthService(db)

    async def _serialize_user(self, user: dict) -> dict:
        role = None
        if user.get("role_id") is not None:
            role = await self.roles.find_by_id(user["role_id"])
        return UserModel.serialize(user, role["name"] if role else None)

    # ------------------------------------------------------------------
    # Users
    # ------------------------------------------------------------------

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
                    "app_roles": info["app_roles"],
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

    async def create_role(self, name: str, actor_id: str, ctx: RequestContext) -> dict:
        name = name.strip().lower()
        if await self.roles.find_by_name(name):
            raise ValueError("Role already exists")
        doc = await self.roles.insert(name)
        await self.audit.record("admin.role_created", actor_id=actor_id, ctx=ctx, role=name)
        return {
            "id": str(doc["_id"]),
            "name": name,
            "created_at": doc["created_at"],
            "updated_at": doc["updated_at"],
        }

    async def change_role(
        self, user_id: str, role_name: str, actor_id: str, ctx: RequestContext
    ) -> dict:
        role = await self.roles.find_by_name(role_name)
        if not role:
            raise ValueError("Role not found")
        user = await self.users.find_by_id(user_id)
        if not user:
            raise ValueError("User not found")

        owner_role = await self.roles.find_by_name(OWNER_ROLE)
        if (
            owner_role
            and user.get("role_id") == owner_role["_id"]
            and role["_id"] != owner_role["_id"]
            and await self.users.count_with_role(owner_role["_id"]) <= 1
        ):
            raise ValueError("Cannot remove the last owner")

        await self.users.update_fields(user_id, {"role_id": role["_id"]})
        user["role_id"] = role["_id"]
        await self.audit.record(
            "admin.role_changed", user_id=user_id, actor_id=actor_id, ctx=ctx, role=role["name"]
        )
        return UserModel.serialize(user, role["name"])

    async def set_app_roles(
        self,
        user_id: str,
        client_id: str,
        roles: list[str],
        actor_id: str,
        ctx: RequestContext,
    ) -> dict:
        client = await self.clients.find(client_id)
        if not client:
            raise ValueError("Application not found")
        allowed = set(client.get("roles") or [])
        wanted = sorted({r.strip().lower() for r in roles if r.strip()})
        unknown = [r for r in wanted if r not in allowed]
        if unknown:
            raise ValueError(f"Unknown role(s) for {client_id}: {', '.join(unknown)}")
        user = await self.users.find_by_id(user_id)
        if not user:
            raise ValueError("User not found")

        app_roles = dict(user.get("app_roles") or {})
        if wanted:
            app_roles[client_id] = wanted
        else:
            app_roles.pop(client_id, None)
        await self.users.update_fields(user_id, {"app_roles": app_roles})
        user["app_roles"] = app_roles
        await self.audit.record(
            "admin.app_roles_changed",
            user_id=user_id,
            actor_id=actor_id,
            ctx=ctx,
            client_id=client_id,
            roles=wanted,
        )
        return await self._serialize_user(user)

    async def reset_password(
        self, user_id: str, actor_id: str, ctx: RequestContext
    ) -> dict:
        """Force a reset: the old password stops working, every session ends,
        and the user receives a single-use link. No password is ever shown."""
        user = await self.users.find_by_id(user_id)
        if not user:
            raise ValueError("User not found")

        # Token first: if anything fails, the account is left untouched.
        plain = await self.auth.create_password_reset_token(
            user,
            timedelta(hours=security_settings.ADMIN_PASSWORD_RESET_EXPIRY_HOURS),
            force=True,
        )
        assert plain is not None
        await self.users.update_fields(user_id, {"password_hash": None})
        await self.sessions.delete_all_for_user(user_id)

        link = self.auth._frontend_link("/reset-password", plain)
        subject, plain_body, html = admin_reset_link_email(link)
        email_sent = await email_service.send_async(user["email"], subject, plain_body, html)
        await self.audit.record(
            "admin.password_reset", user_id=user_id, actor_id=actor_id, ctx=ctx, email_sent=email_sent
        )
        return {
            "message": "Password reset; the user was signed out everywhere",
            "email_sent": email_sent,
            # Only when email delivery failed, so the owner can pass it on.
            "reset_link": None if email_sent else link,
        }

    async def update_user(
        self,
        user_id: str,
        actor_id: str,
        ctx: RequestContext,
        email: str | None = None,
        email_verified: bool | None = None,
    ) -> dict:
        user = await self.users.find_by_id(user_id)
        if not user:
            raise ValueError("User not found")

        if email is None and email_verified is None:
            raise ValueError("No fields to update")

        updates: dict = {}
        email_changed = False

        if email is not None:
            new_email = str(email).strip().lower()
            if not new_email:
                raise ValueError("Email is required")
            if new_email != user["email"]:
                conflict = await self.users.find_by_email_except_id(new_email, user_id)
                if conflict:
                    raise ValueError("Email already in use")
                updates["email"] = new_email
                email_changed = True
                await self.email_change_tokens.delete_for_user(user_id)
                await self.verify_tokens.delete_for_user(user_id)

        if email_verified is not None:
            updates["email_verified"] = bool(email_verified)

        await self.users.update_fields(user_id, updates)
        if email_changed:
            await self.sessions.delete_all_for_user(user_id)
        user.update(updates)
        await self.audit.record(
            "admin.user_updated",
            user_id=user_id,
            actor_id=actor_id,
            ctx=ctx,
            fields=sorted(updates),
        )
        return await self._serialize_user(user)

    # ------------------------------------------------------------------
    # Applications / OAuth clients
    # ------------------------------------------------------------------

    async def list_clients(self) -> list[dict]:
        return [serialize_client(c) for c in await self.clients.list_all()]

    @staticmethod
    def _clean_client_fields(fields: dict) -> dict:
        cleaned: dict[str, Any] = {}
        if "name" in fields and fields["name"] is not None:
            cleaned["name"] = fields["name"].strip()
        if "first_party" in fields and fields["first_party"] is not None:
            cleaned["first_party"] = bool(fields["first_party"])
        if "roles" in fields and fields["roles"] is not None:
            cleaned["roles"] = sorted({r.strip().lower() for r in fields["roles"] if r.strip()})
        for key in ("redirect_uris", "post_logout_redirect_uris"):
            if key in fields and fields[key] is not None:
                cleaned[key] = [validate_redirect_uri(u) for u in fields[key]]
        if "allowed_scopes" in fields and fields["allowed_scopes"] is not None:
            scopes = sorted(set(fields["allowed_scopes"]))
            unknown = set(scopes) - SUPPORTED_SCOPES
            if unknown:
                raise ValueError(f"Unsupported scope(s): {', '.join(sorted(unknown))}")
            if "openid" not in scopes:
                raise ValueError("allowed_scopes must include openid")
            cleaned["allowed_scopes"] = scopes
        return cleaned

    async def create_client(
        self, data: dict, actor_id: str, ctx: RequestContext
    ) -> tuple[dict, Optional[str]]:
        client_id = data["client_id"].strip().lower()
        if await self.clients.find(client_id):
            raise ValueError("Application already exists")
        doc = {
            "client_id": client_id,
            "name": client_id,
            "first_party": False,
            "roles": [],
            "redirect_uris": [],
            "post_logout_redirect_uris": [],
            "allowed_scopes": ["openid", "profile", "email"],
            "client_secret_hash": None,
            **self._clean_client_fields(data),
        }
        secret = None
        if data.get("confidential"):
            secret = secrets.token_urlsafe(32)
            doc["client_secret_hash"] = hash_token(secret)
        created = await self.clients.insert(doc)
        await self.audit.record("admin.client_created", actor_id=actor_id, ctx=ctx, client_id=client_id)
        return serialize_client(created), secret

    async def update_client(
        self, client_id: str, data: dict, actor_id: str, ctx: RequestContext
    ) -> dict:
        fields = self._clean_client_fields(data)
        if not fields:
            raise ValueError("No fields to update")
        updated = await self.clients.update(client_id, fields)
        if not updated:
            raise ValueError("Application not found")
        if "roles" in fields:
            await self._prune_app_roles(client_id, set(fields["roles"]))
        await self.audit.record(
            "admin.client_updated", actor_id=actor_id, ctx=ctx, client_id=client_id, fields=sorted(fields)
        )
        return serialize_client(updated)

    async def _prune_app_roles(self, client_id: str, allowed: set[str]) -> None:
        """Drop user grants for roles the application no longer defines."""
        for user in await self.users.list_with_app(client_id):
            kept = [r for r in user["app_roles"][client_id] if r in allowed]
            if kept != user["app_roles"][client_id]:
                app_roles = dict(user["app_roles"])
                if kept:
                    app_roles[client_id] = kept
                else:
                    app_roles.pop(client_id)
                await self.users.update_fields(user["_id"], {"app_roles": app_roles})

    async def rotate_client_secret(
        self, client_id: str, actor_id: str, ctx: RequestContext
    ) -> str:
        secret = secrets.token_urlsafe(32)
        if not await self.clients.update(client_id, {"client_secret_hash": hash_token(secret)}):
            raise ValueError("Application not found")
        await self.audit.record("admin.client_secret_rotated", actor_id=actor_id, ctx=ctx, client_id=client_id)
        return secret

    async def delete_client(self, client_id: str, actor_id: str, ctx: RequestContext) -> None:
        if not await self.clients.delete(client_id):
            raise ValueError("Application not found")
        await self.users.unset_app(client_id)
        # OAuth grants die with the client.
        await self.sessions.delete_for_client(client_id)
        await self.consents.delete_for_client(client_id)
        await self.audit.record("admin.client_deleted", actor_id=actor_id, ctx=ctx, client_id=client_id)
