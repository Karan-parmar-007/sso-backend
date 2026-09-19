from datetime import timedelta, timezone
from typing import Optional
import logging

from bson import ObjectId
from pymongo.asynchronous.database import AsyncDatabase

from app.config import security_settings
from app.db.indexes import utcnow
from app.db.oids import id_str
from app.models.action_limit import ActionLimitModel
from app.models.refresh_token import RefreshTokenModel
from app.models.role import RoleModel
from app.models.token import (
    EmailChangeTokenModel,
    EmailVerificationTokenModel,
    PasswordResetTokenModel,
)
from app.models.user import UserModel
from app.utils.email import (
    email_change_email,
    email_service,
    password_reset_email,
    verification_email,
)
from app.utils.security import (
    create_access_token,
    create_opaque_token,
    create_refresh_token,
    hash_password,
    hash_token,
    validate_password_strength,
    verify_password,
)

logger = logging.getLogger(__name__)


class RateLimitError(Exception):
    pass


def _aware(dt):
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


class AuthService:
    """API business logic. All Mongo access goes through models."""

    def __init__(self, db: AsyncDatabase):
        self.users = UserModel(db)
        self.roles = RoleModel(db)
        self.sessions = RefreshTokenModel(db)
        self.verify_tokens = EmailVerificationTokenModel(db)
        self.reset_tokens = PasswordResetTokenModel(db)
        self.email_change_tokens = EmailChangeTokenModel(db)
        self.action_limits = ActionLimitModel(db)

    async def get_role_by_name(self, name: str) -> Optional[dict]:
        return await self.roles.find_by_name(name)

    async def get_role_by_id(self, role_id: str | ObjectId) -> Optional[dict]:
        return await self.roles.find_by_id(role_id)

    async def get_user_by_email(self, email: str) -> Optional[dict]:
        return await self.users.find_by_email(email)

    async def get_user_by_id(self, user_id: str | ObjectId) -> Optional[dict]:
        return await self.users.find_by_id(user_id)

    async def user_info(self, user: dict) -> dict:
        role = (
            await self.get_role_by_id(user["role_id"]) if user.get("role_id") else None
        )
        return UserModel.serialize(user, role["name"] if role else None)

    async def _check_action_limit(self, key: str, action: str, max_count: int) -> None:
        now = utcnow()
        doc = await self.action_limits.find(key, action)
        if not doc:
            return
        expire_at = _aware(doc.get("expire_at"))
        if expire_at and expire_at < now:
            return
        if doc.get("count", 0) >= max_count:
            raise RateLimitError(f"Rate limit reached for {action}. Try again later.")

    async def _record_action(self, key: str, action: str) -> None:
        now = utcnow()
        existing = await self.action_limits.find(key, action)
        existing_expire = _aware(existing.get("expire_at")) if existing else None
        if existing and existing_expire and existing_expire > now:
            await self.action_limits.increment(existing["_id"], now)
        else:
            await self.action_limits.start_window(key, action, now)

    def _frontend_link(self, path: str, token: str) -> str:
        base = security_settings.AUTH_FRONTEND_URL.rstrip("/")
        return f"{base}{path}?token={token}"

    async def _access_token_for(self, user: dict) -> str:
        uid = id_str(user)
        claims: dict = {"user_id": uid, "email": user["email"]}
        if user.get("role_id"):
            role = await self.get_role_by_id(user["role_id"])
            if role and role.get("name"):
                claims["role_name"] = str(role["name"]).strip().lower()
        return create_access_token(subject=uid, additional_claims=claims)

    async def signup(self, name: str, email: str, password: str) -> dict:
        email = email.lower().strip()
        validate_password_strength(password)
        if await self.get_user_by_email(email):
            raise ValueError("Email already registered")

        role = await self.get_role_by_name("user")
        if not role:
            raise RuntimeError("Default role 'user' missing — run bootstrap")

        now = utcnow()
        user = await self.users.insert(
            {
                "name": name.strip(),
                "email": email,
                "password_hash": hash_password(password),
                "role_id": role["_id"],
                "email_verified": False,
                "created_at": now,
                "updated_at": now,
            }
        )
        await self.send_verification_email(user)
        return user

    async def login(
        self,
        email: str,
        password: str,
        device_info: str,
        remember_me: bool,
        ip_address: Optional[str] = None,
    ) -> tuple[dict, str, str]:
        user = await self.get_user_by_email(email)
        if not user or not verify_password(password, user["password_hash"]):
            raise ValueError("Invalid email or password")

        access_token = await self._access_token_for(user)
        expires_delta = None if remember_me else timedelta(days=1)
        refresh_plain, token_hash, expires_at = create_refresh_token(expires_delta)
        now = utcnow()
        await self.sessions.insert(
            {
                "user_id": user["_id"],
                "token_hash": token_hash,
                "expires_at": expires_at,
                "device_info": (device_info or "Unknown")[:500],
                "ip_address": (ip_address or "")[:64] or None,
                "created_at": now,
                "last_seen_at": now,
            }
        )
        return user, access_token, refresh_plain

    async def logout(self, user_id: str, refresh_token: Optional[str]) -> None:
        if refresh_token:
            await self.sessions.delete_by_user_and_hash(
                user_id, hash_token(refresh_token)
            )

    async def refresh_tokens(
        self,
        refresh_token: str,
        device_info: str,
        ip_address: Optional[str] = None,
    ) -> tuple[dict, str, str]:
        record = await self.sessions.find_by_hash(hash_token(refresh_token))
        if not record:
            raise ValueError("Invalid refresh token")

        expires_at = _aware(record["expires_at"])
        if expires_at < utcnow():
            await self.sessions.delete_by_id(record["_id"])
            raise ValueError("Refresh token expired")

        user = await self.get_user_by_id(record["user_id"])
        if not user:
            raise ValueError("User not found")

        remaining = expires_at - utcnow()
        if remaining.total_seconds() < 1:
            remaining = timedelta(minutes=1)

        await self.sessions.delete_by_id(record["_id"])
        new_plain, new_hash, new_expires = create_refresh_token(remaining)
        now = utcnow()
        await self.sessions.insert(
            {
                "user_id": user["_id"],
                "token_hash": new_hash,
                "expires_at": new_expires,
                "device_info": (device_info or record.get("device_info") or "Unknown")[
                    :500
                ],
                "ip_address": ip_address or record.get("ip_address"),
                "created_at": record.get("created_at") or now,
                "last_seen_at": now,
            }
        )
        return user, await self._access_token_for(user), new_plain

    async def list_sessions(
        self, user_id: str, current_refresh_token: Optional[str]
    ) -> list[dict]:
        current_hash = (
            hash_token(current_refresh_token) if current_refresh_token else None
        )
        docs = await self.sessions.list_active(user_id, utcnow())
        return [
            {
                "id": id_str(doc["_id"]),
                "device_info": doc.get("device_info"),
                "ip_address": doc.get("ip_address"),
                "created_at": doc.get("created_at"),
                "last_seen_at": doc.get("last_seen_at") or doc.get("created_at"),
                "expires_at": doc.get("expires_at"),
                "is_current": bool(
                    current_hash and doc.get("token_hash") == current_hash
                ),
            }
            for doc in docs
        ]

    async def revoke_session(
        self,
        user_id: str,
        session_id: str,
        current_refresh_token: Optional[str],
    ) -> bool:
        record = await self.sessions.find_by_id_and_user(session_id, user_id)
        if not record:
            raise ValueError("Session not found")
        is_current = bool(
            current_refresh_token
            and record.get("token_hash") == hash_token(current_refresh_token)
        )
        await self.sessions.delete_by_id(session_id)
        return is_current

    async def revoke_other_sessions(
        self, user_id: str, current_refresh_token: Optional[str]
    ) -> int:
        if not current_refresh_token:
            return await self.sessions.delete_all_for_user(user_id)
        return await self.sessions.delete_others(
            user_id, hash_token(current_refresh_token)
        )

    async def send_verification_email(self, user: dict) -> None:
        if user.get("email_verified"):
            raise ValueError("Email already verified")
        email = user["email"]
        await self._check_action_limit(
            email,
            "verify_email_send",
            security_settings.MAX_VERIFY_EMAIL_SENDS_PER_DAY,
        )

        existing = await self.verify_tokens.find_latest_for_user(user["_id"])
        if (
            existing
            and existing.get("resend_count", 1) >= security_settings.MAX_EMAILS_PER_TOKEN
        ):
            raise RateLimitError("Max verification emails for this request reached")

        plain, token_hash = create_opaque_token()
        now = utcnow()
        expires = now + timedelta(hours=security_settings.EMAIL_VERIFICATION_EXPIRY_HOURS)

        if (
            existing
            and existing.get("resend_count", 1) < security_settings.MAX_EMAILS_PER_TOKEN
        ):
            await self.verify_tokens.update_resend(
                existing["_id"],
                {
                    "token_hash": token_hash,
                    "expires_at": expires,
                    "updated_at": now,
                },
            )
        else:
            await self.verify_tokens.delete_for_user(user["_id"])
            await self.verify_tokens.insert(
                {
                    "user_id": user["_id"],
                    "token_hash": token_hash,
                    "expires_at": expires,
                    "created_at": now,
                    "resend_count": 1,
                }
            )

        await self._record_action(email, "verify_email_send")
        link = self._frontend_link("/verify-email", plain)
        subject, plain_body, html = verification_email(link)
        email_service.send(email, subject, plain_body, html)

    async def verify_email(self, token: str) -> dict:
        record = await self.verify_tokens.find_by_hash(hash_token(token))
        if not record:
            raise ValueError("Invalid or expired verification link")
        if _aware(record["expires_at"]) < utcnow():
            await self.verify_tokens.delete_by_id(record["_id"])
            raise ValueError("Verification link expired")

        user = await self.get_user_by_id(record["user_id"])
        if not user:
            raise ValueError("User not found")

        await self.users.update_fields(user["_id"], {"email_verified": True})
        await self.verify_tokens.delete_for_user(user["_id"])
        user["email_verified"] = True
        return user

    async def forgot_password(self, email: str) -> None:
        email = email.lower().strip()
        user = await self.get_user_by_email(email)
        if not user:
            return

        await self._check_action_limit(
            email, "forgot_password", security_settings.MAX_FORGOT_PASSWORD_PER_DAY
        )

        extra = {"used": False}
        existing = await self.reset_tokens.find_latest_for_user(user["_id"], extra=extra)
        if (
            existing
            and existing.get("resend_count", 1) >= security_settings.MAX_EMAILS_PER_TOKEN
        ):
            raise RateLimitError("Max reset emails for this request reached")

        plain, token_hash = create_opaque_token()
        now = utcnow()
        expires = now + timedelta(hours=security_settings.PASSWORD_RESET_EXPIRY_HOURS)

        if (
            existing
            and existing.get("resend_count", 1) < security_settings.MAX_EMAILS_PER_TOKEN
        ):
            await self.reset_tokens.update_resend(
                existing["_id"],
                {
                    "token_hash": token_hash,
                    "expires_at": expires,
                    "updated_at": now,
                },
            )
        else:
            await self.reset_tokens.delete_for_user(user["_id"], extra=extra)
            await self.reset_tokens.insert(
                {
                    "user_id": user["_id"],
                    "token_hash": token_hash,
                    "expires_at": expires,
                    "used": False,
                    "created_at": now,
                    "resend_count": 1,
                }
            )

        await self._record_action(email, "forgot_password")
        link = self._frontend_link("/reset-password", plain)
        subject, plain_body, html = password_reset_email(link)
        email_service.send(email, subject, plain_body, html)

    async def reset_password(
        self, token: str, new_password: str, confirm_password: str
    ) -> None:
        if new_password != confirm_password:
            raise ValueError("Passwords do not match")
        validate_password_strength(new_password)

        record = await self.reset_tokens.find_by_hash(
            hash_token(token), extra={"used": False}
        )
        if not record:
            raise ValueError("Invalid or expired reset link")
        if _aware(record["expires_at"]) < utcnow():
            raise ValueError("Reset link expired")

        user = await self.get_user_by_id(record["user_id"])
        if not user:
            raise ValueError("User not found")

        await self.users.update_fields(
            user["_id"], {"password_hash": hash_password(new_password)}
        )
        await self.reset_tokens.mark_used(record["_id"])
        await self.reset_tokens.delete_for_user(user["_id"], extra={"used": False})
        await self.sessions.delete_all_for_user(user["_id"])

    async def change_password(
        self,
        user_id: str,
        old_password: str,
        new_password: str,
        confirm_password: str,
    ) -> None:
        if new_password != confirm_password:
            raise ValueError("Passwords do not match")
        validate_password_strength(new_password)

        user = await self.get_user_by_id(user_id)
        if not user:
            raise ValueError("User not found")
        if not verify_password(old_password, user["password_hash"]):
            raise ValueError("Current password is incorrect")

        await self._check_action_limit(
            user["email"],
            "change_password",
            security_settings.MAX_CHANGE_PASSWORD_PER_DAY,
        )
        await self.users.update_fields(
            user["_id"], {"password_hash": hash_password(new_password)}
        )
        await self._record_action(user["email"], "change_password")

    async def request_email_change(self, user_id: str, new_email: str) -> None:
        new_email = new_email.lower().strip()
        user = await self.get_user_by_id(user_id)
        if not user:
            raise ValueError("User not found")
        if new_email == user["email"]:
            raise ValueError("New email is the same as current email")
        if await self.get_user_by_email(new_email):
            raise ValueError("Email already in use")

        uid = id_str(user)
        await self._check_action_limit(
            uid, "change_email", security_settings.MAX_EMAIL_CHANGE_PER_DAY
        )

        existing = await self.email_change_tokens.find_latest_for_user(user["_id"])
        if (
            existing
            and existing.get("resend_count", 1) >= security_settings.MAX_EMAILS_PER_TOKEN
        ):
            raise RateLimitError("Max emails for this change request reached")

        plain, token_hash = create_opaque_token()
        now = utcnow()
        expires = now + timedelta(hours=security_settings.EMAIL_CHANGE_EXPIRY_HOURS)

        if (
            existing
            and existing.get("resend_count", 1) < security_settings.MAX_EMAILS_PER_TOKEN
        ):
            await self.email_change_tokens.update_resend(
                existing["_id"],
                {
                    "new_email": new_email,
                    "token_hash": token_hash,
                    "expires_at": expires,
                    "updated_at": now,
                },
            )
        else:
            await self.email_change_tokens.delete_for_user(user["_id"])
            await self.email_change_tokens.insert(
                {
                    "user_id": user["_id"],
                    "new_email": new_email,
                    "token_hash": token_hash,
                    "expires_at": expires,
                    "created_at": now,
                    "resend_count": 1,
                }
            )
            await self._record_action(uid, "change_email")

        link = self._frontend_link("/confirm-email", plain)
        subject, plain_body, html = email_change_email(link, new_email)
        email_service.send(new_email, subject, plain_body, html)

    async def confirm_email_change(self, token: str) -> dict:
        record = await self.email_change_tokens.find_by_hash(hash_token(token))
        if not record:
            raise ValueError("Invalid or expired confirmation link")
        if _aware(record["expires_at"]) < utcnow():
            raise ValueError("Confirmation link expired")

        new_email = record["new_email"].lower().strip()
        if await self.get_user_by_email(new_email):
            raise ValueError("Email already in use")

        await self.users.update_fields(
            record["user_id"],
            {"email": new_email, "email_verified": True},
        )
        await self.email_change_tokens.delete_for_user(record["user_id"])
        user = await self.get_user_by_id(record["user_id"])
        if not user:
            raise ValueError("User not found")
        return user
