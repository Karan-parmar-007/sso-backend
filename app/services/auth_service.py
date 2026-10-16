from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
import logging

from bson import ObjectId
from pymongo.asynchronous.database import AsyncDatabase

from app.config import security_settings
from app.db.indexes import utcnow
from app.db.oids import id_str
from app.models.known_device import KnownDeviceModel
from app.models.rate_limit import RateLimitModel
from app.models.refresh_token import RefreshTokenModel, family_of
from app.models.role import RoleModel
from app.models.token import (
    EmailChangeTokenModel,
    EmailVerificationTokenModel,
    PasswordResetTokenModel,
)
from app.models.user import UserModel
from app.services.audit_service import AuditService
from app.utils.email import (
    email_change_email,
    email_change_requested_notice,
    email_changed_notice,
    email_in_use_notice,
    email_service,
    new_device_email,
    password_changed_email,
    password_reset_email,
    signup_existing_account_email,
    verification_email,
)
from app.utils.request_context import RequestContext, device_fingerprint
from app.utils.security import (
    ACCESS_TOKEN_EXPIRE_SECONDS,
    create_access_token,
    create_opaque_token,
    create_refresh_token,
    burn_password_check,
    decode_access_token,
    hash_password,
    hash_token,
    new_session_id,
    validate_password_strength,
    verify_password,
)

logger = logging.getLogger(__name__)

_DAY = timedelta(days=1)


class RateLimitError(Exception):
    def __init__(self, message: str, retry_after_seconds: Optional[int] = None):
        super().__init__(message)
        self.retry_after_seconds = retry_after_seconds


class EmailNotVerifiedError(Exception):
    pass


class InvalidRefreshTokenError(Exception):
    pass


@dataclass
class IssuedSession:
    """Result of login / refresh: what the route turns into cookies."""

    user: dict
    access_token: str
    refresh_token: str
    session_id: str
    remember_me: bool
    refresh_expires_at: datetime


@dataclass
class ResolvedSession:
    """Result of GET /session."""

    user: Optional[dict]
    session_id: Optional[str]
    issued: Optional[IssuedSession] = None
    clear_cookies: bool = False


def _aware(dt):
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _expires_in(expires_at: datetime) -> int:
    return max(0, int((_aware(expires_at) - utcnow()).total_seconds()))


class AuthService:
    """API business logic. All Mongo access goes through models."""

    def __init__(self, db: AsyncDatabase):
        self.users = UserModel(db)
        self.roles = RoleModel(db)
        self.sessions = RefreshTokenModel(db)
        self.verify_tokens = EmailVerificationTokenModel(db)
        self.reset_tokens = PasswordResetTokenModel(db)
        self.email_change_tokens = EmailChangeTokenModel(db)
        self.limits = RateLimitModel(db)
        self.devices = KnownDeviceModel(db)
        self.audit = AuditService(db)

    # ------------------------------------------------------------------
    # Lookups
    # ------------------------------------------------------------------

    async def get_role_by_name(self, name: str) -> Optional[dict]:
        return await self.roles.find_by_name(name)

    async def get_role_by_id(self, role_id: str | ObjectId) -> Optional[dict]:
        return await self.roles.find_by_id(role_id)

    async def get_user_by_email(self, email: str) -> Optional[dict]:
        return await self.users.find_by_email(email)

    async def get_user_by_id(self, user_id: str | ObjectId) -> Optional[dict]:
        try:
            return await self.users.find_by_id(user_id)
        except ValueError:
            return None

    async def role_name_of(self, user: dict) -> Optional[str]:
        if not user.get("role_id"):
            return None
        role = await self.get_role_by_id(user["role_id"])
        return str(role["name"]).strip().lower() if role and role.get("name") else None

    async def user_info(self, user: dict) -> dict:
        return UserModel.serialize(user, await self.role_name_of(user))

    # ------------------------------------------------------------------
    # Rate limiting
    # ------------------------------------------------------------------

    async def _consume(self, action: str, key: str, limit: int, window: timedelta) -> None:
        count = await self.limits.hit(action, key, window, utcnow())
        if count > limit:
            raise RateLimitError(f"Rate limit reached for {action}. Try again later.")

    async def _attempt(self, action: str, key: str, limit: int, window: timedelta) -> None:
        """Count an attempt *before* doing the work, atomically, so a burst of
        parallel guesses can't all slip past a check-then-increment gap."""
        count, window_end = await self.limits.hit_window(action, key, window, utcnow())
        if count > limit:
            retry = _expires_in(window_end)
            minutes = max(1, (retry + 59) // 60)
            raise RateLimitError(
                f"Too many attempts. Try again in {minutes} minute{'s' if minutes != 1 else ''}.",
                retry_after_seconds=retry,
            )

    @staticmethod
    def _login_window() -> timedelta:
        return timedelta(minutes=security_settings.LOGIN_FAILURE_WINDOW_MINUTES)

    # ------------------------------------------------------------------
    # Tokens & sessions
    # ------------------------------------------------------------------

    async def access_claims(self, user: dict) -> dict[str, Any]:
        uid = id_str(user)
        claims: dict[str, Any] = {
            "user_id": uid,
            "email": user["email"],
            "name": user.get("name"),
            "email_verified": bool(user.get("email_verified")),
            "roles": user.get("app_roles") or {},
        }
        role = await self.role_name_of(user)
        if role:
            claims["role"] = role
            claims["role_name"] = role  # pre-SDK app backends read this name
        return claims

    async def _access_token_for(self, user: dict, session_id: str) -> str:
        return create_access_token(
            subject=id_str(user),
            session_id=session_id,
            additional_claims=await self.access_claims(user),
        )

    async def _start_session(
        self,
        user: dict,
        remember_me: bool,
        ctx: RequestContext,
    ) -> IssuedSession:
        sid = new_session_id()
        lifetime = (
            None
            if remember_me
            else timedelta(hours=security_settings.SHORT_SESSION_HOURS)
        )
        refresh_plain, token_hash, expires_at = create_refresh_token(lifetime)
        now = utcnow()
        await self.sessions.insert(
            {
                "user_id": user["_id"],
                "family_id": sid,
                "token_hash": token_hash,
                "expires_at": expires_at,
                "remember_me": remember_me,
                "device_info": ctx.user_agent,
                "ip_address": ctx.ip,
                "client_id": None,
                "created_at": now,
                "last_seen_at": now,
            }
        )
        return IssuedSession(
            user=user,
            access_token=await self._access_token_for(user, sid),
            refresh_token=refresh_plain,
            session_id=sid,
            remember_me=remember_me,
            refresh_expires_at=expires_at,
        )

    async def session_is_active(self, session_id: Optional[str]) -> bool:
        if not session_id:
            return False
        return await self.sessions.family_is_active(session_id, utcnow())

    async def refresh_tokens(self, refresh_token: str, ctx: RequestContext) -> IssuedSession:
        """Rotate a refresh token.

        - Current token: atomically marked rotated, a successor is issued.
        - Already rotated within the grace window (parallel tabs / sibling
          apps racing on the shared cookie): a sibling successor is issued.
        - Already rotated earlier: the token was replayed — revoke the whole
          session (theft detection).
        """
        now = utcnow()
        record = await self.sessions.find_by_hash(hash_token(refresh_token))
        if not record or record.get("client_id"):
            raise InvalidRefreshTokenError("Invalid refresh token")

        family = family_of(record)
        if _aware(record["expires_at"]) <= now:
            await self.sessions.revoke_family(family)
            raise InvalidRefreshTokenError("Session expired")
        if not record.get("family_id"):
            await self.sessions.set_family(record["_id"], family)

        rotated_at = _aware(record.get("rotated_at"))
        if rotated_at is None:
            claimed = await self.sessions.claim_rotation(record["_id"], now)
            if claimed is None:
                # Lost the race to a parallel refresh; fall into the grace path.
                latest = await self.sessions.find_by_hash(record["token_hash"])
                rotated_at = _aware(latest.get("rotated_at")) if latest else None
                if rotated_at is None:
                    raise InvalidRefreshTokenError("Session revoked")

        if rotated_at is not None:
            age = (now - rotated_at).total_seconds()
            if age > security_settings.REFRESH_REUSE_GRACE_SECONDS:
                await self.sessions.revoke_family(family)
                await self.audit.record(
                    "session.refresh_reuse",
                    user_id=record["user_id"],
                    ctx=ctx,
                    session_id=family,
                    rotated_seconds_ago=int(age),
                )
                raise InvalidRefreshTokenError("Refresh token reuse detected")

        user = await self.get_user_by_id(record["user_id"])
        if not user:
            await self.sessions.revoke_family(family)
            raise InvalidRefreshTokenError("User not found")

        new_plain, new_hash, _ = create_refresh_token()
        remember_me = bool(record.get("remember_me", True))
        await self.sessions.insert(
            {
                "user_id": user["_id"],
                "family_id": family,
                "token_hash": new_hash,
                # Absolute session lifetime is fixed at login.
                "expires_at": record["expires_at"],
                "remember_me": remember_me,
                "device_info": ctx.user_agent or record.get("device_info"),
                "ip_address": ctx.ip or record.get("ip_address"),
                "client_id": None,
                "created_at": record.get("created_at") or now,
                "last_seen_at": now,
            }
        )
        return IssuedSession(
            user=user,
            access_token=await self._access_token_for(user, family),
            refresh_token=new_plain,
            session_id=family,
            remember_me=remember_me,
            refresh_expires_at=_aware(record["expires_at"]),
        )

    async def resolve_session(
        self,
        access_token: Optional[str],
        refresh_token: Optional[str],
        ctx: RequestContext,
    ) -> ResolvedSession:
        """Who is this browser? Refreshes server-side when the access token is
        missing, invalid, revoked or about to expire."""
        payload = decode_access_token(access_token) if access_token else None
        if payload:
            sid = payload.get("sid")
            remaining = int(payload["exp"]) - int(utcnow().timestamp())
            fresh = remaining > security_settings.SESSION_REFRESH_LEEWAY_SECONDS
            if await self.session_is_active(sid):
                if fresh or not refresh_token:
                    user = await self.get_user_by_id(payload.get("user_id") or payload["sub"])
                    if user:
                        return ResolvedSession(user=user, session_id=sid)
            elif not refresh_token:
                return ResolvedSession(user=None, session_id=None, clear_cookies=True)

        if refresh_token:
            try:
                issued = await self.refresh_tokens(refresh_token, ctx)
            except InvalidRefreshTokenError:
                return ResolvedSession(user=None, session_id=None, clear_cookies=True)
            return ResolvedSession(user=issued.user, session_id=issued.session_id, issued=issued)

        return ResolvedSession(user=None, session_id=None, clear_cookies=bool(access_token))

    async def retire_session(self, refresh_token: Optional[str], keep_sid: str) -> None:
        """After a login in a browser that already had a session (re-auth),
        end the old one instead of leaving it orphaned."""
        if not refresh_token:
            return
        record = await self.sessions.find_by_hash(hash_token(refresh_token))
        if record and not record.get("client_id") and family_of(record) != keep_sid:
            await self.sessions.revoke_family(family_of(record))

    async def logout(
        self,
        refresh_token: Optional[str],
        access_payload: Optional[dict],
        ctx: RequestContext,
        everywhere: bool = False,
    ) -> None:
        """Works with an expired access token: the refresh cookie identifies the session."""
        user_id: Any = None
        family: Optional[str] = None
        if refresh_token:
            record = await self.sessions.find_by_hash(hash_token(refresh_token))
            if record:
                user_id, family = record["user_id"], family_of(record)
        if family is None and access_payload:
            user_id = access_payload.get("user_id") or access_payload.get("sub")
            family = access_payload.get("sid")
        if user_id is None:
            return
        if everywhere:
            await self.sessions.delete_all_for_user(user_id)
        elif family:
            await self.sessions.revoke_family(family)
        await self.audit.record(
            "logout", user_id=user_id, ctx=ctx, session_id=family, everywhere=everywhere
        )

    async def list_sessions(self, user_id: str, current_sid: Optional[str]) -> list[dict]:
        docs = await self.sessions.list_active(user_id, utcnow())
        return [
            {
                "id": family_of(doc),
                "device_info": doc.get("device_info"),
                "ip_address": doc.get("ip_address"),
                "created_at": doc.get("created_at"),
                "last_seen_at": doc.get("last_seen_at") or doc.get("created_at"),
                "expires_at": doc.get("expires_at"),
                "is_current": bool(current_sid and family_of(doc) == current_sid),
            }
            for doc in docs
        ]

    async def revoke_session(
        self, user_id: str, session_id: str, current_sid: Optional[str], ctx: RequestContext
    ) -> bool:
        if not await self.sessions.find_session(user_id, session_id):
            raise ValueError("Session not found")
        await self.sessions.revoke_session(user_id, session_id)
        await self.audit.record("session.revoked", user_id=user_id, ctx=ctx, session_id=session_id)
        return session_id == current_sid

    async def revoke_other_sessions(
        self, user_id: str, current_sid: Optional[str], ctx: RequestContext
    ) -> int:
        count = await self.sessions.delete_all_for_user(user_id, keep_family=current_sid)
        await self.audit.record(
            "session.revoked_others", user_id=user_id, ctx=ctx, session_id=current_sid, count=count
        )
        return count

    # ------------------------------------------------------------------
    # Signup / login
    # ------------------------------------------------------------------

    def _frontend_link(self, path: str, token: Optional[str] = None) -> str:
        base = security_settings.AUTH_FRONTEND_URL.rstrip("/")
        return f"{base}{path}?token={token}" if token else f"{base}{path}"

    async def signup(self, name: str, email: str, password: str, ctx: RequestContext) -> None:
        """Same response whether or not the email is registered (no enumeration)."""
        if ctx.ip:
            await self._consume(
                "signup_ip", ctx.ip, security_settings.SIGNUP_MAX_PER_IP_PER_HOUR, timedelta(hours=1)
            )
        email = email.lower().strip()
        validate_password_strength(password)

        existing = await self.get_user_by_email(email)
        if existing:
            burn_password_check(password)  # the new-account path hashes one
            try:
                await self._consume("signup_existing_notice", email, 2, _DAY)
            except RateLimitError:
                return
            subject, plain, html = signup_existing_account_email(
                self._frontend_link("/login"), self._frontend_link("/forgot-password")
            )
            email_service.send_background(email, subject, plain, html)
            await self.audit.record("signup.existing_email", user_id=existing["_id"], email=email, ctx=ctx)
            return

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
                "app_roles": {},
                "email_verified": False,
                "created_at": now,
                "updated_at": now,
            }
        )
        await self.audit.record("signup", user_id=user["_id"], email=email, ctx=ctx)
        try:
            await self.send_verification_email(user)
        except RateLimitError:
            pass

    async def login(
        self,
        email: str,
        password: str,
        remember_me: bool,
        ctx: RequestContext,
    ) -> IssuedSession:
        email = email.lower().strip()
        window = self._login_window()
        # Every attempt counts before the password is checked. The strict
        # limit is per (email, IP) so a stranger can't lock the owner out from
        # elsewhere; a much higher per-account cap still stops distributed
        # guessing. A successful login clears both.
        await self._attempt(
            "login_email_ip",
            f"{email}|{ctx.ip or '-'}",
            security_settings.LOGIN_MAX_FAILURES_PER_EMAIL,
            window,
        )
        await self._attempt(
            "login_account", email, security_settings.LOGIN_MAX_ATTEMPTS_PER_ACCOUNT, window
        )
        if ctx.ip:
            await self._attempt(
                "login_ip", ctx.ip, security_settings.LOGIN_MAX_FAILURES_PER_IP, window
            )

        user = await self.get_user_by_email(email)
        if not verify_password(password, user["password_hash"] if user else None):
            await self.audit.record(
                "login.failure", user_id=user["_id"] if user else None, email=email, ctx=ctx
            )
            raise ValueError("Invalid email or password")

        if security_settings.REQUIRE_EMAIL_VERIFICATION and not user.get("email_verified"):
            await self.audit.record("login.unverified", user_id=user["_id"], email=email, ctx=ctx)
            raise EmailNotVerifiedError("Verify your email before signing in")

        now = utcnow()
        await self.limits.reset("login_email_ip", f"{email}|{ctx.ip or '-'}", window, now)
        await self.limits.reset("login_account", email, window, now)
        issued = await self._start_session(user, remember_me, ctx)
        await self.audit.record(
            "login.success", user_id=user["_id"], email=email, ctx=ctx, session_id=issued.session_id
        )
        await self._new_device_check(user, ctx)
        return issued

    async def _new_device_check(self, user: dict, ctx: RequestContext) -> None:
        try:
            had_devices = await self.devices.count_for_user(user["_id"]) > 0
            is_new = await self.devices.touch(
                user["_id"], device_fingerprint(id_str(user), ctx.user_agent), ctx.device_label, utcnow()
            )
        except Exception:
            logger.exception("Known-device bookkeeping failed")
            return
        if not (is_new and had_devices):
            return
        await self.audit.record("login.new_device", user_id=user["_id"], ctx=ctx, device=ctx.device_label)
        if security_settings.NEW_DEVICE_ALERTS:
            subject, plain, html = new_device_email(
                ctx.device_label,
                ctx.ip or "unknown",
                utcnow().strftime("%Y-%m-%d %H:%M UTC"),
                self._frontend_link("/account"),
            )
            email_service.send_background(user["email"], subject, plain, html)

    # ------------------------------------------------------------------
    # Email verification
    # ------------------------------------------------------------------

    async def send_verification_email(self, user: dict) -> None:
        if user.get("email_verified"):
            raise ValueError("Email already verified")
        email = user["email"]
        await self._consume(
            "verify_email_send", email, security_settings.MAX_VERIFY_EMAIL_SENDS_PER_DAY, _DAY
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

        if existing:
            await self.verify_tokens.update_resend(
                existing["_id"],
                {"token_hash": token_hash, "expires_at": expires, "updated_at": now},
            )
        else:
            await self.verify_tokens.insert(
                {
                    "user_id": user["_id"],
                    "token_hash": token_hash,
                    "expires_at": expires,
                    "created_at": now,
                    "resend_count": 1,
                }
            )

        link = self._frontend_link("/verify-email", plain)
        subject, plain_body, html = verification_email(link)
        email_service.send_background(email, subject, plain_body, html)

    async def resend_verification_by_email(self, email: str) -> None:
        """Public resend (login screen). Silent for unknown/verified/limited emails."""
        user = await self.get_user_by_email(email.lower().strip())
        if not user or user.get("email_verified"):
            return
        try:
            await self.send_verification_email(user)
        except (RateLimitError, ValueError):
            return

    async def verify_email(self, token: str, ctx: RequestContext) -> dict:
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
        await self.audit.record("email.verified", user_id=user["_id"], email=user["email"], ctx=ctx)
        user["email_verified"] = True
        return user

    # ------------------------------------------------------------------
    # Passwords
    # ------------------------------------------------------------------

    async def forgot_password(self, email: str, ctx: RequestContext) -> None:
        """Always succeeds from the caller's point of view (no enumeration)."""
        email = email.lower().strip()
        user = await self.get_user_by_email(email)
        if not user:
            return
        try:
            await self._consume(
                "forgot_password", email, security_settings.MAX_FORGOT_PASSWORD_PER_DAY, _DAY
            )
        except RateLimitError:
            return

        plain = await self.create_password_reset_token(
            user, timedelta(hours=security_settings.PASSWORD_RESET_EXPIRY_HOURS)
        )
        if plain is None:
            return
        link = self._frontend_link("/reset-password", plain)
        subject, plain_body, html = password_reset_email(link)
        email_service.send_background(email, subject, plain_body, html)
        await self.audit.record("password.reset_requested", user_id=user["_id"], email=email, ctx=ctx)

    async def create_password_reset_token(
        self, user: dict, lifetime: timedelta, force: bool = False
    ) -> Optional[str]:
        """New single-use reset token. None when this request was re-sent too
        often — unless `force` (admin reset), which replaces pending tokens."""
        extra = {"used": False}
        if force:
            await self.reset_tokens.delete_for_user(user["_id"], extra=extra)
        existing = await self.reset_tokens.find_latest_for_user(user["_id"], extra=extra)
        if (
            existing
            and existing.get("resend_count", 1) >= security_settings.MAX_EMAILS_PER_TOKEN
        ):
            return None

        plain, token_hash = create_opaque_token()
        now = utcnow()
        if existing:
            await self.reset_tokens.update_resend(
                existing["_id"],
                {"token_hash": token_hash, "expires_at": now + lifetime, "updated_at": now},
            )
        else:
            await self.reset_tokens.insert(
                {
                    "user_id": user["_id"],
                    "token_hash": token_hash,
                    "expires_at": now + lifetime,
                    "used": False,
                    "created_at": now,
                    "resend_count": 1,
                }
            )
        return plain

    async def reset_password(
        self, token: str, new_password: str, confirm_password: str, ctx: RequestContext
    ) -> None:
        if new_password != confirm_password:
            raise ValueError("Passwords do not match")
        validate_password_strength(new_password)

        record = await self.reset_tokens.claim_unused(hash_token(token))
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
        await self.reset_tokens.delete_for_user(user["_id"], extra={"used": False})
        await self.sessions.delete_all_for_user(user["_id"])
        await self.limits.reset("login_account", user["email"], self._login_window(), utcnow())
        await self.audit.record("password.reset", user_id=user["_id"], email=user["email"], ctx=ctx)
        subject, plain, html = password_changed_email(self._frontend_link("/account"))
        email_service.send_background(user["email"], subject, plain, html)

    async def _verify_current_password(self, user: dict, password: str, ctx: RequestContext) -> None:
        """Re-authentication for sensitive changes, with its own lockout."""
        uid = id_str(user)
        window = self._login_window()
        await self._attempt(
            "password_check", uid, security_settings.PASSWORD_CHECK_MAX_FAILURES, window
        )
        if not verify_password(password, user.get("password_hash")):
            await self.audit.record("password.check_failed", user_id=user["_id"], ctx=ctx)
            raise ValueError("Current password is incorrect")
        await self.limits.reset("password_check", uid, window, utcnow())

    async def change_password(
        self,
        user_id: str,
        current_sid: Optional[str],
        old_password: str,
        new_password: str,
        confirm_password: str,
        ctx: RequestContext,
    ) -> int:
        """Returns the number of other sessions signed out."""
        if new_password != confirm_password:
            raise ValueError("Passwords do not match")
        validate_password_strength(new_password)

        user = await self.get_user_by_id(user_id)
        if not user:
            raise ValueError("User not found")
        await self._verify_current_password(user, old_password, ctx)
        await self._consume(
            "change_password", user["email"], security_settings.MAX_CHANGE_PASSWORD_PER_DAY, _DAY
        )

        await self.users.update_fields(
            user["_id"], {"password_hash": hash_password(new_password)}
        )
        revoked = await self.sessions.delete_all_for_user(user["_id"], keep_family=current_sid)
        await self.audit.record(
            "password.changed", user_id=user["_id"], ctx=ctx, session_id=current_sid, revoked=revoked
        )
        subject, plain, html = password_changed_email(self._frontend_link("/account"))
        email_service.send_background(user["email"], subject, plain, html)
        return revoked

    # ------------------------------------------------------------------
    # Email change
    # ------------------------------------------------------------------

    async def request_email_change(
        self, user_id: str, new_email: str, current_password: str, ctx: RequestContext
    ) -> None:
        new_email = new_email.lower().strip()
        user = await self.get_user_by_id(user_id)
        if not user:
            raise ValueError("User not found")
        await self._verify_current_password(user, current_password, ctx)
        if new_email == user["email"]:
            raise ValueError("New email is the same as current email")

        # Limit first, and answer the same way whether or not the address is
        # registered — otherwise this is an unlimited account-existence oracle.
        uid = id_str(user)
        await self._consume("change_email", uid, security_settings.MAX_EMAIL_CHANGE_PER_DAY, _DAY)
        if await self.get_user_by_email(new_email):
            subject, plain_body, html = email_in_use_notice()
            email_service.send_background(new_email, subject, plain_body, html)
            await self.audit.record(
                "email.change_to_existing", user_id=user["_id"], ctx=ctx, new_email=new_email
            )
            return

        plain, token_hash = create_opaque_token()
        now = utcnow()
        await self.email_change_tokens.delete_for_user(user["_id"])
        await self.email_change_tokens.insert(
            {
                "user_id": user["_id"],
                "new_email": new_email,
                "token_hash": token_hash,
                "expires_at": now + timedelta(hours=security_settings.EMAIL_CHANGE_EXPIRY_HOURS),
                "created_at": now,
                "resend_count": 1,
            }
        )

        link = self._frontend_link("/confirm-email", plain)
        subject, plain_body, html = email_change_email(link, new_email)
        email_service.send_background(new_email, subject, plain_body, html)
        subject, plain_body, html = email_change_requested_notice(new_email)
        email_service.send_background(user["email"], subject, plain_body, html)
        await self.audit.record("email.change_requested", user_id=user["_id"], ctx=ctx, new_email=new_email)

    async def confirm_email_change(self, token: str, ctx: RequestContext) -> dict:
        record = await self.email_change_tokens.claim(hash_token(token))
        if not record:
            raise ValueError("Invalid or expired confirmation link")
        if _aware(record["expires_at"]) < utcnow():
            raise ValueError("Confirmation link expired")

        new_email = record["new_email"].lower().strip()
        if await self.get_user_by_email(new_email):
            raise ValueError("Email already in use")

        user = await self.get_user_by_id(record["user_id"])
        if not user:
            raise ValueError("User not found")
        old_email = user["email"]

        await self.users.update_fields(
            record["user_id"], {"email": new_email, "email_verified": True}
        )
        await self.email_change_tokens.delete_for_user(record["user_id"])
        await self.sessions.delete_all_for_user(record["user_id"])
        await self.audit.record(
            "email.changed", user_id=record["user_id"], ctx=ctx, old_email=old_email, new_email=new_email
        )
        subject, plain, html = email_changed_notice(new_email)
        email_service.send_background(old_email, subject, plain, html)

        user.update({"email": new_email, "email_verified": True})
        return user


def access_token_expires_in() -> int:
    return ACCESS_TOKEN_EXPIRE_SECONDS
