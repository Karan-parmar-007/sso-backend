"""OAuth 2.0 / OpenID Connect provider: authorization code + PKCE (S256).

Design notes
- Every OAuth grant hangs off the first-party SSO browser session that
  authorized it (`sid` = that session's family id). Ending the session
  (logout, session revocation, password change) therefore ends the grant:
  userinfo rejects its access tokens and its refresh token stops working.
- Refresh tokens live in `refresh_tokens` with `client_id` set and their own
  family (`grant_id`), so first-party /refresh and session listing ignore
  them. Rotation, the reuse grace window and theft detection mirror
  AuthService.refresh_tokens. Their absolute expiry is the parent session's.
- prompt=login / an exceeded max_age end the current SSO session and send
  the user to the login page with `prompt=login`/`max_age` stripped from the
  `next` URL: the login page cannot short-circuit (no cookies left) and the
  return trip cannot loop. The fresh session's `created_at` is `auth_time`.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Optional
from urllib.parse import unquote_plus, urlencode, urlsplit, urlunsplit

import jwt
from pymongo.asynchronous.database import AsyncDatabase

from app.config import security_settings
from app.db.indexes import utcnow
from app.db.oids import id_str
from app.models.client import ClientModel
from app.models.oauth import OAuthCodeModel, OAuthConsentModel, OAuthRequestModel
from app.models.refresh_token import RefreshTokenModel, family_of
from app.services.audit_service import AuditService
from app.services.auth_service import AuthService, IssuedSession
from app.utils.request_context import RequestContext
from app.utils.security import (
    ACCESS_TOKEN_EXPIRE_SECONDS,
    create_opaque_token,
    create_refresh_token,
    decode_access_token,
    decode_jwt,
    hash_token,
    new_session_id,
    sign_jwt,
)

CODE_TTL = timedelta(seconds=60)
# Consumed codes are kept this long so a replay can revoke what they issued.
CODE_PURGE_AFTER = timedelta(minutes=10)
CONSENT_REQUEST_TTL = timedelta(minutes=10)

SUPPORTED_SCOPES = ("openid", "profile", "email", "offline_access")
DEFAULT_CLIENT_SCOPES = ["openid", "profile", "email"]
PROMPT_VALUES = {"none", "login", "consent"}
CLAIMS_SUPPORTED = [
    "sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "sid", "azp",
    "at_hash", "email", "email_verified", "name",
]

_VERIFIER_RE = re.compile(r"^[A-Za-z0-9\-._~]{43,128}$")
_S256_CHALLENGE_RE = re.compile(r"^[A-Za-z0-9\-_]{43}$")
_MAX_PARAM_LENGTH = 2048


class OAuthError(Exception):
    """RFC 6749 error: `error` code + human description + HTTP status."""

    def __init__(self, error: str, description: str, status_code: int = 400):
        super().__init__(description)
        self.error = error
        self.description = description
        self.status_code = status_code

    def body(self) -> dict[str, str]:
        return {"error": self.error, "error_description": self.description}


@dataclass
class AuthorizeResult:
    """What GET /authorize turns into a response.

    `error` = must NOT redirect (unknown client / unregistered redirect_uri).
    Otherwise 302 to `redirect_to`, applying the session cookie changes.
    """

    redirect_to: Optional[str] = None
    error: Optional[OAuthError] = None
    issued: Optional[IssuedSession] = None
    clear_cookies: bool = False


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _aware(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def s256_challenge(verifier: str) -> str:
    return _b64url(hashlib.sha256(verifier.encode("ascii")).digest())


def at_hash(access_token: str) -> str:
    """OIDC at_hash for RS256: left half of SHA-256, base64url."""
    return _b64url(hashlib.sha256(access_token.encode("ascii")).digest()[:16])


def with_query(url: str, params: Mapping[str, Optional[str]]) -> str:
    """Append params to a (possibly already parameterised) URL."""
    parts = urlsplit(url)
    extra = urlencode({k: v for k, v in params.items() if v is not None})
    query = f"{parts.query}&{extra}" if parts.query else extra
    return urlunsplit(parts._replace(query=query))


def parse_basic_auth(header: Optional[str]) -> Optional[tuple[str, str]]:
    """(client_id, client_secret) from `Authorization: Basic`, else None."""
    if not header or not header.lower().startswith("basic "):
        return None
    try:
        raw = base64.b64decode(header[6:].strip(), validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        raise OAuthError("invalid_client", "Malformed Basic credentials", 401)
    client_id, sep, secret = raw.partition(":")
    if not sep:
        raise OAuthError("invalid_client", "Malformed Basic credentials", 401)
    # RFC 6749 §2.3.1: both parts are form-urlencoded before encoding.
    return unquote_plus(client_id), unquote_plus(secret)


def issuer() -> str:
    return security_settings.JWT_ISSUER.rstrip("/")


def _frontend(path: str) -> str:
    return f"{security_settings.AUTH_FRONTEND_URL.rstrip('/')}{path}"


def discovery_document() -> dict[str, Any]:
    iss = issuer()
    return {
        "issuer": iss,
        "authorization_endpoint": f"{iss}/oauth/authorize",
        "token_endpoint": f"{iss}/oauth/token",
        "userinfo_endpoint": f"{iss}/oauth/userinfo",
        "revocation_endpoint": f"{iss}/oauth/revoke",
        "end_session_endpoint": f"{iss}/oauth/logout",
        "jwks_uri": f"{iss}/.well-known/jwks.json",
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic", "client_secret_post", "none",
        ],
        "revocation_endpoint_auth_methods_supported": [
            "client_secret_basic", "client_secret_post", "none",
        ],
        "scopes_supported": list(SUPPORTED_SCOPES),
        "claims_supported": CLAIMS_SUPPORTED,
        "prompt_values_supported": sorted(PROMPT_VALUES),
        "authorization_response_iss_parameter_supported": True,
        "request_parameter_supported": False,
        "request_uri_parameter_supported": False,
    }


def _parse_scope(raw: Optional[str]) -> list[str]:
    return sorted(set((raw or "").split()))


# --------------------------------------------------------------------------
# Service
# --------------------------------------------------------------------------


class OAuthService:
    """OAuth/OIDC business logic. All Mongo access goes through models."""

    def __init__(self, db: AsyncDatabase):
        self.auth = AuthService(db)
        self.clients = ClientModel(db)
        self.codes = OAuthCodeModel(db)
        self.requests = OAuthRequestModel(db)
        self.consents = OAuthConsentModel(db)
        self.sessions = RefreshTokenModel(db)
        self.audit = AuditService(db)

    # ------------------------------------------------------------------
    # Authorization endpoint
    # ------------------------------------------------------------------

    async def authorize(
        self,
        query: list[tuple[str, str]],
        access_token: Optional[str],
        refresh_token: Optional[str],
        ctx: RequestContext,
    ) -> AuthorizeResult:
        params: dict[str, str] = {}
        repeated: set[str] = set()
        for key, value in query:
            if key in params:
                repeated.add(key)
            params[key] = value

        # Until client + redirect_uri are trusted, errors are never redirected.
        client_id = params.get("client_id")
        client = await self.clients.find(client_id) if client_id else None
        if not client or "client_id" in repeated:
            return AuthorizeResult(error=OAuthError("invalid_client", "Unknown client_id"))
        redirect_uri = params.get("redirect_uri")
        if (
            not redirect_uri
            or "redirect_uri" in repeated
            or redirect_uri not in (client.get("redirect_uris") or [])
        ):
            return AuthorizeResult(
                error=OAuthError(
                    "invalid_request", "redirect_uri is missing or not registered for this client"
                )
            )

        state = params.get("state")

        def fail(error: str, description: str) -> AuthorizeResult:
            return AuthorizeResult(
                redirect_to=self._error_redirect(redirect_uri, error, description, state)
            )

        if repeated:
            return fail("invalid_request", f"Repeated parameter(s): {', '.join(sorted(repeated))}")
        if any(len(v) > _MAX_PARAM_LENGTH for v in params.values()):
            return fail("invalid_request", "Parameter too long")
        if params.get("request") or params.get("request_uri"):
            return fail("request_not_supported", "Request objects are not supported")
        if params.get("response_type") != "code":
            return fail("unsupported_response_type", "Only response_type=code is supported")

        scopes = _parse_scope(params.get("scope"))
        if "openid" not in scopes:
            return fail("invalid_scope", "scope must include openid")
        allowed = set(client.get("allowed_scopes") or DEFAULT_CLIENT_SCOPES)
        if not set(scopes) <= allowed:
            extra = ", ".join(sorted(set(scopes) - allowed))
            return fail("invalid_scope", f"Scope(s) not allowed for this client: {extra}")

        challenge = params.get("code_challenge")
        if not challenge:
            return fail("invalid_request", "code_challenge is required (PKCE)")
        if params.get("code_challenge_method") != "S256":
            return fail("invalid_request", "code_challenge_method must be S256")
        if not _S256_CHALLENGE_RE.match(challenge):
            return fail("invalid_request", "Malformed code_challenge")

        prompts = set((params.get("prompt") or "").split())
        if prompts - PROMPT_VALUES:
            return fail("invalid_request", "Unsupported prompt value")
        if "none" in prompts and len(prompts) > 1:
            return fail("invalid_request", "prompt=none cannot be combined with other values")
        max_age: Optional[int] = None
        if params.get("max_age") is not None:
            try:
                max_age = int(params["max_age"])
            except ValueError:
                max_age = -1
            if max_age < 0:
                return fail("invalid_request", "max_age must be a non-negative integer")

        resolved = await self.auth.resolve_session(access_token, refresh_token, ctx)
        result = AuthorizeResult(issued=resolved.issued, clear_cookies=resolved.clear_cookies)
        user, sid = resolved.user, resolved.session_id
        auth_time = await self._auth_time(user, sid) if user and sid else None
        now = utcnow()

        if user is not None:
            too_old = (
                max_age is not None
                and auth_time is not None
                and (now - auth_time).total_seconds() > max_age
            )
            if auth_time is None or "login" in prompts or too_old:
                if "none" in prompts:
                    result.redirect_to = self._error_redirect(
                        redirect_uri, "login_required", "Re-authentication required", state
                    )
                    return result
                # Fresh authentication requested. Don't touch the current
                # session (a cross-site link must not be able to sign anyone
                # out); the login page asks for credentials again and the new
                # login replaces this browser's session.
                await self.audit.record(
                    "oauth.reauth", user_id=user["_id"], ctx=ctx, session_id=sid, client_id=client_id
                )
                result.redirect_to = self._login_redirect(params, force=True)
                return result

        if user is None:
            if "none" in prompts:
                result.redirect_to = self._error_redirect(
                    redirect_uri, "login_required", "The user is not signed in", state
                )
            else:
                result.redirect_to = self._login_redirect(params)
            return result

        if not client.get("first_party"):
            consent = await self.consents.find(user["_id"], client["client_id"])
            covered = bool(consent) and set(scopes) <= set(consent.get("scopes") or [])
            if "consent" in prompts or not covered:
                if "none" in prompts:
                    result.redirect_to = self._error_redirect(
                        redirect_uri, "consent_required", "The user has not approved this client", state
                    )
                    return result
                request_id = secrets.token_urlsafe(24)
                await self.requests.insert(
                    {
                        "_id": request_id,
                        "user_id": user["_id"],
                        "sid": sid,
                        "client_id": client["client_id"],
                        "redirect_uri": redirect_uri,
                        "scopes": scopes,
                        "state": state,
                        "nonce": params.get("nonce"),
                        "code_challenge": challenge,
                        "created_at": now,
                        "expires_at": now + CONSENT_REQUEST_TTL,
                    }
                )
                result.redirect_to = with_query(_frontend("/consent"), {"request": request_id})
                return result

        code = await self._issue_code(
            client["client_id"], redirect_uri, user, sid, scopes,
            params.get("nonce"), challenge, auth_time, ctx,
        )
        result.redirect_to = self._success_redirect(redirect_uri, code, state)
        return result

    async def _auth_time(self, user: dict, sid: str) -> Optional[datetime]:
        """When the user last entered credentials: the session's start."""
        record = await self.sessions.find_session(user["_id"], sid)
        if not record or not record.get("created_at"):
            return None
        return _aware(record["created_at"])

    @staticmethod
    def _login_redirect(params: dict[str, str], force: bool = False) -> str:
        """SSO login page, returning to this authorize request afterwards.

        prompt=login and max_age are dropped from the return URL: the session
        created by that login satisfies them, and keeping them would loop.
        """
        back = dict(params)
        back.pop("max_age", None)
        prompts = set((back.pop("prompt", "") or "").split()) - {"login"}
        if prompts:
            back["prompt"] = " ".join(sorted(prompts))
        next_url = f"{issuer()}/oauth/authorize?{urlencode(back)}"
        # prompt=login tells the login page to ask even if already signed in.
        return with_query(_frontend("/login"), {"next": next_url, "prompt": "login" if force else None})

    @staticmethod
    def _error_redirect(
        redirect_uri: str, error: str, description: str, state: Optional[str]
    ) -> str:
        return with_query(
            redirect_uri,
            {"error": error, "error_description": description, "state": state, "iss": issuer()},
        )

    @staticmethod
    def _success_redirect(redirect_uri: str, code: str, state: Optional[str]) -> str:
        return with_query(redirect_uri, {"code": code, "state": state, "iss": issuer()})

    async def _issue_code(
        self,
        client_id: str,
        redirect_uri: str,
        user: dict,
        sid: str,
        scopes: list[str],
        nonce: Optional[str],
        code_challenge: str,
        auth_time: Optional[datetime],
        ctx: RequestContext,
    ) -> str:
        plain, code_hash = create_opaque_token()
        now = utcnow()
        await self.codes.insert(
            {
                "code_hash": code_hash,
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "user_id": user["_id"],
                "sid": sid,
                "scopes": scopes,
                "nonce": nonce,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
                "auth_time": auth_time or now,
                "created_at": now,
                "expires_at": now + CODE_TTL,
                "purge_at": now + CODE_PURGE_AFTER,
            }
        )
        await self.audit.record(
            "oauth.authorize", user_id=user["_id"], ctx=ctx, session_id=sid,
            client_id=client_id, scopes=scopes,
        )
        return plain

    # ------------------------------------------------------------------
    # Consent (SSO frontend)
    # ------------------------------------------------------------------

    async def consent_details(self, request_id: str, user_id: str) -> dict[str, Any]:
        """Raises LookupError unless the request is pending for this user."""
        req = await self.requests.find_for_user(request_id, user_id, utcnow())
        client = await self.clients.find(req["client_id"]) if req else None
        user = await self.auth.get_user_by_id(user_id) if client else None
        if not req or not client or not user:
            raise LookupError("Consent request not found")
        return {
            "client": {"client_id": client["client_id"], "name": client["name"]},
            "scopes": req["scopes"],
            "user": {"email": user["email"]},
        }

    async def decide_consent(
        self,
        request_id: str,
        user_id: str,
        current_sid: Optional[str],
        approve: bool,
        ctx: RequestContext,
    ) -> str:
        """Returns the URL to send the browser to. LookupError if not pending."""
        now = utcnow()
        req = await self.requests.take_for_user(request_id, user_id, now)
        client = await self.clients.find(req["client_id"]) if req else None
        user = await self.auth.get_user_by_id(user_id) if client else None
        if (
            not req
            or not client
            or not user
            or req["redirect_uri"] not in (client.get("redirect_uris") or [])
        ):
            raise LookupError("Consent request not found")

        await self.audit.record(
            "oauth.consent", user_id=user["_id"], ctx=ctx, session_id=current_sid,
            client_id=client["client_id"], scopes=req["scopes"], approved=approve,
        )
        if not approve:
            return self._error_redirect(
                req["redirect_uri"], "access_denied", "The user denied the request", req.get("state")
            )

        await self.consents.grant(user["_id"], client["client_id"], req["scopes"], now)
        sid = current_sid or req["sid"]
        code = await self._issue_code(
            client["client_id"], req["redirect_uri"], user, sid, req["scopes"],
            req.get("nonce"), req["code_challenge"], await self._auth_time(user, sid), ctx,
        )
        return self._success_redirect(req["redirect_uri"], code, req.get("state"))

    # ------------------------------------------------------------------
    # Client authentication (token / revoke)
    # ------------------------------------------------------------------

    async def authenticate_client(
        self,
        client_id: Optional[str],
        client_secret: Optional[str],
        authorization: Optional[str],
    ) -> dict:
        """Confidential clients: Basic or client_secret_post. Public: client_id only."""
        basic = parse_basic_auth(authorization)
        if basic:
            if client_secret is not None:
                raise OAuthError("invalid_request", "Use only one client authentication method")
            if client_id and client_id != basic[0]:
                raise OAuthError("invalid_request", "client_id does not match the credentials")
            client_id, client_secret = basic
        if not client_id:
            raise OAuthError("invalid_client", "Client authentication failed", 401)
        client = await self.clients.find(client_id)
        if not client:
            raise OAuthError("invalid_client", "Client authentication failed", 401)
        secret_hash = client.get("client_secret_hash")
        if secret_hash:
            if not client_secret or not hmac.compare_digest(hash_token(client_secret), secret_hash):
                raise OAuthError("invalid_client", "Client authentication failed", 401)
        elif client_secret:
            raise OAuthError("invalid_client", "Public clients must not send a client secret", 401)
        return client

    # ------------------------------------------------------------------
    # Token endpoint
    # ------------------------------------------------------------------

    async def token(
        self,
        form: Mapping[str, Optional[str]],
        authorization: Optional[str],
        ctx: RequestContext,
    ) -> dict[str, Any]:
        grant_type = form.get("grant_type")
        if not grant_type:
            raise OAuthError("invalid_request", "grant_type is required")
        client = await self.authenticate_client(
            form.get("client_id"), form.get("client_secret"), authorization
        )
        if grant_type == "authorization_code":
            return await self._exchange_code(client, form, ctx)
        if grant_type == "refresh_token":
            return await self._refresh(client, form, ctx)
        raise OAuthError("unsupported_grant_type", f"Unsupported grant_type: {grant_type}")

    async def _exchange_code(
        self, client: dict, form: Mapping[str, Optional[str]], ctx: RequestContext
    ) -> dict[str, Any]:
        code, redirect_uri = form.get("code"), form.get("redirect_uri")
        verifier = form.get("code_verifier")
        if not code or not redirect_uri or not verifier:
            raise OAuthError("invalid_request", "code, redirect_uri and code_verifier are required")
        if not _VERIFIER_RE.match(verifier):
            raise OAuthError("invalid_request", "Malformed code_verifier")

        now = utcnow()
        grant_id = new_session_id()
        code_hash = hash_token(code)
        record = await self.codes.consume(code_hash, client["client_id"], grant_id, now)
        if record is None:
            await self._handle_code_replay(code_hash, client["client_id"], ctx)
            raise OAuthError("invalid_grant", "Invalid, expired or already used authorization code")
        if _aware(record["expires_at"]) <= now:
            raise OAuthError("invalid_grant", "Authorization code expired")
        if record["redirect_uri"] != redirect_uri:
            raise OAuthError("invalid_grant", "redirect_uri does not match the authorization request")
        if not hmac.compare_digest(s256_challenge(verifier), record["code_challenge"]):
            raise OAuthError("invalid_grant", "PKCE verification failed")

        user = await self.auth.get_user_by_id(record["user_id"])
        sid = record["sid"]
        if not user or not await self.sessions.family_is_active(sid, now):
            raise OAuthError("invalid_grant", "The session that authorized this code has ended")

        scopes = list(record["scopes"])
        auth_time = _aware(record["auth_time"])
        response = self._token_response(
            client["client_id"], user, sid, scopes, auth_time, record.get("nonce")
        )
        if "offline_access" in scopes:
            parent = await self.sessions.find_session(user["_id"], sid)
            if parent:
                response["refresh_token"] = await self._insert_refresh(
                    client["client_id"], user, sid, grant_id, scopes, auth_time,
                    _aware(parent["expires_at"]), now, ctx, created_at=now,
                )
                # A replay that raced this exchange may have revoked before the
                # insert above; re-check so its refresh token can't survive.
                latest = await self.codes.find_by_hash(code_hash)
                if latest and latest.get("replayed_at"):
                    await self.sessions.revoke_family(grant_id)
                    raise OAuthError("invalid_grant", "Authorization code was replayed")
        await self.audit.record(
            "oauth.token", user_id=user["_id"], ctx=ctx, session_id=sid,
            client_id=client["client_id"], scopes=scopes, grant_id=grant_id,
        )
        return response

    async def _handle_code_replay(self, code_hash: str, client_id: str, ctx: RequestContext) -> None:
        """A used code presented again: revoke what its first exchange issued."""
        record = await self.codes.find_by_hash(code_hash)
        if not record or record.get("consumed_at") is None or record["client_id"] != client_id:
            return
        # Flag first, then revoke: an exchange still in flight re-checks the
        # flag after storing its refresh token (see _exchange_code).
        await self.codes.mark_replayed(code_hash)
        if record.get("grant_id"):
            await self.sessions.revoke_family(record["grant_id"])
        await self.audit.record(
            "oauth.code_replay", user_id=record["user_id"], ctx=ctx, session_id=record.get("sid"),
            client_id=client_id, grant_id=record.get("grant_id"),
        )

    async def _refresh(
        self, client: dict, form: Mapping[str, Optional[str]], ctx: RequestContext
    ) -> dict[str, Any]:
        """Rotate an OAuth refresh token (same semantics as session refresh)."""
        token = form.get("refresh_token")
        if not token:
            raise OAuthError("invalid_request", "refresh_token is required")
        now = utcnow()
        record = await self.sessions.find_by_hash(hash_token(token))
        if not record or record.get("client_id") != client["client_id"]:
            raise OAuthError("invalid_grant", "Invalid refresh token")

        family = family_of(record)
        if _aware(record["expires_at"]) <= now:
            await self.sessions.revoke_family(family)
            raise OAuthError("invalid_grant", "Refresh token expired")

        rotated_at = _aware(record.get("rotated_at"))
        if rotated_at is None:
            claimed = await self.sessions.claim_rotation(record["_id"], now)
            if claimed is None:
                latest = await self.sessions.find_by_hash(record["token_hash"])
                rotated_at = _aware(latest.get("rotated_at")) if latest else None
                if rotated_at is None:
                    raise OAuthError("invalid_grant", "Refresh token revoked")
        if rotated_at is not None:
            age = (now - rotated_at).total_seconds()
            if age > security_settings.REFRESH_REUSE_GRACE_SECONDS:
                await self.sessions.revoke_family(family)
                await self.audit.record(
                    "oauth.refresh_reuse", user_id=record["user_id"], ctx=ctx,
                    session_id=record.get("session_id"), client_id=client["client_id"],
                    grant_id=family, rotated_seconds_ago=int(age),
                )
                raise OAuthError("invalid_grant", "Refresh token reuse detected")

        granted = list(record.get("scopes") or [])
        scopes = granted
        if form.get("scope"):
            scopes = _parse_scope(form.get("scope"))
            if not set(scopes) <= set(granted):
                raise OAuthError("invalid_scope", "Requested scope exceeds the original grant")

        sid = record.get("session_id")
        user = await self.auth.get_user_by_id(record["user_id"])
        if not user or not sid or not await self.sessions.family_is_active(sid, now):
            await self.sessions.revoke_family(family)
            raise OAuthError("invalid_grant", "The session behind this grant has ended")

        auth_time = _aware(record.get("auth_time")) or now
        response = self._token_response(client["client_id"], user, sid, scopes, auth_time, None)
        response["refresh_token"] = await self._insert_refresh(
            client["client_id"], user, sid, family, granted, auth_time,
            _aware(record["expires_at"]), now, ctx,
            created_at=_aware(record.get("created_at")) or now,
            previous=record,
        )
        return response

    async def _insert_refresh(
        self,
        client_id: str,
        user: dict,
        sid: str,
        grant_id: str,
        scopes: list[str],
        auth_time: datetime,
        expires_at: datetime,
        now: datetime,
        ctx: RequestContext,
        *,
        created_at: datetime,
        previous: Optional[dict] = None,
    ) -> str:
        plain, token_hash, _ = create_refresh_token()
        await self.sessions.insert(
            {
                "user_id": user["_id"],
                "family_id": grant_id,
                "token_hash": token_hash,
                # Never outlives the SSO session that authorized the grant.
                "expires_at": expires_at,
                "client_id": client_id,
                "session_id": sid,
                "scopes": scopes,
                "auth_time": auth_time,
                "device_info": ctx.user_agent or (previous or {}).get("device_info"),
                "ip_address": ctx.ip or (previous or {}).get("ip_address"),
                "created_at": created_at,
                "last_seen_at": now,
            }
        )
        return plain

    def _token_response(
        self,
        client_id: str,
        user: dict,
        sid: str,
        scopes: list[str],
        auth_time: datetime,
        nonce: Optional[str],
    ) -> dict[str, Any]:
        now = int(utcnow().timestamp())
        exp = now + ACCESS_TOKEN_EXPIRE_SECONDS
        sub = id_str(user)
        scope = " ".join(scopes)
        access = sign_jwt(
            {
                "iss": issuer(),
                "sub": sub,
                "aud": client_id,
                "client_id": client_id,
                "scope": scope,
                "sid": sid,
                "jti": new_session_id(),
                "iat": now,
                "exp": exp,
                "type": "oauth_access",
            },
            force_rs256=True,
        )
        response: dict[str, Any] = {
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": ACCESS_TOKEN_EXPIRE_SECONDS,
            "scope": scope,
        }
        if "openid" in scopes:
            claims: dict[str, Any] = {
                "iss": issuer(),
                "sub": sub,
                "aud": client_id,
                "azp": client_id,
                "iat": now,
                "exp": exp,
                "auth_time": int(auth_time.timestamp()),
                "sid": sid,
                "at_hash": at_hash(access),
                **self._user_claims(user, scopes),
            }
            if nonce:
                claims["nonce"] = nonce
            response["id_token"] = sign_jwt(claims, force_rs256=True)
        return response

    @staticmethod
    def _user_claims(user: dict, scopes: list[str] | set[str]) -> dict[str, Any]:
        claims: dict[str, Any] = {}
        if "email" in scopes:
            claims["email"] = user["email"]
            claims["email_verified"] = bool(user.get("email_verified"))
        if "profile" in scopes:
            claims["name"] = user.get("name")
        return claims

    # ------------------------------------------------------------------
    # Userinfo / revocation / logout
    # ------------------------------------------------------------------

    async def userinfo(self, token: Optional[str]) -> dict[str, Any]:
        """Claims for a valid OAuth access token. OAuthError(invalid_token, 401) otherwise."""
        invalid = OAuthError("invalid_token", "The access token is invalid or expired", 401)
        if not token:
            raise OAuthError("invalid_token", "Missing bearer token", 401)
        try:
            payload = decode_jwt(token, audience=None)
        except jwt.PyJWTError:
            raise invalid
        if payload.get("type") != "oauth_access" or not payload.get("client_id"):
            raise invalid
        if payload.get("aud") != payload["client_id"]:
            raise invalid
        if not await self.clients.find(payload["client_id"]):
            raise invalid
        sid = payload.get("sid")
        if not sid or not await self.sessions.family_is_active(sid, utcnow()):
            raise invalid
        user = await self.auth.get_user_by_id(payload["sub"])
        if not user:
            raise invalid
        scopes = set((payload.get("scope") or "").split())
        return {"sub": id_str(user), **self._user_claims(user, scopes)}

    async def revoke(
        self,
        form: Mapping[str, Optional[str]],
        authorization: Optional[str],
        ctx: RequestContext,
    ) -> None:
        """RFC 7009. Refresh tokens revoke their whole grant. Access tokens are
        short-lived self-contained JWTs and unknown tokens are ignored (200)."""
        client = await self.authenticate_client(
            form.get("client_id"), form.get("client_secret"), authorization
        )
        token = form.get("token")
        if not token:
            raise OAuthError("invalid_request", "token is required")
        record = await self.sessions.find_by_hash(hash_token(token))
        if not record or record.get("client_id") != client["client_id"]:
            return
        family = family_of(record)
        await self.sessions.revoke_family(family)
        await self.audit.record(
            "oauth.revoke", user_id=record["user_id"], ctx=ctx,
            session_id=record.get("session_id"), client_id=client["client_id"], grant_id=family,
        )

    async def end_session(
        self,
        id_token_hint: Optional[str],
        client_id: Optional[str],
        post_logout_redirect_uri: Optional[str],
        state: Optional[str],
        access_token: Optional[str],
        refresh_token: Optional[str],
        ctx: RequestContext,
    ) -> tuple[str, bool]:
        """RP-initiated logout. Returns (redirect URL, whether the session ended).

        The SSO session is ended only when `id_token_hint` is a valid ID token
        for *this browser's* session (matching `sid`); otherwise any site could
        sign users out by linking here. Without a matching hint nothing is
        terminated and the user lands on their account page, where they can
        sign out themselves.
        """
        hint: Optional[dict] = None
        if id_token_hint:
            try:
                payload = decode_jwt(id_token_hint, audience=None, allow_expired=True)
            except jwt.PyJWTError:
                payload = None
            # ID tokens carry no `type`; session/OAuth access tokens do.
            if payload and payload.get("type") is None and isinstance(payload.get("aud"), str):
                hint = payload
        if hint and client_id and hint["aud"] != client_id:
            hint = None
        client = await self.clients.find(hint["aud"]) if hint else None

        access_payload = decode_access_token(access_token) if access_token else None
        current_sid: Optional[str] = None
        if refresh_token:
            record = await self.sessions.find_by_hash(hash_token(refresh_token))
            if record and not record.get("client_id"):
                current_sid = family_of(record)
        if current_sid is None and access_payload:
            current_sid = access_payload.get("sid")

        if hint is None or (current_sid is not None and hint.get("sid") != current_sid):
            await self.audit.record("oauth.logout_ignored", ctx=ctx, client_id=client_id)
            return _frontend("/account" if current_sid else "/login"), False

        if current_sid is not None:
            await self.auth.logout(refresh_token, access_payload, ctx)
        await self.audit.record("oauth.logout", ctx=ctx, client_id=hint["aud"], session_id=current_sid)

        if (
            client
            and post_logout_redirect_uri
            and post_logout_redirect_uri in (client.get("post_logout_redirect_uris") or [])
        ):
            return with_query(post_logout_redirect_uri, {"state": state}), True
        return _frontend("/login"), True
