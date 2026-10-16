"""OAuth 2.0 / OpenID Connect provider: authorization code + PKCE."""

import base64
import hashlib
import secrets
import sys
from contextlib import asynccontextmanager
from datetime import timedelta
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
import pytest

from app.config import security_settings
from app.db.indexes import utcnow
from main import app
from tests.conftest import csrf_headers, login, make_client
from tests.test_admin import owner_client

ISSUER = "http://testserver/api/auth"
NOTES_CB = "https://notes.example.com/callback"
NOTES_BYE = "https://notes.example.com/bye"
CRM_CB = "https://crm.example.com/cb"
OAUTH = "/api/auth/oauth"


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def query_of(url: str) -> dict[str, str]:
    return {k: v[0] for k, v in parse_qs(urlsplit(url).query).items()}


def basic(client_id: str, secret: str) -> dict:
    raw = base64.b64encode(f"{client_id}:{secret}".encode()).decode()
    return {"Authorization": f"Basic {raw}"}


async def authorize(c: httpx.AsyncClient, client_id: str, redirect_uri: str, challenge: str, **extra):
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": "openid profile email",
        "state": "st-123",
        "nonce": "nonce-abc",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        **extra,
    }
    return await c.get(f"{OAUTH}/authorize", params={k: v for k, v in params.items() if v is not None})


async def exchange(rp: httpx.AsyncClient, code: str, verifier: str, client_id="notes",
                   redirect_uri=NOTES_CB, headers=None, **extra):
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "code_verifier": verifier,
        **({"client_id": client_id} if client_id else {}),
        **extra,
    }
    return await rp.post(f"{OAUTH}/token", data=data, headers=headers or {})


@pytest.fixture
async def oauth_clients(db, outbox):
    """`notes`: third-party public client. `crm`: first-party confidential client."""
    async with owner_client() as c:
        res = await c.post(
            "/api/auth/admin/clients",
            json={
                "client_id": "notes",
                "name": "Notes",
                "redirect_uris": [NOTES_CB],
                "post_logout_redirect_uris": [NOTES_BYE],
                "allowed_scopes": ["openid", "profile", "email", "offline_access"],
            },
            headers=csrf_headers(c),
        )
        assert res.status_code == 201, res.text
        assert res.json()["confidential"] is False
        res = await c.post(
            "/api/auth/admin/clients",
            json={
                "client_id": "crm",
                "name": "CRM",
                "first_party": True,
                "confidential": True,
                "redirect_uris": [CRM_CB],
                "allowed_scopes": ["openid", "email", "offline_access"],
            },
            headers=csrf_headers(c),
        )
        assert res.status_code == 201, res.text
        return {"crm_secret": res.json()["client_secret"]}


@asynccontextmanager
async def signed_in_browser(make_user, email="user@example.com"):
    await make_user(email=email)
    async with make_client() as browser:
        assert (await login(browser, email=email)).status_code == 200
        yield browser


async def approved_code(browser, challenge, scope="openid profile email", **extra) -> str:
    """Run the third-party (`notes`) authorize + consent and return the code."""
    res = await authorize(browser, "notes", NOTES_CB, challenge, scope=scope, **extra)
    assert res.status_code == 302, res.text
    location = res.headers["location"]
    if location.startswith(NOTES_CB):
        return query_of(location)["code"]
    assert location.startswith("http://auth.test/consent?request=")
    request_id = query_of(location)["request"]
    res = await browser.post(
        f"{OAUTH}/consent/{request_id}", json={"approve": True}, headers=csrf_headers(browser)
    )
    assert res.status_code == 200, res.text
    return query_of(res.json()["redirect_to"])["code"]


async def crm_code(browser, challenge, scope="openid email offline_access") -> str:
    res = await authorize(browser, "crm", CRM_CB, challenge, scope=scope)
    assert res.status_code == 302, res.text
    return query_of(res.headers["location"])["code"]


async def verify_id_token(client: httpx.AsyncClient, id_token: str, audience: str) -> dict:
    keys = jwt.PyJWKSet.from_dict((await client.get("/api/auth/.well-known/jwks.json")).json())
    kid = jwt.get_unverified_header(id_token)["kid"]
    key = next(k for k in keys.keys if k.key_id == kid)
    return jwt.decode(id_token, key.key, algorithms=["RS256"], audience=audience, issuer=ISSUER)


def expected_at_hash(access_token: str) -> str:
    digest = hashlib.sha256(access_token.encode()).digest()[:16]
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


# --------------------------------------------------------------------------
# Discovery
# --------------------------------------------------------------------------


async def test_discovery_document(client):
    res = await client.get("/api/auth/.well-known/openid-configuration")
    assert res.status_code == 200
    doc = res.json()
    assert doc["issuer"] == ISSUER
    assert doc["authorization_endpoint"] == f"{ISSUER}/oauth/authorize"
    assert doc["token_endpoint"] == f"{ISSUER}/oauth/token"
    assert doc["userinfo_endpoint"] == f"{ISSUER}/oauth/userinfo"
    assert doc["revocation_endpoint"] == f"{ISSUER}/oauth/revoke"
    assert doc["end_session_endpoint"] == f"{ISSUER}/oauth/logout"
    assert doc["jwks_uri"] == f"{ISSUER}/.well-known/jwks.json"
    assert doc["response_types_supported"] == ["code"]
    assert doc["code_challenge_methods_supported"] == ["S256"]
    assert doc["id_token_signing_alg_values_supported"] == ["RS256"]
    assert set(doc["grant_types_supported"]) == {"authorization_code", "refresh_token"}
    assert set(doc["token_endpoint_auth_methods_supported"]) == {
        "client_secret_basic", "client_secret_post", "none",
    }
    assert set(doc["scopes_supported"]) == {"openid", "profile", "email", "offline_access"}
    assert doc["subject_types_supported"] == ["public"]
    assert {"sub", "email", "nonce", "at_hash"} <= set(doc["claims_supported"])


# --------------------------------------------------------------------------
# Public third-party client: consent + code + PKCE
# --------------------------------------------------------------------------


async def test_public_client_full_flow_with_consent(db, make_user, oauth_clients):
    verifier, challenge = pkce()
    async with signed_in_browser(make_user) as browser, make_client() as rp:
        res = await authorize(browser, "notes", NOTES_CB, challenge)
        assert res.status_code == 302
        location = res.headers["location"]
        assert location.startswith("http://auth.test/consent?request=")
        request_id = query_of(location)["request"]

        details = await browser.get(f"{OAUTH}/consent/{request_id}")
        assert details.status_code == 200
        assert details.json() == {
            "client": {"client_id": "notes", "name": "Notes"},
            "scopes": ["email", "openid", "profile"],
            "user": {"email": "user@example.com"},
        }
        # Consent POST is cookie-authenticated → CSRF required.
        assert (await browser.post(f"{OAUTH}/consent/{request_id}", json={"approve": True})).status_code == 403

        res = await browser.post(
            f"{OAUTH}/consent/{request_id}", json={"approve": True}, headers=csrf_headers(browser)
        )
        assert res.status_code == 200
        redirect = res.json()["redirect_to"]
        assert redirect.startswith(NOTES_CB + "?")
        params = query_of(redirect)
        assert params["state"] == "st-123" and params["iss"] == ISSUER

        res = await exchange(rp, params["code"], verifier)
        assert res.status_code == 200, res.text
        assert res.headers["cache-control"] == "no-store" and res.headers["pragma"] == "no-cache"
        body = res.json()
        assert body["token_type"] == "Bearer" and body["expires_in"] == 900
        assert body["scope"] == "email openid profile"
        assert "refresh_token" not in body  # no offline_access

        user = await db.users.find_one({"email": "user@example.com"})
        claims = await verify_id_token(rp, body["id_token"], "notes")
        assert claims["sub"] == str(user["_id"])
        assert claims["nonce"] == "nonce-abc"
        assert claims["azp"] == "notes"
        assert claims["at_hash"] == expected_at_hash(body["access_token"])
        assert claims["email"] == "user@example.com" and claims["email_verified"] is True
        assert claims["name"] == "User"
        assert claims["sid"] == jwt.decode(browser.cookies.get("access_token"), options={"verify_signature": False})["sid"]
        assert isinstance(claims["auth_time"], int)

        access = jwt.decode(body["access_token"], options={"verify_signature": False})
        assert access["aud"] == "notes" and access["client_id"] == "notes"
        assert access["type"] == "oauth_access" and access["iss"] == ISSUER

        # Consent remembered: second authorize returns a code straight away.
        _, challenge2 = pkce()
        res = await authorize(browser, "notes", NOTES_CB, challenge2)
        assert res.headers["location"].startswith(NOTES_CB + "?code=")
        # ...but prompt=consent asks again.
        res = await authorize(browser, "notes", NOTES_CB, challenge2, prompt="consent")
        assert res.headers["location"].startswith("http://auth.test/consent?request=")
        # Wider scope than consented → consent again.
        res = await authorize(browser, "notes", NOTES_CB, challenge2, scope="openid email offline_access")
        assert res.headers["location"].startswith("http://auth.test/consent?request=")


async def test_consent_deny_prompt_none_and_ownership(db, make_user, oauth_clients):
    _, challenge = pkce()
    async with signed_in_browser(make_user) as browser:
        res = await authorize(browser, "notes", NOTES_CB, challenge, prompt="none")
        params = query_of(res.headers["location"])
        assert res.headers["location"].startswith(NOTES_CB)
        assert params["error"] == "consent_required" and params["state"] == "st-123"

        res = await authorize(browser, "notes", NOTES_CB, challenge)
        request_id = query_of(res.headers["location"])["request"]

        async with signed_in_browser(make_user, email="other@example.com") as other:
            assert (await other.get(f"{OAUTH}/consent/{request_id}")).status_code == 404
            res = await other.post(
                f"{OAUTH}/consent/{request_id}", json={"approve": True}, headers=csrf_headers(other)
            )
            assert res.status_code == 404

        res = await browser.post(
            f"{OAUTH}/consent/{request_id}", json={"approve": False}, headers=csrf_headers(browser)
        )
        assert res.status_code == 200
        params = query_of(res.json()["redirect_to"])
        assert params["error"] == "access_denied" and params["state"] == "st-123"
        assert "code" not in params
        # A decision is final.
        assert (await browser.get(f"{OAUTH}/consent/{request_id}")).status_code == 404
        assert await db.oauth_consents.count_documents({}) == 0


# --------------------------------------------------------------------------
# Confidential first-party client
# --------------------------------------------------------------------------


async def test_confidential_client_authentication(db, make_user, oauth_clients):
    secret = oauth_clients["crm_secret"]
    async with signed_in_browser(make_user) as browser, make_client() as rp:
        verifier, challenge = pkce()
        code = await crm_code(browser, challenge)  # first-party: no consent screen

        # No secret / wrong secret → invalid_client 401 (code stays usable).
        res = await exchange(rp, code, verifier, client_id="crm", redirect_uri=CRM_CB)
        assert res.status_code == 401 and res.json()["error"] == "invalid_client"
        assert "WWW-Authenticate" in res.headers
        res = await exchange(rp, code, verifier, client_id=None, redirect_uri=CRM_CB,
                             headers=basic("crm", "wrong"))
        assert res.status_code == 401
        # Two methods at once → invalid_request.
        res = await exchange(rp, code, verifier, client_id=None, redirect_uri=CRM_CB,
                             headers=basic("crm", secret), client_secret=secret)
        assert res.status_code == 400 and res.json()["error"] == "invalid_request"

        res = await exchange(rp, code, verifier, client_id=None, redirect_uri=CRM_CB,
                             headers=basic("crm", secret))
        assert res.status_code == 200, res.text
        body = res.json()
        assert body["refresh_token"]
        claims = await verify_id_token(rp, body["id_token"], "crm")
        assert "name" not in claims and claims["email"] == "user@example.com"

        # client_secret_post works too.
        verifier, challenge = pkce()
        code = await crm_code(browser, challenge)
        res = await exchange(rp, code, verifier, client_id="crm", redirect_uri=CRM_CB, client_secret=secret)
        assert res.status_code == 200, res.text

        # Public client sending a secret is rejected.
        verifier, challenge = pkce()
        code = await approved_code(browser, challenge)
        res = await exchange(rp, code, verifier, client_secret="nope")
        assert res.status_code == 401


# --------------------------------------------------------------------------
# Authorization request / code validation
# --------------------------------------------------------------------------


async def test_unregistered_redirect_uri_and_unknown_client_never_redirect(db, make_user, oauth_clients):
    _, challenge = pkce()
    async with signed_in_browser(make_user) as browser:
        res = await authorize(browser, "notes", "https://evil.example.com/cb", challenge)
        assert res.status_code == 400 and "location" not in res.headers
        assert res.json()["error"] == "invalid_request"
        res = await authorize(browser, "notes", NOTES_CB + "/extra", challenge)
        assert res.status_code == 400
        res = await authorize(browser, "nope", NOTES_CB, challenge)
        assert res.status_code == 400 and res.json()["error"] == "invalid_client"
        res = await authorize(browser, "notes", None, challenge)
        assert res.status_code == 400


async def test_authorize_request_validation_redirects_errors(db, make_user, oauth_clients):
    _, challenge = pkce()
    async with signed_in_browser(make_user) as browser:
        cases = [
            ({"code_challenge": None}, "invalid_request"),
            ({"code_challenge_method": "plain"}, "invalid_request"),
            ({"code_challenge_method": None}, "invalid_request"),
            ({"response_type": "token"}, "unsupported_response_type"),
            ({"scope": "profile email"}, "invalid_scope"),
            ({"scope": "openid admin"}, "invalid_scope"),
            ({"prompt": "none login"}, "invalid_request"),
        ]
        for extra, error in cases:
            res = await authorize(browser, "notes", NOTES_CB, challenge, **extra)
            assert res.status_code == 302, (extra, res.text)
            params = query_of(res.headers["location"])
            assert res.headers["location"].startswith(NOTES_CB)
            assert params["error"] == error, (extra, params)
            assert params["state"] == "st-123"
        # crm is not allowed profile.
        res = await authorize(browser, "crm", CRM_CB, challenge, scope="openid profile")
        assert query_of(res.headers["location"])["error"] == "invalid_scope"


async def test_code_exchange_rejections(db, make_user, oauth_clients):
    async with signed_in_browser(make_user) as browser, make_client() as rp:
        verifier, challenge = pkce()
        code = await approved_code(browser, challenge)
        # Another client cannot redeem it (and doesn't burn it).
        res = await exchange(rp, code, verifier, client_id="crm", redirect_uri=NOTES_CB,
                             client_secret=oauth_clients["crm_secret"])
        assert res.status_code == 400 and res.json()["error"] == "invalid_grant"
        # Malformed verifier.
        res = await exchange(rp, code, "short")
        assert res.status_code == 400 and res.json()["error"] == "invalid_request"
        # Wrong verifier → invalid_grant, code burned.
        res = await exchange(rp, code, pkce()[0])
        assert res.status_code == 400 and res.json()["error"] == "invalid_grant"
        assert (await exchange(rp, code, verifier)).status_code == 400

        verifier, challenge = pkce()
        code = await approved_code(browser, challenge)
        res = await exchange(rp, code, verifier, redirect_uri="https://notes.example.com/other")
        assert res.status_code == 400 and res.json()["error"] == "invalid_grant"

        verifier, challenge = pkce()
        code = await approved_code(browser, challenge)
        await db.oauth_codes.update_many({}, {"$set": {"expires_at": utcnow() - timedelta(seconds=1)}})
        res = await exchange(rp, code, verifier)
        assert res.status_code == 400 and "expired" in res.json()["error_description"]

        res = await exchange(rp, "garbage", verifier)
        assert res.status_code == 400 and res.json()["error"] == "invalid_grant"
        res = await rp.post(f"{OAUTH}/token", data={"grant_type": "password", "client_id": "notes"})
        assert res.json()["error"] == "unsupported_grant_type"
        res = await rp.post(f"{OAUTH}/token", data={"client_id": "notes"})
        assert res.json()["error"] == "invalid_request"


async def test_code_single_use_and_replay_revokes_grant(db, make_user, oauth_clients):
    async with signed_in_browser(make_user) as browser, make_client() as rp:
        verifier, challenge = pkce()
        code = await approved_code(browser, challenge, scope="openid offline_access")
        first = await exchange(rp, code, verifier)
        assert first.status_code == 200, first.text
        refresh = first.json()["refresh_token"]

        replay = await exchange(rp, code, verifier)
        assert replay.status_code == 400 and replay.json()["error"] == "invalid_grant"
        # The refresh token issued from the replayed code is dead.
        res = await rp.post(f"{OAUTH}/token", data={
            "grant_type": "refresh_token", "refresh_token": refresh, "client_id": "notes",
        })
        assert res.status_code == 400 and res.json()["error"] == "invalid_grant"
        assert await db.audit_events.count_documents({"event": "oauth.code_replay"}) == 1
        # The SSO browser session itself is untouched.
        assert (await browser.get("/api/auth/me")).status_code == 200


# --------------------------------------------------------------------------
# Login / prompt handling
# --------------------------------------------------------------------------


async def test_not_signed_in_redirects_to_login_or_login_required(db, oauth_clients):
    _, challenge = pkce()
    async with make_client() as anon:
        res = await authorize(anon, "notes", NOTES_CB, challenge)
        assert res.status_code == 302
        location = res.headers["location"]
        assert location.startswith("http://auth.test/login?next=")
        next_url = query_of(location)["next"]
        assert next_url.startswith(f"{ISSUER}/oauth/authorize?")
        assert query_of(next_url)["code_challenge"] == challenge
        assert query_of(next_url)["state"] == "st-123"

        res = await authorize(anon, "notes", NOTES_CB, challenge, prompt="none")
        params = query_of(res.headers["location"])
        assert res.headers["location"].startswith(NOTES_CB)
        assert params["error"] == "login_required" and params["state"] == "st-123"


async def test_prompt_login_and_max_age_force_reauthentication(db, make_user, oauth_clients):
    _, challenge = pkce()
    async with signed_in_browser(make_user) as browser:
        res = await authorize(browser, "crm", CRM_CB, challenge, scope="openid", prompt="login")
        location = res.headers["location"]
        assert location.startswith("http://auth.test/login?next=")
        assert "prompt" not in query_of(query_of(location)["next"])  # no loop
        assert query_of(location)["prompt"] == "login"  # login page must ask
        # A cross-site link can't sign anyone out: the session is untouched...
        assert "set-cookie" not in res.headers
        old_sid = (await browser.get("/api/auth/session")).json()["session_id"]

        # ...until the user actually logs in again, which replaces it.
        assert (await login(browser)).status_code == 200
        assert (await browser.get("/api/auth/session")).json()["session_id"] != old_sid
        assert await db.refresh_tokens.count_documents({"family_id": old_sid}) == 0
        res = await authorize(browser, "crm", CRM_CB, challenge, scope="openid", max_age="3600")
        assert res.headers["location"].startswith(CRM_CB + "?code=")

        await db.refresh_tokens.update_many(
            {"client_id": None}, {"$set": {"created_at": utcnow() - timedelta(hours=2)}}
        )
        res = await authorize(browser, "crm", CRM_CB, challenge, scope="openid", max_age="3600", prompt="none")
        assert query_of(res.headers["location"])["error"] == "login_required"
        res = await authorize(browser, "crm", CRM_CB, challenge, scope="openid", max_age="3600")
        location = res.headers["location"]
        assert location.startswith("http://auth.test/login?next=")
        assert "max_age" not in query_of(query_of(location)["next"])


async def test_authorize_refreshes_expired_access_cookie(db, make_user, oauth_clients):
    _, challenge = pkce()
    async with signed_in_browser(make_user) as browser:
        old_refresh = browser.cookies.get("refresh_token")
        from tests.conftest import drop_cookie

        drop_cookie(browser, "access_token")
        res = await authorize(browser, "crm", CRM_CB, challenge, scope="openid")
        assert res.headers["location"].startswith(CRM_CB + "?code=")
        assert browser.cookies.get("access_token")
        assert browser.cookies.get("refresh_token") != old_refresh


# --------------------------------------------------------------------------
# Refresh tokens
# --------------------------------------------------------------------------


async def test_oauth_refresh_rotation_and_reuse_detection(db, make_user, oauth_clients, monkeypatch):
    secret = oauth_clients["crm_secret"]
    async with signed_in_browser(make_user) as browser, make_client() as rp:
        verifier, challenge = pkce()
        code = await crm_code(browser, challenge)
        tokens = (await exchange(rp, code, verifier, client_id=None, redirect_uri=CRM_CB,
                                 headers=basic("crm", secret))).json()
        r1 = tokens["refresh_token"]
        record = await db.refresh_tokens.find_one({"client_id": "crm"})
        assert record["session_id"] and record["family_id"] != record["session_id"]

        async def refresh(token, **extra):
            return await rp.post(f"{OAUTH}/token", data={"grant_type": "refresh_token", "refresh_token": token, **extra},
                                 headers=basic("crm", secret))

        res = await refresh(r1)
        assert res.status_code == 200, res.text
        body = res.json()
        r2 = body["refresh_token"]
        assert r2 != r1 and body["access_token"] and body["id_token"]
        claims = await verify_id_token(rp, body["id_token"], "crm")
        assert "nonce" not in claims

        # Down-scoping is allowed, widening is not.
        res = await refresh(r2, scope="openid profile")
        assert res.json()["error"] == "invalid_scope"
        # Wrong client cannot use it.
        res = await rp.post(f"{OAUTH}/token", data={"grant_type": "refresh_token", "refresh_token": r2,
                                                    "client_id": "notes"})
        assert res.status_code == 400 and res.json()["error"] == "invalid_grant"

        # Inside the grace window a parallel refresh with r1 still works.
        assert (await refresh(r1)).status_code == 200
        # Outside it, reusing a rotated token revokes the whole grant.
        monkeypatch.setattr(security_settings, "REFRESH_REUSE_GRACE_SECONDS", -1)
        res = await refresh(r1)
        assert res.status_code == 400 and "reuse" in res.json()["error_description"]
        assert (await refresh(r2)).status_code == 400
        assert await db.audit_events.count_documents({"event": "oauth.refresh_reuse"}) == 1
        assert (await browser.get("/api/auth/me")).status_code == 200  # SSO session survives


async def test_oauth_refresh_dies_with_sso_session(db, make_user, oauth_clients):
    async with signed_in_browser(make_user) as browser, make_client() as rp:
        verifier, challenge = pkce()
        code = await approved_code(browser, challenge, scope="openid offline_access")
        refresh = (await exchange(rp, code, verifier)).json()["refresh_token"]
        await browser.post("/api/auth/logout", headers=csrf_headers(browser))
        res = await rp.post(f"{OAUTH}/token", data={"grant_type": "refresh_token", "refresh_token": refresh,
                                                    "client_id": "notes"})
        assert res.status_code == 400 and res.json()["error"] == "invalid_grant"


async def test_first_party_endpoints_reject_oauth_tokens(db, make_user, oauth_clients):
    async with signed_in_browser(make_user) as browser, make_client() as rp:
        verifier, challenge = pkce()
        code = await approved_code(browser, challenge, scope="openid offline_access")
        tokens = (await exchange(rp, code, verifier)).json()

        # OAuth refresh token as the first-party refresh cookie.
        async with make_client() as attacker:
            attacker.cookies.set("refresh_token", tokens["refresh_token"])
            assert (await attacker.post("/api/auth/refresh")).status_code == 401
            session = (await attacker.get("/api/auth/session")).json()
            assert session["authenticated"] is False
        # The OAuth grant is not listed as a browser session.
        sessions = (await browser.get("/api/auth/sessions")).json()
        assert sessions["total_count"] == 1

        # OAuth access token on first-party endpoints.
        bearer = {"Authorization": f"Bearer {tokens['access_token']}"}
        assert (await rp.get("/api/auth/me", headers=bearer)).status_code == 401
        assert (await rp.get("/api/auth/sessions", headers=bearer)).status_code == 401

        # ...and in the app-side SDK (IdentityDep).
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "sdk" / "python"))
        from karan_sso import SsoSettings
        from karan_sso.fastapi import SsoAuth

        sso = SsoAuth(
            SsoSettings(_env_file=None, SSO_BASE_URL="http://testserver/api", SSO_ISSUER=ISSUER,
                        SSO_JWT_SECRET="", SSO_APP_ID="familyos"),
            http=lambda: httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver"),
        )

        class _Req:
            def __init__(self, token):
                self.cookies = {"access_token": token}
                self.headers = {}
                self.state = type("S", (), {})()

        with pytest.raises(Exception) as exc:
            await sso.identity(_Req(tokens["access_token"]))
        assert getattr(exc.value, "status_code", None) == 401
        # Sanity: the first-party cookie token is accepted.
        assert (await sso.identity(_Req(browser.cookies.get("access_token")))).email == "user@example.com"


# --------------------------------------------------------------------------
# Userinfo / revoke / logout
# --------------------------------------------------------------------------


async def test_userinfo_scopes_and_rejections(db, make_user, oauth_clients):
    async with signed_in_browser(make_user) as browser, make_client() as rp:
        user = await db.users.find_one({"email": "user@example.com"})

        verifier, challenge = pkce()
        code = await approved_code(browser, challenge)
        access = (await exchange(rp, code, verifier)).json()["access_token"]
        bearer = {"Authorization": f"Bearer {access}"}
        res = await rp.get(f"{OAUTH}/userinfo", headers=bearer)
        assert res.status_code == 200
        assert res.json() == {
            "sub": str(user["_id"]), "email": "user@example.com", "email_verified": True, "name": "User",
        }
        assert (await rp.post(f"{OAUTH}/userinfo", headers=bearer)).json()["sub"] == str(user["_id"])

        verifier, challenge = pkce()
        code = await approved_code(browser, challenge, scope="openid")
        narrow = (await exchange(rp, code, verifier)).json()["access_token"]
        res = await rp.get(f"{OAUTH}/userinfo", headers={"Authorization": f"Bearer {narrow}"})
        assert res.json() == {"sub": str(user["_id"])}

        # Missing / garbage / first-party session token.
        res = await rp.get(f"{OAUTH}/userinfo")
        assert res.status_code == 401 and res.headers["www-authenticate"].startswith("Bearer")
        assert (await rp.get(f"{OAUTH}/userinfo", headers={"Authorization": "Bearer x.y.z"})).status_code == 401
        first_party = browser.cookies.get("access_token")
        res = await rp.get(f"{OAUTH}/userinfo", headers={"Authorization": f"Bearer {first_party}"})
        assert res.status_code == 401
        assert 'error="invalid_token"' in res.headers["www-authenticate"]

        # Ending the SSO session kills the OAuth access token.
        await browser.post("/api/auth/logout", headers=csrf_headers(browser))
        assert (await rp.get(f"{OAUTH}/userinfo", headers=bearer)).status_code == 401


async def test_userinfo_rejects_tokens_of_deleted_client(db, make_user, oauth_clients):
    async with signed_in_browser(make_user) as browser, make_client() as rp:
        verifier, challenge = pkce()
        code = await approved_code(browser, challenge, scope="openid offline_access")
        tokens = (await exchange(rp, code, verifier)).json()
        async with owner_client() as c:
            assert (await c.delete("/api/auth/admin/clients/notes", headers=csrf_headers(c))).status_code == 200
        bearer = {"Authorization": f"Bearer {tokens['access_token']}"}
        assert (await rp.get(f"{OAUTH}/userinfo", headers=bearer)).status_code == 401
        assert await db.refresh_tokens.count_documents({"client_id": "notes"}) == 0
        assert await db.oauth_consents.count_documents({"client_id": "notes"}) == 0


async def test_revoke_endpoint(db, make_user, oauth_clients):
    secret = oauth_clients["crm_secret"]
    async with signed_in_browser(make_user) as browser, make_client() as rp:
        verifier, challenge = pkce()
        code = await crm_code(browser, challenge)
        tokens = (await exchange(rp, code, verifier, client_id=None, redirect_uri=CRM_CB,
                                 headers=basic("crm", secret))).json()

        # Unknown tokens → 200. Confidential client must authenticate.
        res = await rp.post(f"{OAUTH}/revoke", data={"token": "unknown"}, headers=basic("crm", secret))
        assert res.status_code == 200
        res = await rp.post(f"{OAUTH}/revoke", data={"token": tokens["refresh_token"], "client_id": "crm"})
        assert res.status_code == 401
        # Another client can't revoke it (silently ignored).
        res = await rp.post(f"{OAUTH}/revoke", data={"token": tokens["refresh_token"], "client_id": "notes"})
        assert res.status_code == 200
        assert await db.refresh_tokens.count_documents({"client_id": "crm"}) == 1

        res = await rp.post(
            f"{OAUTH}/revoke",
            data={"token": tokens["refresh_token"], "token_type_hint": "refresh_token"},
            headers=basic("crm", secret),
        )
        assert res.status_code == 200
        assert await db.refresh_tokens.count_documents({"client_id": "crm"}) == 0
        res = await rp.post(f"{OAUTH}/token", data={"grant_type": "refresh_token",
                                                    "refresh_token": tokens["refresh_token"]},
                            headers=basic("crm", secret))
        assert res.status_code == 400
        # Revoking an access token is accepted (no-op: short-lived JWT).
        res = await rp.post(f"{OAUTH}/revoke", data={"token": tokens["access_token"]}, headers=basic("crm", secret))
        assert res.status_code == 200


async def test_rp_initiated_logout(db, make_user, oauth_clients):
    async with signed_in_browser(make_user) as browser, make_client() as rp:
        verifier, challenge = pkce()
        code = await approved_code(browser, challenge)
        id_token = (await exchange(rp, code, verifier)).json()["id_token"]

        res = await browser.get(f"{OAUTH}/logout", params={
            "id_token_hint": id_token, "post_logout_redirect_uri": NOTES_BYE, "state": "bye-1",
        })
        assert res.status_code == 302
        assert res.headers["location"] == f"{NOTES_BYE}?state=bye-1"
        assert (await browser.get("/api/auth/session")).json()["authenticated"] is False
        user = await db.users.find_one({"email": "user@example.com"})
        assert await db.refresh_tokens.count_documents({"user_id": user["_id"], "client_id": None}) == 0

    async with signed_in_browser(make_user, email="u2@example.com") as browser:
        # Another session's (valid) id_token, no hint, or a forged hint must NOT
        # sign this browser out — otherwise any site could log users out.
        for params in (
            {"id_token_hint": id_token, "post_logout_redirect_uri": NOTES_BYE},
            {"post_logout_redirect_uri": NOTES_BYE},
            {"id_token_hint": id_token[:-4] + "AAAA", "post_logout_redirect_uri": NOTES_BYE},
        ):
            res = await browser.get(f"{OAUTH}/logout", params=params)
            assert res.headers["location"] == "http://auth.test/account"
            assert (await browser.get("/api/auth/me")).status_code == 200

        # Own hint but unregistered redirect → logged out, sent to SSO login.
        verifier, challenge = pkce()
        code = await approved_code(browser, challenge)
        own_id_token = (await exchange(rp_client := make_client(), code, verifier)).json()["id_token"]
        await rp_client.aclose()
        res = await browser.get(f"{OAUTH}/logout", params={
            "id_token_hint": own_id_token, "post_logout_redirect_uri": "https://evil.example.com/",
        })
        assert res.headers["location"] == "http://auth.test/login"
        assert (await browser.get("/api/auth/me")).status_code == 401
