"""Login, /session, refresh rotation, reuse detection, logout."""

import asyncio
from datetime import timedelta

import jwt

from app.db.indexes import utcnow
from app.utils.security import hash_token
from tests.conftest import PASSWORD, csrf_headers, drop_cookie, login, make_client


async def test_login_sets_cookies_and_session_reports_user(client, make_user):
    await make_user()
    res = await login(client)
    assert res.status_code == 200
    assert {"access_token", "refresh_token", "csrf_token"} <= set(client.cookies.keys())

    session = (await client.get("/api/auth/session")).json()
    assert session["authenticated"] is True
    assert session["user"]["email"] == "user@example.com"
    assert session["session_id"]


async def test_session_is_anonymous_without_cookies(client):
    res = await client.get("/api/auth/session")
    assert res.status_code == 200
    assert res.json() == {
        "authenticated": False,
        "user": None,
        "session_id": None,
        "access_token_expires_in": None,
    }


async def test_session_refreshes_when_access_token_expired(client, make_user):
    """The bug class behind 'shows Sign in while signed in'."""
    await make_user()
    await login(client)
    old_refresh = client.cookies.get("refresh_token")
    drop_cookie(client, "access_token")  # browser dropped it after 15 min

    res = await client.get("/api/auth/session")
    body = res.json()
    assert body["authenticated"] is True
    assert body["access_token_expires_in"]
    assert client.cookies.get("access_token")
    assert client.cookies.get("refresh_token") != old_refresh


async def test_access_token_claims_and_jwks(client, make_user):
    await make_user()
    await login(client)
    token = client.cookies.get("access_token")
    header = jwt.get_unverified_header(token)
    assert header["alg"] == "RS256" and header["kid"] == "test-kid"

    jwks = (await client.get("/api/auth/.well-known/jwks.json")).json()
    key = jwt.PyJWK(jwks["keys"][0]).key
    claims = jwt.decode(token, key, algorithms=["RS256"], options={"verify_aud": False})
    assert claims["iss"] == "http://testserver/api/auth"
    assert claims["type"] == "access"
    assert claims["sid"] and claims["jti"] and claims["iat"]
    assert claims["role"] == "user" and claims["role_name"] == "user"
    assert claims["roles"] == {}
    assert "aud" not in claims  # JWT_AUDIENCE empty during rollout


async def test_refresh_rotates_and_old_token_reuse_revokes_session(client, db, make_user):
    await make_user()
    await login(client)
    first = client.cookies.get("refresh_token")

    assert (await client.post("/api/auth/refresh")).status_code == 200
    second = client.cookies.get("refresh_token")
    assert second != first

    # Pretend the first rotation happened long ago, then replay the old token.
    await db.refresh_tokens.update_one(
        {"token_hash": hash_token(first)},
        {"$set": {"rotated_at": utcnow() - timedelta(minutes=5)}},
    )
    async with make_client() as attacker:
        attacker.cookies.set("refresh_token", first, path="/api/auth")
        res = await attacker.post("/api/auth/refresh")
        assert res.status_code == 401

    # Whole session family is gone: the legitimate token no longer works.
    assert (await client.post("/api/auth/refresh")).status_code == 401
    assert await db.audit_events.count_documents({"event": "session.refresh_reuse"}) == 1


async def test_parallel_refresh_within_grace_keeps_session(client, db, make_user):
    """Two tabs / two apps refreshing with the same cookie at once."""
    await make_user()
    await login(client)
    token = client.cookies.get("refresh_token")

    async def refresh_with(t):
        async with make_client() as tab:
            tab.cookies.set("refresh_token", t, path="/api/auth")
            return await tab.post("/api/auth/refresh")

    results = await asyncio.gather(*(refresh_with(token) for _ in range(4)))
    assert [r.status_code for r in results] == [200] * 4
    assert await db.audit_events.count_documents({"event": "session.refresh_reuse"}) == 0

    # The session is intact: each successor token refreshes again.
    async with make_client() as tab:
        tab.cookies.set("refresh_token", results[0].cookies["refresh_token"], path="/api/auth")
        assert (await tab.post("/api/auth/refresh")).status_code == 200

    sessions = await db.refresh_tokens.distinct("family_id")
    assert len(sessions) == 1


async def test_logout_works_with_expired_access_token(client, db, make_user):
    await make_user()
    await login(client)
    refresh = client.cookies.get("refresh_token")
    drop_cookie(client, "access_token")

    res = await client.post("/api/auth/logout", headers=csrf_headers(client))
    assert res.status_code == 200
    assert "access_token" not in client.cookies and "refresh_token" not in client.cookies

    async with make_client() as replay:
        replay.cookies.set("refresh_token", refresh, path="/api/auth")
        assert (await replay.post("/api/auth/refresh")).status_code == 401
        assert (await replay.get("/api/auth/session")).json()["authenticated"] is False


async def test_logout_everywhere(db, make_user, outbox):
    await make_user()
    async with make_client() as a, make_client() as b:
        await login(a)
        await login(b)
        res = await a.post("/api/auth/logout?everywhere=true", headers=csrf_headers(a))
        assert res.status_code == 200
        assert (await b.post("/api/auth/refresh")).status_code == 401


async def test_revoked_session_access_token_is_rejected(db, make_user, outbox):
    await make_user()
    async with make_client() as a, make_client() as b:
        await login(a)
        await login(b)
        sessions = (await a.get("/api/auth/sessions")).json()["sessions"]
        assert len(sessions) == 2
        other = next(s for s in sessions if not s["is_current"])

        res = await a.delete(f"/api/auth/sessions/{other['id']}", headers=csrf_headers(a))
        assert res.status_code == 200
        # b still holds an unexpired access token, but its session is gone.
        assert (await b.get("/api/auth/me")).status_code == 401
        assert (await b.get("/api/auth/session")).json()["authenticated"] is False


async def test_remember_me_off_stays_a_browser_session_after_refresh(client, make_user):
    await make_user()
    res = await login(client, remember_me=False)
    refresh_cookie = next(h for h in res.headers.get_list("set-cookie") if h.startswith("refresh_token="))
    assert "Max-Age" not in refresh_cookie

    res = await client.post("/api/auth/refresh")
    refresh_cookie = next(h for h in res.headers.get_list("set-cookie") if h.startswith("refresh_token="))
    assert "Max-Age" not in refresh_cookie


async def test_csrf_cookie_is_stable_across_refresh(client, make_user):
    await make_user()
    await login(client)
    before = client.cookies.get("csrf_token")
    await client.post("/api/auth/refresh")
    assert client.cookies.get("csrf_token") == before


async def test_legacy_hs256_only_while_sso_signs_hs256(client, make_user, monkeypatch):
    from app.config import security_settings

    user = await make_user()
    await login(client)
    sid = jwt.decode(client.cookies.get("access_token"), options={"verify_signature": False})["sid"]

    def hs256(**extra):
        claims = {
            "sub": str(user["_id"]), "user_id": str(user["_id"]), "email": user["email"],
            "type": "access", "exp": utcnow() + timedelta(minutes=5), **extra,
        }
        return {"Authorization": "Bearer " + jwt.encode(claims, "legacy-test-secret-0123456789abcdef", algorithm="HS256")}

    async with make_client() as api:  # no cookies: only the bearer counts
        # SSO signs RS256: the shared secret no longer authenticates anyone.
        assert (await api.get("/api/auth/me", headers=hs256(sid=sid))).status_code == 401

        monkeypatch.setattr(security_settings, "JWT_SIGNING_ALG", "HS256")
        assert (await api.get("/api/auth/me", headers=hs256(sid=sid))).status_code == 200
        # Without a session id a token can't be checked for revocation: refused.
        assert (await api.get("/api/auth/me", headers=hs256())).status_code == 401


async def test_token_signed_with_unknown_key_rejected(client, make_user):
    from cryptography.hazmat.primitives.asymmetric import rsa

    user = await make_user()
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = jwt.encode(
        {"sub": str(user["_id"]), "email": user["email"], "type": "access",
         "exp": utcnow() + timedelta(minutes=5)},
        other,
        algorithm="RS256",
        headers={"kid": "test-kid"},
    )
    res = await client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 401


async def test_password_is_required_on_login(client, make_user):
    await make_user()
    res = await login(client, password="wrong" + PASSWORD)
    assert res.status_code == 401
