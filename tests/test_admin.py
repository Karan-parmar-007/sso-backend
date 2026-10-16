"""Owner-only administration: roles, per-app roles, resets, clients, audit."""

from contextlib import asynccontextmanager

import jwt

from tests.conftest import csrf_headers, login, make_client


@asynccontextmanager
async def owner_client():
    async with make_client() as c:
        res = await login(c, email="owner@example.com", password="OwnerPass123")
        assert res.status_code == 200, res.text
        yield c


async def test_last_owner_cannot_be_demoted(db, outbox):
    owner = await db.users.find_one({"email": "owner@example.com"})
    async with owner_client() as c:
        res = await c.patch(
            f"/api/auth/admin/users/{owner['_id']}/role",
            json={"role_name": "user"},
            headers=csrf_headers(c),
        )
        assert res.status_code == 400
        assert "last owner" in res.json()["detail"]


async def test_admin_reset_sends_link_and_invalidates_password(db, make_user, outbox):
    user = await make_user()
    async with make_client() as victim:
        await login(victim)
        async with owner_client() as c:
            res = await c.post(
                f"/api/auth/admin/users/{user['_id']}/reset-password", headers=csrf_headers(c)
            )
            assert res.status_code == 200
            body = res.json()
            assert body["email_sent"] is True and body["reset_link"] is None
            assert "temporary_password" not in body
        assert (await victim.post("/api/auth/refresh")).status_code == 401
        assert (await login(victim)).status_code == 401  # old password is dead
        token = outbox.last_link("user@example.com", "/reset-password")
        res = await victim.post(
            "/api/auth/reset-password",
            json={"token": token, "new_password": "Fresh12345", "confirm_password": "Fresh12345"},
        )
        assert res.status_code == 200
        assert (await login(victim, password="Fresh12345")).status_code == 200


async def test_app_roles_flow_into_access_token(db, make_user, outbox):
    user = await make_user()
    async with owner_client() as c:
        res = await c.put(
            f"/api/auth/admin/users/{user['_id']}/app-roles/familyos",
            json={"roles": ["admin"]},
            headers=csrf_headers(c),
        )
        assert res.status_code == 200, res.text
        assert res.json()["app_roles"] == {"familyos": ["admin"]}

        bad = await c.put(
            f"/api/auth/admin/users/{user['_id']}/app-roles/familyos",
            json={"roles": ["superuser"]},
            headers=csrf_headers(c),
        )
        assert bad.status_code == 400

    async with make_client() as u:
        await login(u)
        claims = jwt.decode(u.cookies.get("access_token"), options={"verify_signature": False})
        assert claims["roles"] == {"familyos": ["admin"]}


async def test_client_registry_crud(db, outbox):
    async with owner_client() as c:
        listed = (await c.get("/api/auth/admin/clients")).json()
        assert {x["client_id"] for x in listed["clients"]} >= {"portfolio", "familyos", "allprojects"}

        res = await c.post(
            "/api/auth/admin/clients",
            json={
                "client_id": "notes",
                "name": "Notes",
                "confidential": True,
                "redirect_uris": ["https://notes.example.com/callback"],
                "roles": ["editor"],
            },
            headers=csrf_headers(c),
        )
        assert res.status_code == 201, res.text
        assert res.json()["client_secret"]

        res = await c.post(
            "/api/auth/admin/clients",
            json={"client_id": "evil", "name": "Evil", "redirect_uris": ["http://evil.example.com/cb"]},
            headers=csrf_headers(c),
        )
        assert res.status_code == 400  # non-https redirect

        res = await c.delete("/api/auth/admin/clients/notes", headers=csrf_headers(c))
        assert res.status_code == 200


async def test_admin_endpoints_require_owner(client, make_user):
    await make_user()
    await login(client)
    assert (await client.get("/api/auth/admin/users")).status_code == 403
    assert (await client.get("/api/auth/admin/audit")).status_code == 403


async def test_audit_log_lists_admin_actions(db, make_user, outbox):
    user = await make_user()
    async with owner_client() as c:
        await c.patch(
            f"/api/auth/admin/users/{user['_id']}/role",
            json={"role_name": "super_admin"},
            headers=csrf_headers(c),
        )
        events = (await c.get("/api/auth/admin/audit?event=admin.role_changed")).json()
        assert events["total_count"] == 1
        assert events["events"][0]["meta"] == {"role": "super_admin"}


async def test_admin_reset_works_even_when_user_exhausted_reset_emails(db, make_user, outbox):
    """Review fix: the token is created before the password is cleared."""
    user = await make_user()
    async with make_client() as anon:
        for _ in range(3):
            await anon.post("/api/auth/forgot-password", json={"email": "user@example.com"})
    async with owner_client() as c:
        res = await c.post(f"/api/auth/admin/users/{user['_id']}/reset-password", headers=csrf_headers(c))
        assert res.status_code == 200, res.text
    token = outbox.last_link("user@example.com", "/reset-password")
    async with make_client() as u:
        res = await u.post(
            "/api/auth/reset-password",
            json={"token": token, "new_password": "Fresh12345", "confirm_password": "Fresh12345"},
        )
        assert res.status_code == 200
