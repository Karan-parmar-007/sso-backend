"""Brute force, enumeration, verification, CSRF, password & email changes."""

from tests.conftest import PASSWORD, csrf_headers, login, make_client


async def test_login_locks_after_repeated_failures_even_with_right_password(client, make_user):
    await make_user()
    for _ in range(5):
        assert (await login(client, password="Wrong12345")).status_code == 401
    res = await login(client)
    assert res.status_code == 429
    assert "Retry-After" in res.headers


async def test_unknown_email_locks_the_same_way(client):
    """No enumeration: unknown emails behave exactly like known ones."""
    for _ in range(5):
        assert (await login(client, email="ghost@example.com", password="Wrong12345")).status_code == 401
    assert (await login(client, email="ghost@example.com", password="Wrong12345")).status_code == 429


async def test_signup_response_identical_for_existing_email(client, make_user, outbox):
    await make_user(email="taken@example.com")
    new = await client.post(
        "/api/auth/signup", json={"name": "N", "email": "new@example.com", "password": PASSWORD}
    )
    taken = await client.post(
        "/api/auth/signup", json={"name": "N", "email": "taken@example.com", "password": PASSWORD}
    )
    assert new.status_code == taken.status_code == 201
    assert new.json() == taken.json()
    assert "Sign-up attempt" in outbox.to("taken@example.com")[-1]["subject"]
    assert "Verify" in outbox.to("new@example.com")[-1]["subject"]


async def test_forgot_password_is_silent(client, make_user, outbox):
    await make_user()
    for _ in range(6):  # past the daily limit: still 200, no 429
        res = await client.post("/api/auth/forgot-password", json={"email": "user@example.com"})
        assert res.status_code == 200
    unknown = await client.post("/api/auth/forgot-password", json={"email": "nobody@example.com"})
    assert unknown.json() == res.json()
    assert len(outbox.to("user@example.com")) == 3


async def test_unverified_login_blocked_and_resend_by_email(client, make_user, outbox):
    await make_user(verified=False)
    res = await login(client)
    assert res.status_code == 403
    assert res.json()["code"] == "email_not_verified"
    assert "access_token" not in client.cookies

    res = await client.post("/api/auth/resend-verification", json={"email": "user@example.com"})
    assert res.status_code == 200
    token = outbox.last_link("user@example.com", "/verify-email")
    assert (await client.post("/api/auth/verify-email", json={"token": token})).status_code == 200
    assert (await login(client)).status_code == 200


async def test_csrf_required_and_referer_bypass_removed(client, make_user):
    await make_user()
    await login(client)
    body = {"old_password": PASSWORD, "new_password": "Another123", "confirm_password": "Another123"}

    res = await client.post("/api/auth/change-password", json=body)
    assert res.status_code == 403
    res = await client.post(
        "/api/auth/change-password", json=body, headers={"Referer": "https://evil.example/docs"}
    )
    assert res.status_code == 403


async def test_change_password_signs_out_other_sessions(db, make_user, outbox):
    await make_user()
    async with make_client() as current, make_client() as other:
        await login(current)
        await login(other)
        res = await current.post(
            "/api/auth/change-password",
            json={"old_password": PASSWORD, "new_password": "Another123", "confirm_password": "Another123"},
            headers=csrf_headers(current),
        )
        assert res.status_code == 200, res.text
        assert (await current.get("/api/auth/me")).status_code == 200
        assert (await other.post("/api/auth/refresh")).status_code == 401
        assert outbox.to("user@example.com")[-1]["subject"] == "Your password was changed"


async def test_change_password_wrong_attempts_are_limited(client, make_user):
    await make_user()
    await login(client)
    body = {"old_password": "Wrong12345", "new_password": "Another123", "confirm_password": "Another123"}
    for _ in range(5):
        res = await client.post("/api/auth/change-password", json=body, headers=csrf_headers(client))
        assert res.status_code == 400
    body["old_password"] = PASSWORD
    res = await client.post("/api/auth/change-password", json=body, headers=csrf_headers(client))
    assert res.status_code == 429


async def test_email_change_requires_password_and_revokes_sessions(client, make_user, outbox):
    await make_user()
    await login(client)
    res = await client.post(
        "/api/auth/request-email-change",
        json={"new_email": "new@example.com", "current_password": "Wrong12345"},
        headers=csrf_headers(client),
    )
    assert res.status_code == 400

    res = await client.post(
        "/api/auth/request-email-change",
        json={"new_email": "new@example.com", "current_password": PASSWORD},
        headers=csrf_headers(client),
    )
    assert res.status_code == 200
    assert outbox.to("user@example.com")[-1]["subject"] == "Email change requested"

    token = outbox.last_link("new@example.com", "/confirm-email")
    res = await client.post("/api/auth/confirm-email-change", json={"token": token})
    assert res.status_code == 200
    assert outbox.to("user@example.com")[-1]["subject"] == "Your account email was changed"
    assert (await client.get("/api/auth/session")).json()["authenticated"] is False
    # Single use
    assert (await client.post("/api/auth/confirm-email-change", json={"token": token})).status_code == 400


async def test_reset_password_link_is_single_use_and_signs_out(client, make_user, outbox):
    await make_user()
    async with make_client() as other:
        await login(other)
        await client.post("/api/auth/forgot-password", json={"email": "user@example.com"})
        token = outbox.last_link("user@example.com", "/reset-password")
        body = {"token": token, "new_password": "Another123", "confirm_password": "Another123"}
        assert (await client.post("/api/auth/reset-password", json=body)).status_code == 200
        assert (await client.post("/api/auth/reset-password", json=body)).status_code == 400
        assert (await other.post("/api/auth/refresh")).status_code == 401
    assert (await login(client, password="Another123")).status_code == 200


async def test_password_longer_than_bcrypt_limit_rejected(client):
    res = await client.post(
        "/api/auth/signup",
        json={"name": "N", "email": "long@example.com", "password": "a1" + "é" * 40},
    )
    assert res.status_code == 400


async def test_new_device_alert(db, make_user, outbox):
    await make_user()
    chrome = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0 Safari/537.36"}
    firefox = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Firefox/121.0"}
    async with make_client() as c:
        c.headers.update(chrome)
        await login(c)
        await login(c)
    assert not [m for m in outbox if m["subject"] == "New sign-in to your account"]
    async with make_client() as c:
        c.headers.update(firefox)
        await login(c)
    alerts = [m for m in outbox if m["subject"] == "New sign-in to your account"]
    assert len(alerts) == 1 and "Firefox on Linux" in alerts[0]["body"]


async def test_security_activity_lists_own_events(client, make_user):
    await make_user()
    await login(client, password="Wrong12345")
    await login(client)
    events = (await client.get("/api/auth/activity")).json()["events"]
    names = [e["event"] for e in events]
    assert "login.success" in names and "login.failure" in names


async def test_client_ip_ignores_spoofed_forwarded_entries(client, db, make_user):
    await make_user()
    await client.post(
        "/api/auth/login",
        json={"email": "user@example.com", "password": PASSWORD},
        headers={"X-Forwarded-For": "6.6.6.6, 10.0.0.7"},
    )
    event = await db.audit_events.find_one({"event": "login.success"})
    assert event["ip"] == "10.0.0.7"


async def test_parallel_guess_burst_cannot_exceed_limit(make_user, outbox):
    """Attempts are counted atomically before the password is checked."""
    import asyncio

    await make_user()

    async def guess():
        async with make_client() as c:
            return (await login(c, password="Wrong12345")).status_code

    codes = await asyncio.gather(*(guess() for _ in range(12)))
    assert codes.count(401) == 5
    assert codes.count(429) == 7


async def test_session_reissues_missing_csrf_cookie(client, make_user):
    from tests.conftest import drop_cookie

    await make_user()
    await login(client)
    drop_cookie(client, "csrf_token")
    assert (await client.get("/api/auth/session")).json()["authenticated"] is True
    assert client.cookies.get("csrf_token")


async def test_lockout_from_one_ip_does_not_lock_owner_elsewhere(make_user, outbox):
    """Review fix: a stranger can't lock the account from their own IP."""
    await make_user()
    async with make_client() as attacker, make_client() as owner:
        attacker.headers["X-Forwarded-For"] = "203.0.113.9"
        owner.headers["X-Forwarded-For"] = "198.51.100.7"
        for _ in range(6):
            await login(attacker, password="Wrong12345")
        assert (await login(attacker)).status_code == 429
        assert (await login(owner)).status_code == 200


async def test_email_change_to_registered_address_is_not_an_oracle(client, make_user, outbox):
    await make_user()
    await make_user(email="taken@example.com")
    await login(client)
    res = await client.post(
        "/api/auth/request-email-change",
        json={"new_email": "taken@example.com", "current_password": PASSWORD},
        headers=csrf_headers(client),
    )
    assert res.status_code == 200
    assert outbox.to("taken@example.com")[-1]["subject"] == "Someone tried to use your email address"
    # The daily limit applies before any existence check.
    res = await client.post(
        "/api/auth/request-email-change",
        json={"new_email": "free@example.com", "current_password": PASSWORD},
        headers=csrf_headers(client),
    )
    assert res.status_code == 429


async def test_login_issues_fresh_csrf_token(client, make_user):
    await make_user()
    res = await client.post(
        "/api/auth/login",
        json={"email": "user@example.com", "password": PASSWORD},
        headers={"Cookie": "csrf_token=planted-by-attacker"},
    )
    csrf = next(h for h in res.headers.get_list("set-cookie") if h.startswith("csrf_token="))
    assert "planted-by-attacker" not in csrf

    # ...but a refresh keeps the session's token stable.
    token = csrf.split(";")[0].split("=", 1)[1]
    async with make_client() as tab:
        tab.cookies.set("refresh_token", res.cookies["refresh_token"], path="/api/auth")
        tab.cookies.set("csrf_token", token)
        refreshed = await tab.post("/api/auth/refresh")
        assert f"csrf_token={token}" in refreshed.headers["set-cookie"]
