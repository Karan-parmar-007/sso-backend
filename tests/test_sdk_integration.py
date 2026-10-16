"""The app-side SDK against the real SSO app (JWKS + live /me)."""

import sys
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "sdk" / "python"))

from karan_sso import SsoSettings  # noqa: E402
from karan_sso.fastapi import SsoAuth  # noqa: E402
from main import app  # noqa: E402
from tests.conftest import csrf_headers, login, make_client  # noqa: E402


class _Req:
    def __init__(self, token):
        self.cookies = {"access_token": token}
        self.headers = {}
        self.state = type("S", (), {})()


async def test_sdk_verifies_sso_tokens_and_sees_revocation(db, make_user, outbox):
    await make_user()
    sso = SsoAuth(
        SsoSettings(
            _env_file=None,
            SSO_BASE_URL="http://testserver/api",
            SSO_ISSUER="http://testserver/api/auth",
            SSO_JWT_SECRET="",
            SSO_APP_ID="familyos",
        ),
        http=lambda: httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver"),
    )
    async with make_client() as browser:
        await login(browser)
        token = browser.cookies.get("access_token")

        identity = await sso.identity(_Req(token))
        assert identity.email == "user@example.com" and identity.role == "user"
        live = await sso.live_identity(_Req(token))
        assert live.live is True

        await browser.post("/api/auth/logout", headers=csrf_headers(browser))
        sso.live._cache.clear()
        try:
            await sso.live_identity(_Req(token))
        except Exception as exc:  # HTTPException 401
            assert getattr(exc, "status_code", None) == 401
        else:
            raise AssertionError("revoked session still accepted by live check")
