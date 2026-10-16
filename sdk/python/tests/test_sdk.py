import json
import time
from datetime import datetime, timedelta, timezone

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI
from jwt.algorithms import RSAAlgorithm

from karan_sso import SsoSettings
from karan_sso import fastapi as sso_fastapi
from karan_sso.fastapi import AdminDep, CSRFMiddleware, IdentityDep, OwnerDep, require_app_role

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
SECRET = "legacy-secret-0123456789abcdef0123"


def jwks_doc():
    jwk = json.loads(RSAAlgorithm.to_jwk(KEY.public_key()))
    jwk.update({"kid": "k1", "alg": "RS256", "use": "sig"})
    return {"keys": [jwk]}


def token(key=KEY, alg="RS256", kid="k1", **overrides):
    claims = {
        "iss": "https://auth.test/api/auth",
        "sub": "u1",
        "user_id": "u1",
        "email": "u1@example.com",
        "type": "access",
        "role": "user",
        "roles": {},
        "sid": "s1",
        "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
    }
    claims.update(overrides)
    claims = {k: v for k, v in claims.items() if v is not None}
    headers = {"kid": kid} if kid else None
    return jwt.encode(claims, key, algorithm=alg, headers=headers)


class FakeSso:
    def __init__(self):
        self.me: dict | None = {"email": "u1@example.com", "role_name": "user", "app_roles": {}}
        self.me_status = 200
        self.calls = {"jwks": 0, "me": 0}

    def handler(self, request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/jwks.json"):
            self.calls["jwks"] += 1
            return httpx.Response(200, json=jwks_doc())
        if request.url.path.endswith("/auth/me"):
            self.calls["me"] += 1
            if self.me_status != 200:
                return httpx.Response(self.me_status, json={"detail": "x"})
            return httpx.Response(200, json=self.me)
        return httpx.Response(404)


@pytest.fixture
def sso():
    fake = FakeSso()
    settings = SsoSettings(
        _env_file=None,
        SSO_BASE_URL="http://sso/api",
        SSO_ISSUER="https://auth.test/api/auth",
        SSO_JWT_SECRET=SECRET,
        SSO_APP_ID="familyos",
    )
    transport = httpx.MockTransport(fake.handler)
    sso_fastapi.configure(settings, http=lambda: httpx.AsyncClient(transport=transport))
    return fake


@pytest.fixture
def app():
    app = FastAPI()
    app.add_middleware(CSRFMiddleware, exempt_prefixes=("/public",))

    @app.get("/me")
    async def me(user: IdentityDep):
        return {"user_id": user.user_id, "role": user.role, "sid": user.session_id}

    @app.get("/admin")
    async def admin(user: AdminDep):
        return {"ok": True}

    @app.get("/owner")
    async def owner(user: OwnerDep):
        return {"ok": True}

    @app.get("/editor", dependencies=[__import__("fastapi").Depends(require_app_role("editor"))])
    async def editor():
        return {"ok": True}

    @app.post("/mutate")
    async def mutate(user: IdentityDep):
        return {"ok": True}

    @app.post("/public/hook")
    async def hook():
        return {"ok": True}

    return app


@pytest.fixture
async def client(app):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://app") as c:
        yield c


def bearer(t):
    return {"Authorization": f"Bearer {t}"}


async def test_rs256_token_verified_via_jwks(sso, client):
    res = await client.get("/me", cookies={"access_token": token()})
    assert res.status_code == 200
    assert res.json() == {"user_id": "u1", "role": "user", "sid": "s1"}
    # JWKS is cached
    await client.get("/me", cookies={"access_token": token()})
    assert sso.calls["jwks"] == 1


async def test_missing_and_garbage_tokens_are_401(sso, client):
    assert (await client.get("/me")).status_code == 401
    assert (await client.get("/me", headers=bearer("not-a-jwt"))).status_code == 401


async def test_wrong_key_expired_and_wrong_issuer_rejected(sso, client):
    assert (await client.get("/me", headers=bearer(token(key=OTHER_KEY)))).status_code == 401
    expired = token(exp=datetime.now(timezone.utc) - timedelta(minutes=5))
    assert (await client.get("/me", headers=bearer(expired))).status_code == 401
    assert (await client.get("/me", headers=bearer(token(iss="https://evil")))).status_code == 401
    assert (await client.get("/me", headers=bearer(token(type="refresh")))).status_code == 401


async def test_audience_rules(sso, client):
    ok = token(aud="karanparmar-apps")
    assert (await client.get("/me", headers=bearer(ok))).status_code == 200
    oauth_client_token = token(aud="some-client")
    assert (await client.get("/me", headers=bearer(oauth_client_token))).status_code == 401


async def test_legacy_hs256_only_with_secret(sso, client):
    legacy = token(key=SECRET, alg="HS256", kid=None)
    assert (await client.get("/me", headers=bearer(legacy))).status_code == 200

    settings = SsoSettings(_env_file=None, SSO_BASE_URL="http://sso/api", SSO_JWT_SECRET="")
    sso_fastapi.configure(settings, http=lambda: httpx.AsyncClient(transport=httpx.MockTransport(FakeSso().handler)))
    assert (await client.get("/me", headers=bearer(legacy))).status_code == 401


async def test_algorithm_confusion_rejected(sso, client):
    """HS256 token whose 'secret' is our public key must not verify."""
    public_pem = KEY.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    claims = {"sub": "u1", "email": "u1@example.com", "type": "access",
              "exp": int(time.time()) + 300, "iss": "https://auth.test/api/auth"}
    import base64, hashlib, hmac
    def b64(b): return base64.urlsafe_b64encode(b).rstrip(b"=")
    signing_input = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()) + b"." + b64(json.dumps(claims).encode())
    sig = b64(hmac.new(public_pem, signing_input, hashlib.sha256).digest())
    forged = (signing_input + b"." + sig).decode()
    assert (await client.get("/me", headers=bearer(forged))).status_code == 401


async def test_admin_uses_live_role_not_token(sso, client):
    # Token says owner, SSO says user (demoted): denied.
    t = token(role="owner")
    assert (await client.get("/admin", headers=bearer(t))).status_code == 403
    # Token says user, SSO says super_admin: allowed.
    sso.me = {"email": "u1@example.com", "role_name": "super_admin", "app_roles": {}}
    assert (await client.get("/admin", headers=bearer(token(jti="other")))).status_code == 200


async def test_app_admin_role_grants_admin(sso, client):
    sso.me = {"email": "u1@example.com", "role_name": "user", "app_roles": {"familyos": ["admin"]}}
    assert (await client.get("/admin", headers=bearer(token()))).status_code == 200
    assert (await client.get("/owner", headers=bearer(token()))).status_code == 403


async def test_require_app_role(sso, client):
    sso.me = {"email": "u1@example.com", "role_name": "user", "app_roles": {"familyos": ["editor"]}}
    assert (await client.get("/editor", headers=bearer(token()))).status_code == 200
    sso.me = {"email": "u1@example.com", "role_name": "owner", "app_roles": {}}
    assert (await client.get("/editor", headers=bearer(token(jti="x")))).status_code == 403


async def test_revoked_session_is_401_and_sso_outage_is_503(sso, client):
    sso.me_status = 401
    assert (await client.get("/admin", headers=bearer(token()))).status_code == 401
    sso.me_status = 500
    assert (await client.get("/admin", headers=bearer(token(jti="y")))).status_code == 503


async def test_live_check_is_cached(sso, client):
    sso.me = {"email": "u1@example.com", "role_name": "owner", "app_roles": {}}
    t = token()
    for _ in range(3):
        assert (await client.get("/owner", headers=bearer(t))).status_code == 200
    assert sso.calls["me"] == 1


async def test_csrf_middleware(sso, client):
    cookies = {"access_token": token(), "csrf_token": "abc"}
    assert (await client.post("/mutate", cookies=cookies)).status_code == 403
    res = await client.post("/mutate", cookies=cookies, headers={"Referer": "https://x.example/docs"})
    assert res.status_code == 403
    res = await client.post("/mutate", cookies=cookies, headers={"X-CSRF-Token": "abc"})
    assert res.status_code == 200
    # Bearer-only clients have no cookies to forge
    assert (await client.post("/mutate", headers=bearer(token()))).status_code == 200
    # Exempt prefix
    assert (await client.post("/public/hook", cookies=cookies)).status_code == 200


async def test_token_without_session_id_rejected(sso, client):
    assert (await client.get("/me", headers=bearer(token(sid=None)))).status_code == 401
