"""Test harness: real MongoDB (TEST_MONGO_URI), fresh database per test.

    TEST_MONGO_URI=mongodb://127.0.0.1:27017 pytest

Settings are read at import time, so the environment is prepared before any
`app` import.
"""

import base64
import os
import re
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
TEST_PRIVATE_PEM = _key.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption(),
)

os.environ.update(
    {
        "MONGO_URI": os.environ.get("TEST_MONGO_URI", "mongodb://127.0.0.1:27017"),
        "MONGO_DB_NAME": "sso_test",
        "ENVIRONMENT": "test",
        "JWT_SIGNING_ALG": "RS256",
        "JWT_PRIVATE_KEY_B64": base64.b64encode(TEST_PRIVATE_PEM).decode(),
        "JWT_ACTIVE_KID": "test-kid",
        "JWT_PREVIOUS_PUBLIC_KEYS": "",
        # Legacy secret configured so HS256 acceptance (rollout) is testable.
        "JWT_SECRET": "legacy-test-secret-0123456789abcdef",
        "JWT_ISSUER": "http://testserver/api/auth",
        "JWT_AUDIENCE": "",
        "REQUIRE_EMAIL_VERIFICATION": "true",
        "SMTP_USERNAME": "",
        "SMTP_PASSWORD": "",
        "OWNER_EMAIL": "owner@example.com",
        "OWNER_PASSWORD": "OwnerPass123",
        "TOKEN_CLEANUP_ENABLED": "false",
        "AUTH_FRONTEND_URL": "http://auth.test",
    }
)

import httpx  # noqa: E402
import pytest  # noqa: E402

from app.db import mongo as mongo_module  # noqa: E402
from app.db.indexes import ensure_indexes, utcnow  # noqa: E402
from app.utils import email as email_module  # noqa: E402
from app.utils.security import hash_password  # noqa: E402
from bootstrap import seed_roles_and_owner  # noqa: E402
from main import app  # noqa: E402

PASSWORD = "Password123"


class Outbox(list):
    def to(self, address: str) -> list[dict]:
        return [m for m in self if m["to"] == address]

    def last_link(self, address: str, path: str) -> str:
        for message in reversed(self.to(address)):
            match = re.search(rf"https?://\S+{re.escape(path)}\?token=([\w-]+)", message["body"] or "")
            if match:
                return match.group(1)
        raise AssertionError(f"No {path} link mailed to {address}")


@pytest.fixture
async def db():
    from pymongo import AsyncMongoClient

    name = f"sso_test_{uuid.uuid4().hex[:10]}"
    client = AsyncMongoClient(os.environ["MONGO_URI"])
    mongo_module.mongo_session.client = client
    from app.config import db_settings

    db_settings.MONGO_DB_NAME = name
    database = client[name]
    await ensure_indexes(database)
    await seed_roles_and_owner(database)
    yield database
    await client.drop_database(name)
    await client.close()
    mongo_module.mongo_session.client = None


@pytest.fixture
def outbox(monkeypatch) -> Outbox:
    box = Outbox()

    def fake_send(to_email, subject, plain_text=None, html_content=None):
        box.append({"to": to_email, "subject": subject, "body": plain_text})
        return True

    monkeypatch.setattr(email_module.email_service, "send", fake_send)
    monkeypatch.setattr(email_module.email_service, "send_background", fake_send)
    return box


def make_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    )


@pytest.fixture
async def client(db, outbox):
    async with make_client() as c:
        yield c


@pytest.fixture
async def make_user(db):
    async def _make(email="user@example.com", password=PASSWORD, verified=True, role="user", name="User"):
        role_doc = await db.roles.find_one({"name": role})
        now = utcnow()
        doc = {
            "name": name,
            "email": email,
            "password_hash": hash_password(password),
            "role_id": role_doc["_id"],
            "app_roles": {},
            "email_verified": verified,
            "created_at": now,
            "updated_at": now,
        }
        result = await db.users.insert_one(doc)
        doc["_id"] = result.inserted_id
        return doc

    return _make


async def login(client: httpx.AsyncClient, email="user@example.com", password=PASSWORD, remember_me=True):
    res = await client.post(
        "/api/auth/login", json={"email": email, "password": password, "remember_me": remember_me}
    )
    return res


def csrf_headers(client: httpx.AsyncClient) -> dict:
    return {"X-CSRF-Token": client.cookies.get("csrf_token") or ""}


def drop_cookie(client: httpx.AsyncClient, name: str) -> None:
    for cookie in list(client.cookies.jar):
        if cookie.name == name:
            client.cookies.jar.clear(cookie.domain, cookie.path, cookie.name)
