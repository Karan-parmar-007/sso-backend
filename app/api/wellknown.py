"""Discovery: signing keys (JWKS) and the OpenID Connect provider metadata."""

from fastapi import APIRouter, Response

from app.services.oauth_service import discovery_document
from app.utils.keys import jwks

router = APIRouter()


@router.get("/.well-known/jwks.json")
def get_jwks(response: Response) -> dict:
    # Short cache: verifiers re-fetch on unknown `kid` anyway.
    response.headers["Cache-Control"] = "public, max-age=300"
    return jwks()


@router.get("/.well-known/openid-configuration")
def openid_configuration(response: Response) -> dict:
    response.headers["Cache-Control"] = "public, max-age=300"
    return discovery_document()
