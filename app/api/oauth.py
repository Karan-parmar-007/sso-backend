"""OAuth 2.0 / OpenID Connect provider routes (authorization code + PKCE).

Mounted at /api/auth/oauth. Logic lives in OAuthService; routes only map
HTTP in/out. See docs/SSO_CONTRACT.md §7.
"""

from typing import Annotated, Any, Dict, Optional

from fastapi import APIRouter, Cookie, Depends, Form, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse

from app.api.cookies import clear_auth_cookies, set_auth_cookies
from app.api.dependencies import OAuthServiceDep
from app.dependencies.jwt_auth import require_auth
from app.schemas.oauth import (
    ConsentDecisionRequest,
    ConsentDecisionResponse,
    ConsentDetailsResponse,
)
from app.services.oauth_service import OAuthError
from app.utils.request_context import request_context

router = APIRouter()

AuthPayload = Annotated[Dict[str, Any], Depends(require_auth)]

_NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}


def _oauth_error(e: OAuthError) -> JSONResponse:
    headers = dict(_NO_STORE)
    if e.status_code == 401:
        headers["WWW-Authenticate"] = 'Basic realm="oauth"'
    return JSONResponse(status_code=e.status_code, content=e.body(), headers=headers)


def _bearer(request: Request) -> Optional[str]:
    auth = request.headers.get("authorization") or ""
    if auth.lower().startswith("bearer "):
        return auth[7:].strip() or None
    return None


def _uid(payload: Dict[str, Any]) -> str:
    return payload.get("user_id") or payload["sub"]


@router.get("/authorize")
async def authorize(
    request: Request,
    service: OAuthServiceDep,
    access_token: Optional[str] = Cookie(None),
    refresh_token: Optional[str] = Cookie(None),
):
    result = await service.authorize(
        list(request.query_params.multi_items()),
        access_token,
        refresh_token,
        request_context(request),
    )
    if result.error:
        # Unknown client / unregistered redirect_uri: never redirect.
        return JSONResponse(status_code=400, content=result.error.body(), headers=_NO_STORE)
    response = RedirectResponse(result.redirect_to, status_code=302)
    if result.issued:
        set_auth_cookies(request, response, result.issued)
    elif result.clear_cookies:
        clear_auth_cookies(response)
    return response


@router.get("/consent/{request_id}", response_model=ConsentDetailsResponse)
async def consent_details(request_id: str, service: OAuthServiceDep, user: AuthPayload):
    try:
        return await service.consent_details(request_id, _uid(user))
    except LookupError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/consent/{request_id}", response_model=ConsentDecisionResponse)
async def consent_decision(
    request: Request,
    request_id: str,
    data: ConsentDecisionRequest,
    service: OAuthServiceDep,
    user: AuthPayload,
):
    try:
        redirect_to = await service.decide_consent(
            request_id, _uid(user), user.get("sid"), data.approve, request_context(request)
        )
    except LookupError as e:
        raise HTTPException(status_code=404, detail=str(e))
    return ConsentDecisionResponse(redirect_to=redirect_to)


@router.post("/token")
async def token(
    request: Request,
    service: OAuthServiceDep,
    grant_type: Optional[str] = Form(None),
    code: Optional[str] = Form(None),
    redirect_uri: Optional[str] = Form(None),
    code_verifier: Optional[str] = Form(None),
    refresh_token: Optional[str] = Form(None),
    scope: Optional[str] = Form(None),
    client_id: Optional[str] = Form(None),
    client_secret: Optional[str] = Form(None),
):
    form = {
        "grant_type": grant_type,
        "code": code,
        "redirect_uri": redirect_uri,
        "code_verifier": code_verifier,
        "refresh_token": refresh_token,
        "scope": scope,
        "client_id": client_id,
        "client_secret": client_secret,
    }
    try:
        body = await service.token(
            form, request.headers.get("authorization"), request_context(request)
        )
    except OAuthError as e:
        return _oauth_error(e)
    return JSONResponse(content=body, headers=_NO_STORE)


@router.api_route("/userinfo", methods=["GET", "POST"])
async def userinfo(request: Request, service: OAuthServiceDep):
    try:
        claims = await service.userinfo(_bearer(request))
    except OAuthError as e:
        return JSONResponse(
            status_code=401,
            content=e.body(),
            headers={
                **_NO_STORE,
                "WWW-Authenticate": f'Bearer error="invalid_token", error_description="{e.description}"',
            },
        )
    return JSONResponse(content=claims, headers=_NO_STORE)


@router.post("/revoke")
async def revoke(
    request: Request,
    service: OAuthServiceDep,
    token: Optional[str] = Form(None),
    token_type_hint: Optional[str] = Form(None),
    client_id: Optional[str] = Form(None),
    client_secret: Optional[str] = Form(None),
):
    """RFC 7009: 200 for unknown / foreign / already revoked tokens."""
    form = {
        "token": token,
        "token_type_hint": token_type_hint,
        "client_id": client_id,
        "client_secret": client_secret,
    }
    try:
        await service.revoke(form, request.headers.get("authorization"), request_context(request))
    except OAuthError as e:
        return _oauth_error(e)
    return JSONResponse(content={}, headers=_NO_STORE)


@router.get("/logout")
async def logout(
    request: Request,
    service: OAuthServiceDep,
    id_token_hint: Optional[str] = None,
    client_id: Optional[str] = None,
    post_logout_redirect_uri: Optional[str] = None,
    state: Optional[str] = None,
    access_token: Optional[str] = Cookie(None),
    refresh_token: Optional[str] = Cookie(None),
):
    """RP-initiated logout: ends the SSO browser session (only for an
    id_token_hint of this browser's session), then redirects to a registered
    post_logout_redirect_uri (or the SSO login page)."""
    redirect_to, ended = await service.end_session(
        id_token_hint,
        client_id,
        post_logout_redirect_uri,
        state,
        access_token,
        refresh_token,
        request_context(request),
    )
    response = RedirectResponse(redirect_to, status_code=302)
    if ended:
        clear_auth_cookies(response)
    return response
