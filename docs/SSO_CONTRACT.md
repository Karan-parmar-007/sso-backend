# SSO integration contract

The SSO (`auth.karanparmar.in`) is the only identity provider for every app on
`*.karanparmar.in`. This document is the contract between SSO and the apps.
Rollout order is in [ROLLOUT.md](ROLLOUT.md).

## 1. Topology

- Caddy routes **`/api/auth*` on every app host** to `sso-backend`. Browsers
  therefore call SSO same-origin (`/api/auth/...`) from any app. In dev, each
  app's Vite proxy does the same (`/api/auth` → `http://localhost:8000`).
- App APIs live under their own prefix (`/api/familyos`, `/api/portfolio`,
  `/api/allprojects`). **Apps never proxy or re-implement `/api/auth/*`.**

## 2. Cookies (set only by SSO, `Domain=.karanparmar.in` in prod, `SameSite=Lax`, `Secure` in prod)

| Cookie | HttpOnly | Path | Lifetime |
|---|---|---|---|
| `access_token` | yes | `/` | 15 min (JWT) |
| `refresh_token` | yes | `/api/auth` | session (≤7 d; browser-session cookie when "remember me" is off) |
| `csrf_token` | no | `/` | same as refresh; stable for the whole session |

Mutating requests that carry session cookies must send `X-CSRF-Token: <csrf_token cookie>`.

## 3. Access token (JWT)

- `RS256`, header `kid`. Public keys: `GET /api/auth/.well-known/jwks.json`.
  (During rollout SSO may still sign `HS256` with the shared secret — see ROLLOUT.)
- Claims:

```jsonc
{
  "iss": "https://auth.karanparmar.in/api/auth",
  "aud": "karanparmar-apps",        // once JWT_AUDIENCE is set
  "sub": "<user id>", "user_id": "<user id>",
  "email": "...", "name": "...", "email_verified": true,
  "role": "owner|super_admin|user|<custom>",   // global role
  "role_name": "...",                           // same value, legacy name
  "roles": { "familyos": ["admin"] },           // app-scoped roles
  "sid": "<session id>", "jti": "...", "iat": 0, "exp": 0,
  "type": "access"
}
```

- `role`/`roles` in the token can be up to 15 min stale. Privileged checks
  must confirm live (the SDK does this).

## 4. SSO endpoints used by apps

All under `/api/auth`. JSON. Browser calls use `credentials: 'include'`.

| Method & path | Purpose |
|---|---|
| `GET /session` | **Always 200.** `{authenticated, user, session_id, access_token_expires_in}`. Refreshes server-side when the access token is missing/expiring/revoked and the refresh cookie is valid (sets new cookies). Clears dead cookies. |
| `POST /refresh` | Rotate tokens (kept for compatibility; prefer `GET /session`). 401 clears cookies. |
| `POST /logout[?everywhere=true]` | Ends the session (refresh cookie identifies it; works with an expired access token). Always clears cookies. Needs CSRF header when cookies are present. |
| `GET /me` | Current user. Accepts the cookie **or** `Authorization: Bearer <access token>`. 401 if the token's session was revoked. Used by app backends for live checks. |
| `GET /sessions`, `DELETE /sessions/{id}`, `DELETE /sessions/others` | Session management (ids are session/family ids). |
| `GET /activity` | The user's own security events. |

`user` object (also returned by `/me`):

```json
{ "id": "…", "name": "…", "email": "…", "email_verified": true,
  "role_name": "user", "app_roles": {"familyos": ["admin"]},
  "created_at": "…", "updated_at": "…" }
```

Login page: `https://auth.karanparmar.in/login?next=<absolute URL on an allowlisted origin>`
(`/signup?next=…` likewise). After login SSO redirects to `next`; if the user is
already signed in it redirects immediately.

## 5. App backends (Python) — use `karan_sso`

Vendored at `<repo>/karan_sso/` (source: `sso-backend/sdk/python`, sync with
`sdk/sync.sh`, never edit the copy). Requires `PyJWT[crypto]`, `httpx`,
`pydantic-settings`.

```python
from karan_sso.fastapi import (
    OptionalIdentityDep, IdentityDep, LiveIdentityDep, AdminDep, OwnerDep,
    require_role, require_app_role, get_sso, CSRFMiddleware,
)
app.add_middleware(CSRFMiddleware, exempt_prefixes=("/health", "/api/<app>/health"))
```

- `IdentityDep`: local JWT verification (JWKS cached), 401 otherwise.
- `AdminDep` / `OwnerDep` / `require_role(...)` / `require_app_role(...)`: live
  check via SSO `/me` (30 s cache) → reflects demotions/revocations; **SSO
  outage = 503, never 403**.
- `AdminDep` = global `owner|super_admin` **or** app role `admin` in `SSO_APP_ID`.
- `SsoIdentity`: `user_id, email, name, email_verified, role, roles, session_id`,
  helpers `is_owner, is_admin, has_app_role(app, role)`.

Env (names unchanged where they existed):

| Var | Value |
|---|---|
| `SSO_BASE_URL` | internal SSO API, e.g. `http://sso-backend:8000/api` |
| `SSO_ISSUER` | `https://auth.karanparmar.in/api/auth` (empty = don't check) |
| `SSO_AUDIENCE` | `karanparmar-apps` (default) |
| `SSO_REQUIRE_AUDIENCE` | `false` until SSO sets `JWT_AUDIENCE`, then `true` |
| `SSO_JWT_SECRET` | legacy HS256 secret — **only during rollout**, then remove |
| `SSO_APP_ID` | `familyos` / `portfolio` / `allprojects` |

Rules for app backends:

1. Delete local copies of `sso_client.py`, JWT decoding, role dependencies and
   CSRF middleware; use the SDK.
2. **Delete app-side `/auth/refresh` and `/auth/logout` proxies** and any
   `/api/auth` mounts — the browser talks to SSO directly. An app may keep its
   own `GET /api/<app>/auth/session` only for app-specific data (e.g. a Family
   OS profile); it must not try to refresh.
3. Never forward the browser's whole Cookie header to SSO; the SDK sends the
   access token as a bearer.
4. `docs_url/redoc_url/openapi_url = None` when `ENVIRONMENT == "production"`.
5. CORS: explicit origins; no localhost in production.

## 6. App frontends — use `sso-client.ts`

Vendored at `src/lib/sso/sso-client.ts` (source: `sso-backend/sdk/web`).

```ts
import { createSsoClient } from '#/lib/sso/sso-client'
export const sso = createSsoClient({ ssoUrl: import.meta.env.VITE_SSO_URL })
```

1. **Who is signed in:** `sso.getSession()` (single-flight; refreshes
   server-side). Show a neutral placeholder while pending — never flash
   "Sign in" for a signed-in user.
2. **App API 401:** `await sso.refresh()`; retry once if `true`; otherwise
   treat as signed out (protected page → `sso.redirectToLogin()`).
3. **Login/Signup buttons:** `sso.loginUrl(returnPath)` / `sso.signupUrl(...)`
   with the page the user should land on (keep path + query).
4. **Logout:** `await sso.logout()` then clear app caches and navigate to a
   public page. `sso.onSessionChange` fires on logout/login in other tabs —
   clear caches there too.
5. CSRF: send `X-CSRF-Token: sso.csrfToken()` on mutating app API requests.
6. Role-gated UI: `isAppAdmin(user, '<app>')` etc. (UI only; the backend enforces).

## 7. OAuth 2.0 / OpenID Connect (for clients outside the shared cookie)

Issuer `https://auth.karanparmar.in/api/auth`. Discovery:
`GET /api/auth/.well-known/openid-configuration`.

| Endpoint | Notes |
|---|---|
| `GET /api/auth/oauth/authorize` | `response_type=code`, `client_id`, `redirect_uri` (exact match), `scope` (must include `openid`), `state`, `nonce`, `code_challenge` + `code_challenge_method=S256` (**required**), optional `prompt=none|login|consent`. Not signed in → 302 to SSO frontend `/login?next=<this URL>`. Third-party client without consent → 302 to SSO frontend `/consent?request=<id>`. |
| `GET /api/auth/oauth/consent/{request_id}` | (SSO frontend) `{client: {client_id, name}, scopes: [...], user: {email}}` |
| `POST /api/auth/oauth/consent/{request_id}` | (SSO frontend, cookie + CSRF) body `{approve: bool}` → `{redirect_to}` |
| `POST /api/auth/oauth/token` | form-encoded. `grant_type=authorization_code` (`code`, `redirect_uri`, `client_id`, `code_verifier`, client secret via Basic auth or `client_secret` for confidential clients) or `grant_type=refresh_token` (rotating, same reuse detection as sessions; requires `offline_access`). Returns `access_token` (RS256 JWT, `aud=client_id`, `type=oauth_access`), `id_token`, `token_type=Bearer`, `expires_in`, `scope`, optional `refresh_token`. |
| `GET/POST /api/auth/oauth/userinfo` | Bearer OAuth access token → standard claims per scope. |
| `POST /api/auth/oauth/revoke` | RFC 7009. |
| `GET /api/auth/oauth/logout` | RP-initiated logout: `id_token_hint` (required to end the session, and its `sid` must be this browser's session — otherwise nothing is ended and the user lands on `/account`), `post_logout_redirect_uri` (registered), `state`. |
| `GET /api/auth/.well-known/jwks.json` | Signing keys. |

Behaviour details:

- Authorization responses also carry `iss` (RFC 9207). Errors before
  `client_id` + `redirect_uri` are validated are returned as 400 JSON, never redirected.
- `prompt=login` / an exceeded `max_age` end the current SSO session and send the
  user to `/login`; the `next` URL drops `prompt=login`/`max_age` (no loop).
  `auth_time` = start of the SSO session.
- Every grant is bound to the SSO session that authorized it (`sid`). Ending that
  session (logout, session revocation, password change) invalidates the grant:
  userinfo rejects its access tokens and its refresh token stops working. OAuth
  refresh tokens never outlive that session.
- A replayed authorization code revokes the refresh token issued from it.
  Access tokens are self-contained JWTs (15 min); `/revoke` accepts them as a no-op.
- `/token` with `grant_type=refresh_token` accepts an optional narrower `scope`.
- `/logout` ends the SSO session only for an `id_token_hint` whose `sid` is the
  browser's current session (prevents cross-site forced logout). `client_id`,
  if sent, must match the hint's audience.
- A client's `allowed_scopes` must include `openid`. Deleting a client revokes
  its refresh tokens and consents.

Clients are managed in SSO admin (`/api/auth/admin/clients`). First-party apps
on `*.karanparmar.in` keep using the shared cookie; OIDC is for anything else.
