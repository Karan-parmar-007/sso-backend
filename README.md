# SSO Auth Backend

Mongo-only FastAPI SSO for `auth.karanparmar.in`. Layout follows the portfolio backend: routes stay thin, access checks live in dependencies, services run API logic, models own Mongo.

## Layout

```
app/
  api/
    dependencies.py   # Mongo + service injection (like portfolio app/api/dependencies.py)
    auth.py           # auth routes — no DB, no extra auth checks
    admin.py          # owner-only routes
    main_router.py
  dependencies/       # API access guards only
    jwt_auth.py       # require_auth  (cookies + JWT)
    role.py           # require_role(role_name=...) — auth first, then role
    owner.py          # require_owner — auth first, then owner
  models/             # Mongo only (find/insert/update/delete)
  services/           # business logic; calls models, never raw collections
  schemas/            # request / response
  db/                 # connection + indexes
  cron/               # APScheduler jobs (call utils/models, no extra logic)
  utils/
  middleware/
```

## Rules

1. **`app/api/dependencies.py`**  
   Injects Mongo (`MongoDBDep`) and services (`AuthServiceDep`, `AdminServiceDep`). Same job as portfolio `app/api/dependencies.py`.

2. **`app/dependencies/`**  
   Only “can this caller hit this route?”  
   - `require_auth`  
   - `require_role("user")` → runs `require_auth`, then checks role  
   - `require_owner` → runs `require_auth`, then checks owner  
   Do **not** put DB/service wiring here. Do **not** re-check auth/role inside the route if the dependency already did.

3. **Routes** stay thin:

   ```python
   user: Annotated[Dict[str, Any], Depends(require_auth)]
   user: Annotated[Dict[str, Any], Depends(require_owner)]
   service: AuthServiceDep
   ```

4. **Services** = API logic (validation, emails, tokens, orchestration).  
   **Models** = all Mongo reads/writes. Services must not call `db.users.find_one` directly.

5. **Cron** files only schedule. Cleanup implementation is in utils + models.

## Quick start

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python bootstrap.py
uvicorn main:app --reload --port 8000
```

Token cleanup runs at midnight (`Asia/Kolkata`) via APScheduler (TTL indexes do
most of the work). Owner can also `POST /api/auth/admin/cleanup-tokens`.

## Security model

- **Tokens:** RS256 access JWTs (15 min, `kid` header, published at
  `/api/auth/.well-known/jwks.json`) carrying `iss`, `aud`, `sid`, `jti`, `role`
  and app-scoped `roles`. Keys: `JWT_PRIVATE_KEY_B64` (+ `JWT_PREVIOUS_PUBLIC_KEYS`
  during rotation) — `python -m scripts.generate_signing_key`.
- **Sessions:** one login = one session (`family_id`, exposed as `sid`).
  Refresh tokens rotate atomically; parallel refreshes inside
  `REFRESH_REUSE_GRACE_SECONDS` share the session; replaying an older token
  revokes the whole session. `require_auth` rejects access tokens whose session
  was revoked. `GET /api/auth/session` refreshes server-side, so apps never show a
  signed-in user as signed out.
- **Accounts:** login lockout per email and per IP (`rate_limits`, atomic),
  constant-time login, enumeration-safe signup / forgot-password / resend,
  email verification required, re-authentication for password and email changes,
  password/email changes sign out other sessions and notify by email, new-device
  sign-in alerts, admin resets send a single-use link (no temporary passwords).
- **Audit:** `audit_events` (TTL `AUDIT_RETENTION_DAYS`) — `GET /api/auth/activity`
  for users, `GET /api/auth/admin/audit` for the owner.
- **Apps & OIDC:** registered applications (`clients`) define app-scoped roles
  and OAuth/OIDC clients (authorization code + PKCE, discovery under the issuer).

The integration contract for apps is [docs/SSO_CONTRACT.md](docs/SSO_CONTRACT.md);
production rollout steps are in [docs/ROLLOUT.md](docs/ROLLOUT.md).

## Shared SDKs (`sdk/`)

- `sdk/python/karan_sso` — FastAPI dependencies, token verification (JWKS),
  live role checks, CSRF middleware for app backends.
- `sdk/web/sso-client.ts` — browser client (session, refresh, login URLs,
  logout, cross-tab sync) for app frontends.

Apps vendor copies; **edit only here**, then run `sdk/sync.sh` (and
`sdk/sync.sh --check` to detect drift).

## Tests

```bash
pip install -r requirements.txt -r requirements-dev.txt
TEST_MONGO_URI=mongodb://127.0.0.1:27017 python -m pytest -q   # real MongoDB, temp DB per test
(cd sdk/python && PYTHONPATH=. python -m pytest -q)
```

CI runs both before every deploy.

## Cross-app login return (`?next=`)

Apps send users to `https://auth.karanparmar.in/login?next=<absolute URL>`.
After login the SSO frontend redirects to `next` **only if** its origin is
allowlisted (`VITE_RETURN_ORIGINS`, same set as `CORS_ORIGINS`), preventing open
redirects.
