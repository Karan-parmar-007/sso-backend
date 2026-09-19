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

Token cleanup runs at midnight (`Asia/Kolkata`) via APScheduler. Owner can also `POST /api/v1/admin/cleanup-tokens`.

## Cross-app login return (`?next=`)

Other apps (e.g. portfolio) send users here with:

`http://localhost:5173/login?next=http%3A%2F%2Flocalhost%3A5174%2Fadmin`

After a successful login the SSO frontend redirects to `next` **only if** its
origin is allowlisted (`VITE_RETURN_ORIGINS` on the frontend, same set as
`CORS_ORIGINS` here). That prevents open redirects. Apps verify the JWT locally
and call `GET /api/v1/auth/me` (backend-to-backend with cookies) for live roles.
