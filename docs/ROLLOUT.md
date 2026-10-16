# Rollout: hardened SSO + shared SDK

Every repo deploys to production on push to `master`, so the order below
matters. Each step is backward compatible with the one before it; nobody is
logged out at any point (at worst one silent refresh).

## 0. Before you start

1. **Back up SSO Mongo** (`users`, `refresh_tokens`, `roles`).
2. **Unverified users.** `REQUIRE_EMAIL_VERIFICATION=true` blocks login for
   accounts that never verified (the login page offers a resend button). Check
   how many exist:
   ```js
   db.users.countDocuments({ email_verified: { $ne: true } })
   ```
   If that number is surprising, start with `REQUIRE_EMAIL_VERIFICATION=false`
   and turn it on later. The account in `OWNER_EMAIL` is always marked verified
   by bootstrap.
3. **Generate the signing key and put it in the VPS `.env` BEFORE pushing
   sso-backend.** The new image refuses to start in production without it,
   and the deploy replaces the running container — pushing first means an SSO
   outage. The script only needs `cryptography`:
   ```sh
   cd single_sign_on/backend && ./venv/bin/python -m scripts.generate_signing_key
   ```
   Paste the two printed lines into `/srv/docker/apps/sso/.env` together with
   the step 1 settings, then delete them from your terminal history.

## 1. SSO backend + SSO frontend (compatibility mode)

`/srv/docker/apps/sso/.env` — add (keep `JWT_SECRET`):

```env
JWT_SIGNING_ALG=HS256          # old app backends still verify with the shared secret
JWT_ACTIVE_KID=<generated>
JWT_PRIVATE_KEY_B64=<generated>
JWT_ISSUER=https://auth.karanparmar.in/api/auth
JWT_AUDIENCE=                  # empty until step 3
REQUIRE_EMAIL_VERIFICATION=true
TRUSTED_PROXY_HOPS=1
```

`JWT_ALGORITHM` is no longer read; delete it. Then:

1. Push **sso-backend**, wait for the deploy to go green.
2. Push **sso-frontend** (new admin, consent and account screens).
3. Reload Caddy with the new `Caddyfile` (security headers):
   `docker exec caddy caddy reload --config /etc/caddy/Caddyfile`
4. Check:
   ```sh
   curl -s https://auth.karanparmar.in/api/auth/.well-known/jwks.json      # one RSA key
   curl -s https://familyos.karanparmar.in/api/auth/session               # {"authenticated":false,...}
   curl -sI https://familyos.karanparmar.in | grep -i strict-transport    # HSTS present
   ```
   Sign in on each app: the old app builds keep working (same HS256 tokens,
   same cookies, same endpoints).

Existing sessions survive: refresh-token records from before this release
join a session family the first time they are refreshed.

## 2. Apps (one at a time, backend before frontend)

For each of family_os, portfolio, all_projects add to the app `.env` (keep
`SSO_JWT_SECRET` for now):

```env
SSO_ISSUER=https://auth.karanparmar.in/api/auth
SSO_AUDIENCE=karanparmar-apps
SSO_REQUIRE_AUDIENCE=false
SSO_APP_ID=familyos            # portfolio / allprojects
```

**Family OS only — do this first:** its vault encrypts secrets with the value
of `SSO_JWT_SECRET`. Pin that value so step 4 can't break decryption:

```env
VAULT_SECRET_KEY=<exact current value of SSO_JWT_SECRET>
```

Push the backend, then the frontend. Check: sign in, reload after 15+ minutes
(you must stay signed in, no "Sign in" flash), sign out (other tabs follow),
admin pages for an admin and a non-admin.

## 3. Switch SSO to RS256 + audience

`/srv/docker/apps/sso/.env`:

```env
JWT_SIGNING_ALG=RS256
JWT_AUDIENCE=karanparmar-apps
```

`docker compose up -d --force-recreate sso-backend`. New tokens are RS256 with
an audience; HS256 tokens already in browsers stay valid at the apps (they
still have `SSO_JWT_SECRET`) until they expire (≤ 15 min).

## 4. Retire the shared secret (≥ 15 min after step 3)

- Apps: confirm Family OS has `VAULT_SECRET_KEY` set (step 2), then remove
  `SSO_JWT_SECRET`, set `SSO_REQUIRE_AUDIENCE=true`, recreate each backend
  container.
- SSO: remove `JWT_SECRET`, recreate `sso-backend`.

From here no app can mint tokens: only SSO holds the private key.

## 5. Rotate secrets that were stored in plain text

`new_deployment/*/.env.example` contain live credentials. Rotate, then keep
real values only in the VPS `.env` files (or a secret manager):

- Postgres password (shared by all apps), Mongo Atlas user, Garage access keys
- Gmail SMTP app password (SSO + Family OS)
- `OWNER_PASSWORD` — only needed for first bootstrap; remove it from `.env`
- `JWT_SECRET` — retired as a token key in step 4, but its value lives on as
  Family OS `VAULT_SECRET_KEY`. Treat it as a vault key: changing it requires
  re-encrypting vault data first.
- Family OS `ENCRYPTION_KEYS`: add a new key id and make it active, keep the
  old id for decryption until data is re-encrypted. Don't just replace it.

## Signing-key rotation (routine)

```sh
docker run --rm -e JWT_PRIVATE_KEY_B64=<current> -e JWT_ACTIVE_KID=<current kid> \
  ghcr.io/karan-parmar-007/sso-backend:latest python -m scripts.generate_signing_key
```

Put the new `JWT_ACTIVE_KID`/`JWT_PRIVATE_KEY_B64` and the printed
`JWT_PREVIOUS_PUBLIC_KEYS` line into `.env`, recreate `sso-backend`. Apps pick
up the new key automatically (they re-fetch JWKS on an unknown `kid`). Remove
`JWT_PREVIOUS_PUBLIC_KEYS` after a day.

## Rollback

- Step 3/4: set `JWT_SIGNING_ALG=HS256` again (apps must still have
  `SSO_JWT_SECRET`).
- Step 2: redeploy the previous app image; it works against the new SSO.
- Step 1: redeploy the previous SSO image, then delete rotated refresh tokens
  so the old code can't accept them:
  `db.refresh_tokens.deleteMany({ rotated_at: { $ne: null } })`.
