#!/usr/bin/env bash
# Copy the shared SSO SDKs into every app repo (vendoring).
#
#   sdk/sync.sh            # copy
#   sdk/sync.sh --check    # exit 1 if any vendored copy has drifted
#
# Expects the usual checkout layout under one parent folder (override with
# SSO_APPS_ROOT): single_sign_on/backend (this repo), family_os/…, new_backend,
# new_frontend/portfolio_frontend, all_projects/…
set -euo pipefail

SDK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="${SSO_APPS_ROOT:-$(cd "$SDK_DIR/../../.." && pwd)}"

PY_TARGETS=(
  "family_os/backend/karan_sso"
  "new_backend/karan_sso"
  "all_projects/backend/karan_sso"
)
WEB_TARGETS=(
  "family_os/frontend/family_os/src/lib/sso/sso-client.ts"
  "new_frontend/portfolio_frontend/src/lib/sso/sso-client.ts"
  "all_projects/frontend/all_projects/src/lib/sso/sso-client.ts"
  "single_sign_on/frontend/single_sign_on_frontend/src/lib/sso/sso-client.ts"
)

check=false
[[ "${1:-}" == "--check" ]] && check=true
status=0

for target in "${PY_TARGETS[@]}"; do
  dest="$ROOT/$target"
  [[ -d "$(dirname "$dest")" ]] || { echo "skip (missing repo): $target"; continue; }
  if $check; then
    diff -rq --exclude=__pycache__ "$SDK_DIR/python/karan_sso" "$dest" >/dev/null 2>&1 \
      || { echo "DRIFT: $target"; status=1; }
  else
    rm -rf "$dest"
    cp -r "$SDK_DIR/python/karan_sso" "$dest"
    find "$dest" -name __pycache__ -prune -exec rm -rf {} +
    echo "synced: $target"
  fi
done

for target in "${WEB_TARGETS[@]}"; do
  dest="$ROOT/$target"
  repo_src="$ROOT/${target%%/src/*}/src"
  [[ -d "$repo_src" ]] || { echo "skip (missing repo): $target"; continue; }
  if $check; then
    cmp -s "$SDK_DIR/web/sso-client.ts" "$dest" || { echo "DRIFT: $target"; status=1; }
  else
    mkdir -p "$(dirname "$dest")"
    cp "$SDK_DIR/web/sso-client.ts" "$dest"
    echo "synced: $target"
  fi
done

exit $status
