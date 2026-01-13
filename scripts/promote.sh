#!/usr/bin/env bash
set -euo pipefail

# Rockel Promotion Script (staging -> production)
# Usage:
#   sudo ./scripts/promote.sh
#   sudo ./scripts/promote.sh --dry-run

DRY_RUN=0
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=1

APP_USER="trevor"
REPO_DIR="/var/www/rockel-login"
PM2_APP="rockel"

# Defaults (can be overridden by /etc/rockel/promote.env)
TAG_PREFIX="${TAG_PREFIX:-prod}"

PROD_LOCAL_HEALTH="${PROD_LOCAL_HEALTH:-http://127.0.0.1:3000/health}"
PROD_PUBLIC_HEALTH="${PROD_PUBLIC_HEALTH:-https://malachi.app/health}"
STAGING_HEALTH_URL="${STAGING_HEALTH_URL:-https://staging.malachi.app/health}"

BACKUP_SCRIPT="${BACKUP_SCRIPT:-/usr/local/bin/rockel-backup.sh}"
SPACES_ENDPOINT="${SPACES_ENDPOINT:-https://lon1.digitaloceanspaces.com}"
SPACES_BUCKET="${SPACES_BUCKET:-s3://rockel-backups}"

# Load secrets / overrides
ENV_FILE="/etc/rockel/promote.env"
if [[ -f "$ENV_FILE" ]]; then
  # shellcheck disable=SC1090
  source "$ENV_FILE"
fi

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "ERROR: Missing command: $1"; exit 1; }
}

run() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "DRY RUN: $*"
  else
    eval "$@"
  fi
}

as_app_user() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "DRY RUN: sudo -u $APP_USER -H bash -lc \"$*\""
  else
    sudo -u "$APP_USER" -H bash -lc "$*"
  fi
}

wait_for_url() {
  local url="$1"
  local tries="${2:-25}"
  local delay="${3:-1}"

  for _ in $(seq 1 "$tries"); do
    if curl -fsS "$url" >/dev/null; then
      return 0
    fi
    sleep "$delay"
  done

  return 1
}

rollback_to_sha() {
  local sha="$1"
  echo "Rolling back to ${sha} ..."
  as_app_user "cd $REPO_DIR && git reset --hard $sha"
  as_app_user "cd $REPO_DIR && npm ci --omit=dev"
  run "sudo -u $APP_USER -H bash -lc 'pm2 restart $PM2_APP --update-env'"
  sleep 2
}

echo "== Rockel Promote =="
echo "Dry-run: $DRY_RUN"
echo

require_cmd curl
require_cmd git
require_cmd npm
require_cmd pm2
require_cmd aws

[[ -d "$REPO_DIR/.git" ]] || { echo "ERROR: Not a git repo: $REPO_DIR"; exit 1; }
[[ -x "$BACKUP_SCRIPT" ]] || { echo "ERROR: Backup script missing/not executable: $BACKUP_SCRIPT"; exit 1; }

echo "[1/8] Checking staging health"
if [[ -n "${STAGING_AUTH:-}" ]]; then
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "DRY RUN: curl -fsS -u ****** ${STAGING_HEALTH_URL} >/dev/null"
  else
    curl -fsS -u "${STAGING_AUTH}" "${STAGING_HEALTH_URL}" >/dev/null
  fi
else
  run "curl -fsS ${STAGING_HEALTH_URL} >/dev/null"
fi
echo "OK"

echo "[2/8] Running backup"
run "sudo $BACKUP_SCRIPT >/dev/null"

echo "[3/8] Verifying Spaces access"
run "aws --endpoint-url ${SPACES_ENDPOINT} s3 ls ${SPACES_BUCKET} | tail -n 3"

# capture current SHA for rollback
PREV_SHA="$(sudo -u "$APP_USER" -H bash -lc "cd $REPO_DIR && git rev-parse HEAD")"

echo "[4/8] Merge staging -> main and push"
as_app_user "cd $REPO_DIR && git fetch origin --prune"

if [[ "$DRY_RUN" -eq 0 ]]; then
  DIRTY="$(sudo -u "$APP_USER" -H bash -lc "cd $REPO_DIR && git status --porcelain")"
  [[ -z "$DIRTY" ]] || { echo "ERROR: Working tree not clean"; exit 1; }
fi

# Make sure both branches exist
as_app_user "cd $REPO_DIR && git show-ref --verify --quiet refs/remotes/origin/staging"
as_app_user "cd $REPO_DIR && git show-ref --verify --quiet refs/remotes/origin/main"

# Checkout main and fast-forward to origin/main first
as_app_user "cd $REPO_DIR && git checkout main"
as_app_user "cd $REPO_DIR && git reset --hard origin/main"

# Merge staging into main (will stop if conflicts)
as_app_user "cd $REPO_DIR && git merge --no-edit origin/staging"

# Push updated main
as_app_user "cd $REPO_DIR && git push origin main"


echo "[5/8] npm ci"
as_app_user "cd $REPO_DIR && npm ci --omit=dev"

echo "[6/8] pm2 restart"
run "sudo -u $APP_USER -H bash -lc 'pm2 restart $PM2_APP --update-env'"
sleep 2

echo "[7/8] Local health"
if ! wait_for_url "$PROD_LOCAL_HEALTH" 40 1; then
  echo "❌ Local health failed: $PROD_LOCAL_HEALTH"
  rollback_to_sha "$PREV_SHA"
  wait_for_url "$PROD_LOCAL_HEALTH" 40 1 || { echo "❌ Rollback failed locally"; exit 1; }
fi

echo "[8/8] Public health"
if ! wait_for_url "$PROD_PUBLIC_HEALTH" 40 1; then
  echo "❌ Public health failed: $PROD_PUBLIC_HEALTH"
  rollback_to_sha "$PREV_SHA"
  wait_for_url "$PROD_PUBLIC_HEALTH" 40 1 || { echo "❌ Rollback failed publicly"; exit 1; }
fi

# release tag
if [[ "$DRY_RUN" -eq 0 ]]; then
  TS="$(date +%Y%m%d-%H%M%S)"
  as_app_user "cd $REPO_DIR && git tag -a ${TAG_PREFIX}-${TS} -m 'Promote to production ${TS}'"
  as_app_user "cd $REPO_DIR && git push --tags"
fi

echo "✅ Promote complete"
