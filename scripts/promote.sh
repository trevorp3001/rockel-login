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

PROD_LOCAL_HEALTH="http://127.0.0.1:3000/health"
PROD_PUBLIC_HEALTH="https://malachi.app/health"
STAGING_HEALTH_URL="${STAGING_HEALTH_URL:-https://staging.malachi.app/health}"

BACKUP_SCRIPT="/usr/local/bin/rockel-backup.sh"
SPACES_ENDPOINT="${SPACES_ENDPOINT:-https://lon1.digitaloceanspaces.com}"
SPACES_BUCKET="${SPACES_BUCKET:-s3://rockel-backups}"

ENV_FILE="/etc/rockel/promote.env"
if [[ -f "$ENV_FILE" ]]; then
  source "$ENV_FILE"
fi

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

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "ERROR: Missing command: $1"; exit 1; }
}

echo "== Rockel Promote =="
echo "Dry-run: $DRY_RUN"
echo

require_cmd curl
require_cmd git
require_cmd npm
require_cmd pm2
require_cmd aws

[[ -d "$REPO_DIR/.git" ]] || { echo "ERROR: Not a git repo"; exit 1; }
[[ -x "$BACKUP_SCRIPT" ]] || { echo "ERROR: Backup script missing"; exit 1; }

echo "[1/8] Checking staging health"
if [[ -n "${STAGING_AUTH:-}" ]]; then
  run "curl -fsS -u ${STAGING_AUTH} ${STAGING_HEALTH_URL} >/dev/null"
else
  run "curl -fsS ${STAGING_HEALTH_URL} >/dev/null"
fi
echo "OK"

echo "[2/8] Running backup"
run "sudo $BACKUP_SCRIPT >/dev/null"

echo "[3/8] Verifying Spaces access"
run "aws --endpoint-url ${SPACES_ENDPOINT} s3 ls ${SPACES_BUCKET} | tail -n 3"

echo "[4/8] Git pull"
as_app_user "cd $REPO_DIR && git fetch origin"
if [[ "$DRY_RUN" -eq 0 ]]; then
  DIRTY="$(sudo -u "$APP_USER" -H bash -lc "cd $REPO_DIR && git status --porcelain")"
  [[ -z "$DIRTY" ]] || { echo "ERROR: Working tree not clean"; exit 1; }
fi
as_app_user "cd $REPO_DIR && git pull origin main"

echo "[5/8] npm ci"
as_app_user "cd $REPO_DIR && npm ci --omit=dev"

echo "[6/8] pm2 restart"
as_app_user "pm2 restart $PM2_APP --update-env"

echo "[7/8] Local health"
run "curl -fsS ${PROD_LOCAL_HEALTH} >/dev/null"

echo "[8/8] Public health"
run "curl -fsS ${PROD_PUBLIC_HEALTH} >/dev/null"

echo "✅ Promote complete"
