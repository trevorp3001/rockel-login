# 🚦 Staging → Production Promotion Runbook

This document defines the **only approved process** for promoting code from staging to production
for the Rockel platform.

---

## 🔒 Ground Rules

- ❌ Never test directly on production
- ❌ Never deploy without a verified backup
- ❌ Never deploy if staging health checks fail
- ✅ All deployments are Git-based (no manual file edits)

---

## 1. Preconditions (STAGING)

Run on staging server:

```bash
cd /var/www/rockel-login-staging
git status
pm2 status
curl -sS https://staging.malachi.app/health
