📘 Rockel DB – Production Runbook

System: Rockel Shipping – Rockel DB
Environment: Production
Server: Ubuntu 22.04 (DigitalOcean VPS)
Owner: Trevor Palmer
Last updated: (today)

1️⃣ System Overview
Stack

Node.js (Express)

SQLite (file-based)

PM2 (process manager)

Nginx (reverse proxy)

HTTPS (Let’s Encrypt)

DigitalOcean Spaces (off-site backups)

External uptime monitoring (UptimeRobot)

Key URLs

Health check:

https://malachi.app/health


Admin / Portal:

https://malachi.app/

2️⃣ Where Critical Things Live (memorise this)
Application code
/var/www/rockel-login

Persistent data (MOST IMPORTANT)
/var/www/rockel-data
/var/www/rockel-uploads


If these two directories are safe, the business survives.

Local backups
/var/backups/rockel

Off-site backups (DigitalOcean Spaces)
s3://rockel-backups

3️⃣ Normal Operations
Check app status
pm2 status

View live logs
pm2 logs rockel --lines 100

Restart app (safe)
pm2 restart rockel

Reload Nginx (safe)
sudo systemctl reload nginx

4️⃣ Redeploy Procedure (Safe & Repeatable)

Use only this process.

sudo -u trevor -H /usr/local/bin/rockel-redeploy.sh


What this does:

git pull

Install prod dependencies

Restart PM2 with updated env

Health check

If redeploy fails
pm2 logs rockel

5️⃣ Backups (Critical Section)
Daily backups (automatic)

Local: every day at 02:15

Off-site: uploaded to DigitalOcean Spaces

Retention:

Local: 14 days

Spaces: 30 days (weekly prune)

Manually trigger a backup
sudo /usr/local/bin/rockel-backup.sh

Check backup log
sudo tail -n 100 /var/log/rockel-backup.log

Verify off-site backups
sudo aws --endpoint-url https://lon1.digitaloceanspaces.com s3 ls s3://rockel-backups

6️⃣ Restore Procedure (Emergency)

⚠️ Always stop the app before restoring.

Full restore from local backup
pm2 stop rockel
sudo tar -xzf /var/backups/rockel/rockel_YYYY-MM-DD_HHMMSS.tar.gz -C /
sudo chown -R trevor:trevor /var/www/rockel-data /var/www/rockel-uploads
pm2 start rockel

Restore from DigitalOcean Spaces
sudo aws --endpoint-url https://lon1.digitaloceanspaces.com s3 cp \
  s3://rockel-backups/rockel_YYYY-MM-DD_HHMMSS.tar.gz /tmp/

pm2 stop rockel
sudo tar -xzf /tmp/rockel_YYYY-MM-DD_HHMMSS.tar.gz -C /
sudo chown -R trevor:trevor /var/www/rockel-data /var/www/rockel-uploads
pm2 start rockel

7️⃣ Monitoring & Alerts
External uptime monitoring

Service: UptimeRobot

Endpoint monitored:

https://malachi.app/health


Alerts:

Email on DOWN

Email on recovery

SSL expiry alerts enabled

If alert fires

SSH into server

Check:

pm2 status
sudo systemctl status nginx


Review logs:

pm2 logs rockel --lines 100

8️⃣ Common Failure Scenarios
❌ App down, server up
pm2 restart rockel

❌ Nginx 502 / 504
sudo systemctl restart nginx
pm2 restart rockel

❌ Disk full
df -h
du -h /var/log | sort -h


Clear logs if needed.

❌ Database locked / corrupted

Stop app

Restore latest backup

Restart

9️⃣ Security Notes

Port 3000 is internal only

SSH keys only (no passwords)

Fail2Ban enabled

HTTPS enforced

Secrets stored only in .env

Spaces keys stored only in root AWS config

🔟 Golden Rules (Read This Under Pressure)

Never edit production data directly

Always stop PM2 before restoring backups

Backups first, changes second

If unsure — do nothing and inspect logs

Data directories matter more than code

11️⃣ Future Improvements (Planned)

Staging environment

Move data paths fully to env vars

App-level structured logging

Internal monitoring dashboard

CI/CD pipeline

✅ Runbook Status

✔ Server hardened
✔ Backups automated
✔ Off-site recovery proven
✔ Monitoring active
✔ Redeploy process documented

Rockel DB is production-ready and operable.
