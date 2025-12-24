# Rockel DB – Emergency Checklist (Production)

## Confirm outage
- Check uptime monitor alert
- Hit: https://malachi.app/health

## SSH in
ssh trevor@<VPS_IP>

## Basic status
pm2 status
sudo systemctl status nginx --no-pager
df -h

## If app is down (PM2)
pm2 logs rockel --lines 120
pm2 restart rockel
curl -I http://127.0.0.1:3000/health
curl -I https://malachi.app/health

## If Nginx is failing (502/504)
sudo nginx -t
sudo systemctl restart nginx
pm2 restart rockel

## If disk is full
df -h
sudo du -h /var/log | sort -h | tail
# clear old logs carefully (don’t delete data/uploads)

## If DB issue (locked/corrupt symptoms)
pm2 stop rockel
# restore latest known-good backup (local)
ls -1t /var/backups/rockel/rockel_*.tar.gz | head
sudo tar -xzf /var/backups/rockel/<LATEST>.tar.gz -C /
sudo chown -R trevor:trevor /var/www/rockel-data /var/www/rockel-uploads
pm2 start rockel

## Verify backups exist (off-site)
sudo aws --endpoint-url https://lon1.digitaloceanspaces.com s3 ls s3://rockel-backups | tail

## Final validation
pm2 status
curl https://malachi.app/health
