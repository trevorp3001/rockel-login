# Rockel Shipping Platform — Deployment Notes (Ubuntu VPS)

These notes describe, in order, what to do when you’re ready to deploy the Rockel Shipping platform to a fresh Ubuntu VPS.

You can follow this like a checklist.

---

## 0. Prerequisites (Before Buying a VPS)

- **Local app status**
  - `npm run dev` works on Windows
  - `npm run start:prod` works on Windows
  - `/health` endpoint returns JSON in both modes
- **Git repo** is clean:
  - `.gitignore` excludes: `.env`, `data/`, `uploads/`, `node_modules/`
- **Config files**
  - `.env.example` exists and is up to date
  - `.env` works locally, but is **NOT** committed to Git

When all of the above is true, you’re ready to move to a server.

---

## 1. Buy a VPS and Set Up DNS

1. Choose a provider (e.g. DigitalOcean, Hetzner, Linode, OVH, etc.).
2. Create a small **Ubuntu 22.04** VPS:
   - 1–2 vCPU
   - 2–4 GB RAM
   - 40+ GB SSD
3. Note down:
   - The server’s **public IP address** (e.g. `203.0.113.10`)
4. In your domain registrar’s DNS panel:
   - For `rockelshippingcompany.com` (or your chosen domain), create an **A record**:
     - Name: `@`
     - Value: `YOUR_SERVER_IP`
   - Optionally create `www` → same IP.

Propagation can take anywhere from minutes to a couple of hours, but we don’t need to wait to continue the server setup.

---

## 2. First Login to the Server (SSH from Windows)

1. On Windows, open **PowerShell**.
2. Connect to the server as `root` (your provider will give you the password or an SSH key setup):

   ```powershell
   ssh root@YOUR_SERVER_IP
