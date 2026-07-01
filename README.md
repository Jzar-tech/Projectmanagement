# Team Notes Board

A lightweight private project board for a small internal team.

## Features
- Password-protected accounts
- Private invite code for new team members
- Shared projects
- Kanban board: Backlog, In Progress, Done
- Shared internal notes
- File-based JSON storage; no database server required
- Runs only on `127.0.0.1` and is exposed through Nginx

## Windows VPS installation

1. Install Node.js LTS and Nginx for Windows.
2. Copy this folder to `C:\apps\team-notes-board`.
3. Open PowerShell:

```powershell
cd C:\apps\team-notes-board
copy .env.example .env
notepad .env
npm install
npm start
```

Open `http://127.0.0.1:3000` on the VPS to test.

## Run continuously with PM2

```powershell
npm install -g pm2
cd C:\apps\team-notes-board
pm2 start server.js --name team-notes-board
pm2 save
pm2 startup
```

Run the command printed by `pm2 startup` as Administrator.

## Nginx configuration

Add this server block inside the `http` section of `C:\nginx\conf\nginx.conf`:

```nginx
server {
    listen 80;
    server_name notes.yourdomain.com;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Then reload Nginx:

```powershell
cd C:\nginx
nginx.exe -t
nginx.exe -s reload
```

Create an `A` record for `notes.yourdomain.com` pointing to the VPS public IP.

## HTTPS

Use Win-ACME to issue a Let's Encrypt certificate, then add the generated HTTPS bindings/configuration to Nginx. Do not expose the login over public HTTP for production use.

## Security checklist
- Change `SESSION_SECRET`, `INVITE_CODE`, and admin password before first start.
- Keep Windows Firewall open only for ports 80 and 443; do not expose port 3000.
- Use HTTPS.
- Back up `data\db.json` daily.
- This starter uses the default in-memory session store, which is acceptable for one small app instance. For larger usage, replace it with Redis or a persistent session store.
