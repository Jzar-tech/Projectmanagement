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

## Production workspace model

The app now supports a Jira-style shared workspace:

- Admins create users, teams, and projects.
- Teams contain multiple employees and an optional team lead.
- Projects can be assigned to one or more teams plus direct members.
- Non-admin users only see projects where they are directly assigned or belong to an allowed team.
- Tasks move through Backlog, In Progress, Review, and Done.
- Each task supports assignee changes, priority, labels, estimates, time logging, and work notes.
- Project notes are shared only with users who can access that project.

Admin pages:

- `/admin/users` manages employee accounts, roles, titles, departments, and disabled status.
- `/admin/teams` manages teams, leads, and team membership.
- `/projects` lets admins create projects and assign access.

## Safe redeploy rule

User, team, project, task, note, and time log data is stored in `data/db.json`. Code deployments must preserve:

```bash
/home/deploy/projectmanagement/data
/home/deploy/projectmanagement/.env
/home/deploy/projectmanagement/logs
```

Replacing code files is safe as long as `data/db.json` is not deleted. The current deploy process keeps `data/` and `.env` untouched.
