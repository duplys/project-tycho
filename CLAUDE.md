# Project Tycho — Claude Code Notes

## Deployment

The production instance runs on a Hetzner VPS reachable at **https://tycho.vier99.de**.

- Visualiser dashboard: https://tycho.vier99.de (nginx root → port 8000)
- Blog service: `localhost:8001` on the VPS (not yet proxied through nginx)
- Observatory: internal only, no HTTP frontend

To deploy changes: `git pull` on the VPS, then `docker compose up --build -d` from `/srv/project-tycho`.
