# Project Tycho — Claude Code Notes

## Deployment

The production instance runs on a Hetzner VPS reachable at **https://tycho.vier99.de**.

- Visualiser dashboard: https://tycho.vier99.de (nginx root → port 8000)
- Blog service: https://tycho.vier99.de/blog/ (proxied from `localhost:8001`)
- Observatory: internal only, no HTTP frontend

Nginx site config: `/etc/nginx/sites-available/vier99.de` (symlinked to `sites-enabled/vier99.de`).

To deploy changes: `git pull` on the VPS, then `docker compose up --build -d` from `/srv/project-tycho`.

## Collaboration style

Be direct and honest, including when the answer is "don't bother". If a test, abstraction, or feature isn't worth its cost, say so and explain why — don't default to "yes" just because it's technically possible.
