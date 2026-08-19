# BreachSentinel

Threat Intelligence & Data Leak Monitoring Platform.

**Stack:** Django + DRF · React (Vite) · Go OSINT microservice · PostgreSQL · Redis

## Quick start

```bash
# 1. Configure environment (never commit .env)
cp .env.example .env

# 2. Edit .env — at minimum set DJANGO_SECRET_KEY and POSTGRES_PASSWORD

# 3. Run — dev is the default (frontend hot-reload, no image build/wait)
docker compose up -d
```

### Dev vs. Prod

`docker-compose.override.yml` is auto-loaded and makes **dev the default**: the
frontend runs the Vite dev server with hot-reload from bind-mounted source, so UI
changes appear instantly without rebuilding any image.

```bash
# Dev (default): frontend hot-reload on :3000, backend + source bind-mounted
docker compose up -d
docker compose logs -f frontend-dev            # dev server logs
docker compose exec frontend-dev npx vitest run # frontend tests

# Prod: build the real nginx frontend (passing -f skips the dev override)
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
```

### Deploy to a shared VPS (custom port, no conflicts)

SSH uses the same key as NewsCrawler (`Host breachsentinel` in `~/.ssh/config`).
From the Windows project root, sync and operate without pasting commands:

```powershell
# Sync changed files to ~/BreachSentinel on the VPS
powershell -File deploy/vps/sync_to_vps.ps1

# Sync + auto-tune workers / translation providers
powershell -File deploy/vps/sync_to_vps.ps1 -Optimize

# One-off remote command
powershell -File deploy/vps/sync_to_vps.ps1 -Remote "docker compose -f docker-compose.yml -f docker-compose.vps.yml ps"
ssh breachsentinel "cd ~/BreachSentinel && bash deploy/vps/verify_vps.sh"
```

`docker-compose.vps.yml` publishes **only** the UI (default `:3100`, set via
`FRONTEND_PORT`) and keeps every other service on the internal Docker network,
so it never clashes with other apps on the host. `deploy/vps/deploy.sh` hardens
`.env` (DEBUG off, fresh SECRET_KEY / DB / Redis secrets, host/CSRF for the VPS
IP), auto-tunes worker concurrency for the host, and brings the stack up.

Title translation priority on VPS: **Google → shared NewsCrawler Ollama**
(`nc-ollama` / `qwen2.5:3b` on `newscrawler_default`) → MyMemory last resort.
BreachSentinel does **not** start a second Ollama container. Google 429 opens a
short circuit so the batch falls through to the shared Ollama.

```bash
# On the VPS, from the project root:
bash deploy/vps/deploy.sh                       # UI on http://<vps-ip>:3100
FRONTEND_PORT=8090 bash deploy/vps/deploy.sh    # choose a different UI port

# Optional: replace the fresh VPS DB with a local pg_dump. This preserves all
# data and the existing Django password hashes exactly.
bash deploy/vps/restore_from_local.sh

# Verify DB, migrations, Celery tasks, internal services, UI and API proxy.
bash deploy/vps/verify_vps.sh

docker compose -f docker-compose.yml -f docker-compose.vps.yml logs -f
docker compose -f docker-compose.yml -f docker-compose.vps.yml down
```

| Service   | URL                          |
|-----------|------------------------------|
| Frontend  | http://localhost:3000        |
| Backend   | http://localhost:8000        |
| API Docs  | http://localhost:8000/api/docs/ |
| Health    | http://localhost:8000/api/health/ |
| OSINT     | http://localhost:8080/health |

## Project layout

```
BreachSentinel/
├── backend/           # Django + DRF + Celery
├── frontend/          # React (Vite) + MUI
├── services/osint/    # Go high-concurrency OSINT engine
├── docker-compose.yml           # base services
├── docker-compose.override.yml  # dev default: frontend hot-reload (auto-loaded)
├── docker-compose.prod.yml      # explicit prod: built nginx frontend
├── .env.example
└── .gitignore
```

## API (Phase 2)

Base path: `/api/v1/` (requires authentication — create a user via `createsuperuser`).

| Resource | Endpoint |
|----------|----------|
| Tags | `/api/v1/tags/` |
| Threat actors | `/api/v1/threat-actors/` |
| Indicators (IOCs) | `/api/v1/indicators/` |
| Threats (The Wire) | `/api/v1/threats/` |
| Data leaks | `/api/v1/leaks/` |
| Compromised credentials | `/api/v1/credentials/` |

Swagger UI: http://localhost:8000/api/docs/

Credential passwords are **write-only** in API responses (`password_present` + `password_fingerprint` only).

## Workers (Phase 3)

Background jobs via Celery + Redis (worker + beat).

| Action | Endpoint |
|--------|----------|
| Worker health | `GET /api/v1/workers/health/` |
| Parse stealer dump | `POST /api/v1/workers/parse-stealer/` |
| Ingest intel feeds | `POST /api/v1/workers/ingest-feeds/` |

Example (sync parse for debugging):

```json
POST /api/v1/workers/parse-stealer/
{
  "content": "https://mail.example/login:user@example.com:Secret123",
  "create_leak": true,
  "async_mode": false
}
```

Scheduled (beat): CVE feed at :15, ransomware feed at :45 every hour.

## OSINT microservice (Phase 4)

Go high-concurrency username / digital-footprint scanner (Sherlock-style).

| Action | Endpoint |
|--------|----------|
| Go health | `GET http://localhost:8080/health` |
| Site catalog | `GET /api/v1/osint/sites/` (auth) or `GET http://localhost:8080/api/v1/sites` |
| Scan username | `POST /api/v1/osint/scan/` (auth) |

```json
POST /api/v1/osint/scan/
{
  "username": "target_user",
  "sites": ["GitHub", "GitLab"],
  "timeout_seconds": 45,
  "only_found": true,
  "persist": true
}
```

Found profile URLs are stored as Indicators + an OSINT Threat summary when `persist=true`.

Catalog lives in `services/osint/data/sites.json` (expandable toward 300+ sites).

## UI (Phase 5)

React console at http://localhost:3000

1. Sign in with Django user (`createsuperuser`)
2. Navigate: Overview · Indicators · The Wire · Data Leaks · OSINT Scan · Workers

Auth token is stored in **sessionStorage** (Basic) — cleared when the browser tab session ends. Passwords are never written to localStorage or logs.

## AI & MISP (Phase 6)

| Action | Endpoint |
|--------|----------|
| Integrations health | `GET /api/v1/integrations/health/` |
| Generate briefing | `POST /api/v1/ai/briefings/generate/` |
| List briefings | `GET /api/v1/ai/briefings/` |
| Extract entities | `POST /api/v1/ai/extract-entities/` |
| MISP status | `GET /api/v1/misp/status/` |
| MISP sync | `POST /api/v1/misp/sync/` |

UI: http://localhost:3000/intelligence

Without AI keys, briefings use a **local template** (OPSEC-safe offline mode). MISP calls return `skipped` until `MISP_URL` + `MISP_API_KEY` are set.

## Development phases

1. **Phase 1** — Scaffolding & Docker infra
2. **Phase 2** — Database schema & DRF APIs
3. **Phase 3** — Celery workers (feeds, malware log parsing)
4. **Phase 4** — Go OSINT scanning engine
5. **Phase 5** — React dashboards & cyber UI
6. **Phase 6** — AI briefings & MISP / external APIs *(current)*

Watcher-style upgrades (Watch Rules, CERT RSS, ransomlook fallback, weekly/keyword AI): see [`docs/WATCHER_PARITY.md`](docs/WATCHER_PARITY.md).

## Security / OPSEC

- All secrets live in `.env` (see `.env.example`).
- `.env` is gitignored — never hardcode API keys (Hudson Rock, Anthropic, MISP, etc.).
- Data stays local (Postgres). No telemetry in Phase 1.

## Local development (without full Compose)

```bash
# Backend
cd backend
python -m venv .venv
# Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp ../.env.example ../.env
python manage.py migrate
python manage.py runserver

# Frontend
cd frontend
npm install
npm run dev

# OSINT
cd services/osint
go run ./cmd/server
```
