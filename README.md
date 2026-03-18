# SentinelScan — REST API Vulnerability Scanner

SentinelScan is a production-ready MVP that scans REST APIs for common OWASP Top 10 risks and delivers CVSS-style findings with exportable reports. Built for Hacknight Hackathon 2026.

## Features
- Async FastAPI scanner engine with Celery + Redis queue
- OWASP checks: BOLA/IDOR, Broken Auth, Excessive Data Exposure, Rate Limiting, SQLi/SSRF, Missing Security Headers
- CVSS-style scoring per finding
- JSON + PDF report export
- Demo mode with intentionally vulnerable endpoints
- Authenticated multi-user workspaces and projects
- React dashboard with results and scan history
- Docker Compose one-command deployment

## Quick Start (Docker)
```bash
docker compose up --build
```

Open:
- Frontend: `http://localhost:3000`
- Backend API: `http://localhost:8000`

## Local Development

### Backend
```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

### Frontend
```bash
cd frontend
npm install
npm run dev
```

## Auth + Multi-User
- Register or login to get a JWT.
- Each user gets a default workspace and project.
- Scans are tied to a project, and access is enforced by workspace membership.
- Set `JWT_SECRET` in production.

### Demo Credentials
- Email: `demo@sentinelscan.io`
- Password: `DemoPass123!`

## API Endpoints
- `POST /api/auth/register` — create user + default workspace/project
- `POST /api/auth/login` — get JWT
- `GET /api/org/workspaces` — list workspaces
- `POST /api/org/workspaces` — create workspace
- `GET /api/org/projects` — list projects
- `POST /api/org/projects` — create project
- `POST /api/scan` — start a scan (requires `project_id`)
- `GET /api/scan/{scan_id}` — scan results
- `GET /api/scans` — scan history
- `GET /api/scan/{scan_id}/report?format=json|pdf` — export report
- `GET /healthz` — liveness
- `GET /readyz` — readiness (checks DB)

## OpenAPI Docs
OpenAPI is available at `http://localhost:8000/docs` and includes JWT bearer auth.

## Rate Limiting
Redis-backed fixed window rate limiting is enabled by default. Configure with:
- `RATE_LIMIT_ENABLED`
- `RATE_LIMIT_PER_MINUTE`

## Structured Logs
API requests are logged in JSON with request IDs for tracing.

## CI Smoke Test
```bash
./scripts/smoke_test.sh
```

## Demo Mode
Toggle demo mode in the UI or POST with `demo_mode: true`. The scanner will run against:
`http://localhost:8000/demo/users/1`

## GitHub Repo Structure
```
backend/
  app/
    api/
    core/
    db/
    demo/
    services/
    tasks/
  Dockerfile
  requirements.txt
frontend/
  src/
  nginx.conf
  Dockerfile
docker-compose.yml
README.md
DEMO_SCRIPT.md
```

## Security Notes
This tool performs **non-intrusive** checks only. Always get explicit authorization before scanning third-party APIs.

## License
MIT
