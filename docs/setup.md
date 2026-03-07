# Setup Guide

## Prerequisites

- Python 3.11+
- Node.js 20+
- PostgreSQL 14+ (optional — SQLite used by default in dev)
- OpenClaw installed and gateway running (for OpenClaw chat mode)

---

## Local Development (no Docker)

### 1. Clone and install

```bash
git clone https://github.com/yaseenkadlemakki/clawaudit.git
cd clawaudit

# Python deps (sentinel + backend)
pip install -e ".[backend,dev]"

# Frontend deps
cd frontend && npm install && cd ..
```

### 2. Start the backend

```bash
uvicorn backend.main:app --host 0.0.0.0 --port 18790 --reload
```

The API will be available at `http://localhost:18790`.  
Interactive docs: `http://localhost:18790/docs`

By default, it uses SQLite at `~/.openclaw/sentinel/clawaudit.db`.  
To use PostgreSQL, set:

```bash
export DATABASE_URL="postgresql+asyncpg://user:pass@localhost:5432/clawaudit"
```

### 3. Start the frontend

```bash
cd frontend
npm run dev
```

UI available at `http://localhost:3000`.

### 4. Run the CLI

```bash
# Audit all installed skills
python -m sentinel audit

# Audit a specific skill
python -m sentinel audit --skill my-skill

# View findings
python -m sentinel findings
```

---

## Docker (full stack)

### 1. Configure

```bash
cp docker/.env.example docker/.env
# Edit docker/.env — at minimum set POSTGRES_PASSWORD
```

### 2. Start

```bash
docker compose --env-file docker/.env -f docker/docker-compose.yml up
```

Services:
| Service | URL |
|---------|-----|
| Frontend UI | http://localhost:3000 |
| Backend API | http://localhost:18790 |
| API docs | http://localhost:18790/docs |
| PostgreSQL | localhost:5432 |

### 3. Stop

```bash
docker compose -f docker/docker-compose.yml down
# Remove volumes too (wipes DB):
docker compose -f docker/docker-compose.yml down -v
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | SQLite at `~/.openclaw/sentinel/clawaudit.db` | Database connection URL |
| `CLAWAUDIT_HOST` | `127.0.0.1` | Backend bind address |
| `CLAWAUDIT_PORT` | `18790` | Backend port |
| `CLAWAUDIT_LOG_LEVEL` | `info` | Log level |
| `CLAWAUDIT_CORS_ORIGINS` | `http://localhost:3000` | Comma-separated allowed CORS origins |
| `OPENCLAW_GATEWAY_URL` | `http://localhost:18789` | OpenClaw gateway URL for chat mode |
| `OPENCLAW_GATEWAY_TOKEN` | _(unset — required only for OpenClaw chat mode)_ | Gateway auth token |
| `BYOLLM_MODEL` | `claude-haiku-4-5` | Anthropic model for BYOLLM chat mode |
| `NEXT_PUBLIC_API_URL` | `http://localhost:18790` | Frontend → backend REST URL |
| `NEXT_PUBLIC_WS_URL` | `ws://localhost:18790` | Frontend → backend WebSocket URL |

---

## Running Tests

```bash
# Full suite with coverage
pytest tests/ --cov=sentinel --cov=backend --cov-fail-under=80 -v

# Backend tests only
pytest tests/backend/ -v

# Unit tests only
pytest tests/unit/ -v
```
