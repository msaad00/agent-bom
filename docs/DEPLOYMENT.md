# Deployment Guide

## Architecture

```
Browser → Next.js UI (port 3000)
               │ NEXT_PUBLIC_API_URL
               ▼
         FastAPI backend (port 8422)
               │ AGENT_BOM_POSTGRES_URL
               ▼
         PostgreSQL  (Supabase · Railway · RDS · self-hosted)
               │ optional analytics sidecar
               ▼
         ClickHouse  (AGENT_BOM_CLICKHOUSE_URL)
```

The scanner engine, MCP server, and CLI all share the same Python package. The FastAPI backend wraps the scanner as async jobs. The Next.js UI is a static build that talks to the API.

---

## Option 1 — Local dev (all-in-one docker compose)

```bash
# 1. Clone and copy env template
git clone https://github.com/msaad00/agent-bom
cd agent-bom
cp .env.example .env

# 2. Set required vars in .env
#    POSTGRES_PASSWORD=<any strong password>
#    NEXT_PUBLIC_API_URL=http://localhost:8422   (already the default)

# 3. Start everything
docker compose -f docker-compose.fullstack.yml up --build

# Dashboard →  http://localhost:3000
# API docs  →  http://localhost:8422/docs
```

The `docker-compose.fullstack.yml` starts three services:
| Service | Image | Port |
|---------|-------|------|
| `api` | `agentbom/agent-bom` | 8422 |
| `ui` | `agentbom/agent-bom-ui` | 3000 |
| `postgres` | `postgres:16-alpine` | 5432 |

---

## Option 2 — Supabase + local API (recommended for production)

Supabase gives you Postgres + auth + realtime for free on the free tier.

```bash
# 1. Create a Supabase project at https://supabase.com
#    Copy the "Connection string" (Session mode, port 5432)

# 2. Set env vars
export AGENT_BOM_POSTGRES_URL="postgresql://postgres.<ref>:<password>@aws-0-<region>.pooler.supabase.com:5432/postgres"
export NEXT_PUBLIC_API_URL="http://localhost:8422"

# 3. Start API only (no local postgres needed)
pip install 'agent-bom[api]'
agent-bom api --host 0.0.0.0 --port 8422

# 4. Start UI
cd ui
npm install
NEXT_PUBLIC_API_URL=http://localhost:8422 npm run dev
```

### Supabase table setup

Run the schema migrations from `infra/postgres/init.sql` in the Supabase SQL editor:

```
Supabase dashboard → SQL Editor → paste contents of infra/postgres/init.sql → Run
```

---

## Option 3 — Docker Compose with Supabase (no local DB)

Remove the `postgres` service and `depends_on` from `docker-compose.fullstack.yml`, then:

```bash
# .env
AGENT_BOM_POSTGRES_URL=postgresql://postgres.<ref>:<password>@aws-0-<region>.pooler.supabase.com:5432/postgres
NEXT_PUBLIC_API_URL=http://localhost:8422

docker compose -f docker-compose.fullstack.yml up api ui --build
```

---

## Option 4 — Railway one-click deploy

[![Deploy on Railway](https://railway.com/button.svg)](https://railway.com/template/agent-bom)

Railway auto-provisions Postgres and wires `DATABASE_URL` → map it to `AGENT_BOM_POSTGRES_URL` in the service settings. Set `NEXT_PUBLIC_API_URL` to the Railway API service URL before deploying the UI service.

---

## Environment Variables Reference

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `POSTGRES_PASSWORD` | ✅ | — | Postgres admin password (docker-compose only) |
| `AGENT_BOM_POSTGRES_URL` | ✅ prod | — | Full Postgres connection URL (overrides individual vars) |
| `NEXT_PUBLIC_API_URL` | ✅ | `""` (same origin) | URL the browser uses to reach the FastAPI backend |
| `AGENT_BOM_API_KEY` | optional | — | Bearer token to protect all API endpoints |
| `NVD_API_KEY` | optional | — | NVD API key for higher CVE enrichment rate limits |
| `AGENT_BOM_OIDC_ISSUER` | optional | — | OIDC issuer URL for SSO/JWT auth (`pip install agent-bom[oidc]`) |
| `AGENT_BOM_CLICKHOUSE_URL` | optional | — | ClickHouse URL for analytics trends |
| `SNOWFLAKE_ACCOUNT` | optional | — | Snowflake account for governance reports |

Full list: see `.env.example`.

---

## Production checklist

- [ ] `AGENT_BOM_API_KEY` set (or `AGENT_BOM_OIDC_ISSUER` for SSO)
- [ ] `NEXT_PUBLIC_API_URL` points to your API domain (not localhost)
- [ ] Postgres behind a firewall / Supabase RLS enabled
- [ ] TLS termination in front of both services (nginx / Caddy / Cloudflare Tunnel)
- [ ] `POSTGRES_PORT` not exposed to the public internet
- [ ] NVD_API_KEY set for production enrichment speed

---

## Running the MCP server alongside the API

```bash
# stdio (Claude Desktop, Cursor, Windsurf)
agent-bom mcp-server

# SSE / remote clients
agent-bom mcp-server --sse --host 0.0.0.0 --port 8765
```

The MCP server is stateless — it doesn't need Postgres. It calls the scanner engine directly and returns JSON to the AI assistant.
