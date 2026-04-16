# Deployment Overview

`agent-bom` is intentionally deployable in multiple ways. The product contract is
interoperable and self-hostable:

- run it locally as a CLI
- run it in CI
- run it in Docker or Kubernetes
- expose it as an MCP server
- self-host the API + dashboard
- pair the control plane with Postgres / Supabase, ClickHouse, or Snowflake where
  parity is explicitly documented

That gives users real choices instead of locking the product to one control
plane or one hosting provider.

## Runtime Surfaces

| Surface | Best for | Command / entrypoint |
|---|---|---|
| **CLI** | local scans, endpoint runs, CI jobs | `pip install agent-bom` then `agent-bom agents` |
| **GitHub Action** | PR and release gates | `uses: msaad00/agent-bom@v0.76.4` |
| **Docker** | isolated scans and reproducible runners | `docker run ghcr.io/msaad00/agent-bom agents` |
| **API + dashboard** | team and enterprise self-hosting | `agent-bom serve` |
| **REST API only** | platform integration without bundled UI | `agent-bom api` |
| **MCP server** | Claude Desktop, Claude Code, Codex, Cursor, Windsurf, Smithery-style remote use | `agent-bom mcp server` |
| **Runtime proxy** | live MCP traffic inspection and policy enforcement | `agent-bom proxy` |
| **Shield SDK** | in-process protection inside an app or service | `from agent_bom.shield import Shield` |

## Hosting and Storage Choices

| Choice | What it means today | Best for |
|---|---|---|
| **Local laptop / workstation** | local CLI or `agent-bom serve` with SQLite | individuals, demos, endpoint audit |
| **Self-hosted VM / container** | `agent-bom api` or `agent-bom serve` behind your ingress/auth | teams and platform operators |
| **Docker Compose / container platforms** | containerized API, proxy, or MCP server | repeatable deployment without vendor lock-in |
| **Kubernetes / Helm** | cluster deployment for scanner, proxy, optional runtime monitor, and packaged API + UI control plane | larger team and enterprise rollout |
| **Postgres / Supabase** | primary transactional control plane | full API/UI and tenant-aware persistence |
| **ClickHouse** | analytics and event-scale persistence | trends, runtime event analytics, OLAP |
| **Snowflake** | warehouse-native governance and selected control-plane paths | governance/activity workflows and Snowflake-native operators |

## Important Boundary

`Snowflake` is a supported backend and governance surface, not the default full
application hosting contract.

Today the honest story is:

- `Postgres` / `Supabase`: primary control-plane backend
- `ClickHouse`: analytics add-on
- `Snowflake`: warehouse/governance/native-data option with explicit parity limits

For the detailed backend matrix, see [Backend Parity Matrix](backend-parity.md).

## Deployment Selection

| Need | Recommended path |
|---|---|
| Run one scan locally | CLI |
| Gate pull requests | GitHub Action |
| Keep the runtime isolated | Docker |
| Self-host UI + API for a team | `agent-bom serve` + `Postgres` / `Supabase` |
| Integrate with internal platforms | `agent-bom api` |
| Expose agent-bom as a tool server | `agent-bom mcp server` |
| Add runtime enforcement | `agent-bom proxy` |
| Add analytics at scale | `ClickHouse` alongside the control plane |
| Use warehouse-native governance data | `Snowflake` with explicit parity limits |

## Available on

- [PyPI](https://pypi.org/project/agent-bom/)
- [Docker Hub](https://hub.docker.com/r/agentbom/agent-bom)
- [GHCR](https://github.com/msaad00/agent-bom/pkgs/container/agent-bom)
- [GitHub Marketplace](https://github.com/marketplace/actions/agent-bom-ai-supply-chain-security-scan)
- [Smithery](https://smithery.ai/server/agent-bom/agent-bom)
- [Glama](https://glama.ai)
