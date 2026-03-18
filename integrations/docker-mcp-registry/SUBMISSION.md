# Docker MCP Toolkit — Submission Instructions

Submission files for listing agent-bom in the Docker Desktop MCP Toolkit catalog.

## Files

- `server.yaml` — server metadata, image, allowed hosts, optional secrets
- `tools.json` — all 32 MCP tools with descriptions and parameters
- `readme.md` — Docker MCP Toolkit detail page content

## How to submit

1. Fork https://github.com/docker/mcp-registry
2. Copy this directory to `servers/agent-bom/` in your fork
3. Run validation: `task wizard` or `task build` (requires Taskfile)
4. Open a PR to `docker/mcp-registry` — Docker team reviews for security, license, and quality
5. Upon approval (~24h), agent-bom appears in Docker Desktop → MCP Toolkit

## Update process

When releasing a new version:
1. Update `source.commit` in `server.yaml` to the new release tag SHA
2. Submit a PR to `docker/mcp-registry` updating `servers/agent-bom/server.yaml`

## Notes

- `source.commit` must be pinned to an exact SHA (not a branch)
- `allowHosts` lists all external APIs the MCP server calls
- `NVD_API_KEY` is optional — without it, NVD enrichment uses public rate limits (10 req/min)
- No `~/.config` mount needed — agent-bom discovers MCP configs automatically
