# Start Here

`agent-bom` exposes one evidence model through several surfaces. Pick the entry
path for your role; each row is the shortest route to value.

For the repo layout, see [`../PROJECT_STRUCTURE.md`](../PROJECT_STRUCTURE.md).
For the architecture diagrams, see [`ARCHITECTURE.md`](ARCHITECTURE.md).

---

## Security engineer — scan, gate, export

You want findings, an SBOM, and a CI gate.

```bash
pip install agent-bom
agent-bom agents -p .                     # scan this repo: packages, agents, MCP servers, blast radius
agent-bom agents -p . -f sarif -o out.sarif   # SARIF for code-scanning
agent-bom check flask@2.0.0 --ecosystem pypi  # pre-install allow/warn/block
```

CI gate (GitHub Action):

```yaml
- uses: msaad00/agent-bom@v0.89.1
```

- Output formats, exit codes, and the full command set:
  [`CLI_MAP.md`](CLI_MAP.md)
- What gets scanned and how findings converge:
  [`ARCHITECTURE.md`](ARCHITECTURE.md)
- Compliance mapping and evidence bundles: [`CONTROL_MAPPING.md`](CONTROL_MAPPING.md)

## Platform / SRE — self-host the control plane

You want the API, dashboard, gateway, and a deployment you own.

```bash
pip install 'agent-bom[ui]'
agent-bom serve                           # local API + bundled dashboard
# or a self-hosted pilot:
docker compose -f deploy/docker-compose.pilot.yml up -d
```

- Deployment chooser (Docker / Helm / EKS / Postgres):
  [`../site-docs/deployment/overview.md`](../site-docs/deployment/overview.md)
- API contract (271 operations): [`../docs/openapi/v1.json`](openapi/v1.json)
- Enterprise auth, tenancy, RBAC: [`ENTERPRISE_DEPLOYMENT.md`](ENTERPRISE_DEPLOYMENT.md),
  [`PERMISSIONS.md`](PERMISSIONS.md)
- Runtime proxy/gateway enforcement: [`MCP_SERVER.md`](MCP_SERVER.md) and the
  [runtime enforcement spread](../PROJECT_STRUCTURE.md#runtime-enforcement-spread)

## AI / agent developer — call it from an assistant

You want strict-argument security tools your agent can call, and the ability to
scan a repo by URL.

```bash
pip install 'agent-bom[mcp-server]'
agent-bom mcp server                      # stdio MCP server: 69 tools, 6 resources, 6 prompts
```

- MCP server setup + client guides: [`MCP_SERVER.md`](MCP_SERVER.md),
  [`MCP_CLIENT_GUIDES.md`](MCP_CLIENT_GUIDES.md)
- Tool catalog (read-mostly; 3 audited Shield write actions): see the
  `Tools (69)` block in
  [`../src/agent_bom/mcp_server.py`](../src/agent_bom/mcp_server.py)
- Typed control-plane clients: [`PYTHON_API.md`](PYTHON_API.md),
  [`../sdks/go/README.md`](../sdks/go/README.md)

---

## One model, every door

Whichever path you take, the underlying evidence is the same unified `Finding`
and `ContextGraph`. Humans get a cockpit; agents and pipelines get callable
primitives over identical data. That is the product shape — see
[`ARCHITECTURE.md`](ARCHITECTURE.md) for the layered view.
