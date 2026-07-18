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
agent-bom scan -p .                       # scan this repo: rich console panel with posture grade
agent-bom scan -p . -f sarif -o out.sarif     # SARIF for code-scanning
agent-bom check flask@2.0.0 --ecosystem pypi  # pre-install allow/warn/block
```

New here? [`FIRST_RUN.md`](FIRST_RUN.md) is the canonical quickstart —
`agent-bom scan -p .` is the one first command it leads with.

CI gate (GitHub Action):

```yaml
- uses: msaad00/agent-bom@v0.94.2
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
- API contract (366 operations): [`../docs/openapi/v1.json`](openapi/v1.json)
- Enterprise auth, tenancy, RBAC: [`ENTERPRISE_DEPLOYMENT.md`](ENTERPRISE_DEPLOYMENT.md),
  [`PERMISSIONS.md`](PERMISSIONS.md)
- Runtime proxy/gateway enforcement: [`MCP_SERVER.md`](MCP_SERVER.md) and the
  [runtime enforcement spread](../PROJECT_STRUCTURE.md#runtime-enforcement-spread)

## Cloud / GRC — connect a cloud read-only

You want estate inventory, CIS posture, and exposure paths without granting
write access. `agent-bom connect` covers **AWS, Azure, GCP, and Snowflake**
through one connection model: a scoped read-only role per source, keyless or
token auth, opt-in per provider. It never writes, reads no secret values, and
moves no data out of your account.

```bash
# AWS — print the read-only grant, attach SecurityAudit, then:
agent-bom connect aws
export AGENT_BOM_AWS_INVENTORY=1 AWS_PROFILE=<readonly-profile>
agent-bom cloud aws --cis

# Azure — print the read-only grant, assign Reader (+ Security Reader), then:
agent-bom connect azure
export AGENT_BOM_AZURE_INVENTORY=1
az login && agent-bom cloud azure --cis

# GCP — print the read-only grant, impersonate a read-only service account:
agent-bom connect gcp
export AGENT_BOM_GCP_INVENTORY=1 AGENT_BOM_GCP_IMPERSONATE_SA=<sa-email>
gcloud auth application-default login
agent-bom cloud gcp --project <project-id> --cis

# Snowflake — read-only governance role + key-pair user, never password:
agent-bom connect snowflake
export SNOWFLAKE_ACCOUNT=<org-account> SNOWFLAKE_USER=ABOM_SCANNER
export SNOWFLAKE_AUTHENTICATOR=snowflake_jwt SNOWFLAKE_PRIVATE_KEY_PATH=/path/to/abom_key.p8
agent-bom scan --snowflake

# Cross-cloud estate inventory for AWS/Azure/GCP (reference counts):
agent-bom cloud inventory --provider all
```

- Full grant templates, per-cloud permission catalogs, and the read-only
  rationale: [`CLOUD_CONNECT.md`](CLOUD_CONNECT.md)
- Cloud CIS misconfigurations and Snowflake posture converge into findings:
  `agent-bom scan --aws --azure --gcp --snowflake --fail-on-severity high`
- Exposure paths and non-human identity posture: `agent-bom graph`,
  `agent-bom identity credential-expiry`

## AI / agent developer — call it from an assistant

You want strict-argument security tools your agent can call, and the ability to
scan a repo by URL.

```bash
pip install 'agent-bom[mcp-server]'
agent-bom mcp server                      # stdio MCP server: 75 tools, 6 resources, 8 prompts
```

- MCP server setup + client guides: [`MCP_SERVER.md`](MCP_SERVER.md),
  [`MCP_CLIENT_GUIDES.md`](MCP_CLIENT_GUIDES.md)
- Tool catalog (read-mostly; 3 audited Shield write actions): see the
  `Tools (70)` block in
  [`../src/agent_bom/mcp_server.py`](../src/agent_bom/mcp_server.py)
- Typed control-plane clients: [`PYTHON_API.md`](PYTHON_API.md),
  [`../sdks/go/README.md`](../sdks/go/README.md)

---

## One model, every door

Whichever path you take, the underlying evidence is the same unified `Finding`
and `ContextGraph`. Humans get a cockpit; agents and pipelines get callable
primitives over identical data. That is the product shape — see
[`ARCHITECTURE.md`](ARCHITECTURE.md) for the layered view.
