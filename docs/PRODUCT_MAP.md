# agent-bom product map

`agent-bom` has one evidence model and several entry points. The entry point
changes how data arrives and who operates it; it should not change the finding,
graph, audit, or export semantics.

For the canonical product flow (intake → scan → evidence → control → artifacts)
and the symbol-level CVE reachability differentiator, see
[HOW_IT_WORKS.md](HOW_IT_WORKS.md). This map focuses on lanes, surfaces, and
backend choices rather than re-deriving the flow.

## Service lanes

| Lane | Use it for | Entry point | Backing services | Output |
|---|---|---|---|---|
| Local scan | repos, lockfiles, containers, local agent and MCP config | `agent-bom agents`, GitHub Action, Docker | scanner engine, advisory cache, output formatters | JSON, SARIF, CycloneDX, SPDX, HTML |
| Cloud connect | AWS, Azure, GCP, Snowflake inventory and posture | `agent-bom connect`, `agent-bom cloud scan` | read-only provider clients, CIS checks, graph writer | cloud assets, misconfig findings, account/subscription/project edges |
| Control plane | shared review, graph, audit, fleet, compliance | REST API and dashboard | API, workers, SQLite/Postgres, optional ClickHouse/Snowflake analytics | tenant-scoped findings, posture, graph, audit trail |
| Agent tools | assistant-readable security queries | `agent-bom mcp server` | MCP server, strict argument validation, shared scanners | read-mostly MCP tool results |
| Runtime governance | live MCP/tool-call inspection and decisions | proxy, gateway, Shield write tools | policy engine, gateway routes, audit log, optional OCSF/SIEM export | allow/warn/block decisions and redacted audit events |
| Evidence export | CI gates, auditor packets, ticket attachments | output flags and API export routes | output formatters, compliance mapping, signing/audit paths | SARIF, SBOMs, OCSF, Markdown, HTML, compliance bundles |

## Which surface should I use?

| If you are... | Start with | Then move to |
|---|---|---|
| A developer checking a repo or image | `agent-bom agents -p .` | CI gate, SARIF upload, HTML report |
| A security engineer reviewing agent/MCP risk | `agent-bom agents --demo --offline` or a real project scan | dashboard graph, `agent-bom graph`, MCP tool review |
| A cloud operator connecting estate inventory | `agent-bom connect <provider>` | `agent-bom cloud scan`, CIS posture, account graph |
| A platform team piloting a shared service | `agent-bom serve` or Helm | API auth, Postgres, dashboard, workers, audit retention |
| An assistant/tooling team exposing security to agents | `agent-bom mcp server` | strict MCP config, Shield write scopes, audit reason requirements |
| A runtime/security team enforcing tool calls | gateway or proxy policy | policy audit trail, OCSF/SIEM export, fail-open/fail-closed review |

## Auth and data boundaries

| Boundary | Default posture | Where to configure |
|---|---|---|
| Local CLI | local filesystem and selected command flags; cloud network I/O is opt-in | CLI flags, `AGENT_BOM_*` env vars |
| Cloud connectors | read-only provider permissions; no secret values read or stored | [CLOUD_CONNECT.md](CLOUD_CONNECT.md) |
| REST API | API key/OIDC/SAML/trusted-proxy auth where enabled; tenant scope at request boundary | [ENTERPRISE_DEPLOYMENT.md](ENTERPRISE_DEPLOYMENT.md), [TENANT_RESOLUTION.md](TENANT_RESOLUTION.md) |
| SCIM | bearer tokens are server-side config; request payload tenant IDs are not trusted | [SCIM_SECURITY_MODEL.md](SCIM_SECURITY_MODEL.md) |
| MCP server | read-mostly tool surface; write actions require role, scope, and audit reason | [MCP_SECURITY_MODEL.md](MCP_SECURITY_MODEL.md) |
| Runtime proxy/gateway | explicit policy mode; decisions are redacted and auditable | [RUNTIME_REFERENCE.md](RUNTIME_REFERENCE.md), [POLICY_PRECEDENCE.md](POLICY_PRECEDENCE.md) |
| Evidence exports | caller-selected destination; compliance exports have audit/signing paths where configured | [COMPLIANCE_SIGNING.md](COMPLIANCE_SIGNING.md), [DATA_GOVERNANCE_RETENTION.md](DATA_GOVERNANCE_RETENTION.md) |

## Data flow

The canonical stage-by-stage narrative is [HOW_IT_WORKS.md](HOW_IT_WORKS.md);
the map-level view of the same flow is:

1. **Discover** from local files, packages, MCP clients, cloud APIs, imports, or runtime events.
2. **Match and enrich** with advisory, exploitability, posture, policy, identity, and cloud context.
3. **Normalize** into the unified `Finding` model and `ContextGraph`.
4. **Persist** locally or in the control plane: SQLite for local/small installs, Postgres for shared state, ClickHouse or Snowflake for analytics-style history where configured.
5. **Operate** through the CLI, CI, REST API, dashboard, MCP tools, proxy/gateway, and export formatters.

## Backend choices

| Backend | Role | When to use |
|---|---|---|
| Filesystem output | one-off local artifacts | local scan, CI job artifact, ticket attachment |
| SQLite | default local and small control-plane state | pilots, demos, single-node review |
| Postgres | shared control-plane state | multi-user API/dashboard, tenant-aware operations |
| ClickHouse | analytics/event-scale store | runtime trends, posture history, high-volume audit/event queries |
| Snowflake | warehouse-native evidence path | customer-controlled analytics and governance workflows |

## Keep the product story straight

- The dashboard is an operator surface, not the collector.
- The API and workers own shared orchestration, persistence, auth, graph, and audit behavior.
- Connectors use read-only credentials and normalize provider-specific shapes into the same evidence model.
- MCP server mode exposes security tools to assistants; proxy/gateway mode governs live tool calls.
- Export formats are downstream views of the same findings, not separate sources of truth.

Related docs: [START_HERE.md](START_HERE.md), [CLI_MAP.md](CLI_MAP.md),
[CLOUD_CONNECT.md](CLOUD_CONNECT.md), [DEPLOY_PLATFORM.md](DEPLOY_PLATFORM.md),
[MCP_SECURITY_MODEL.md](MCP_SECURITY_MODEL.md), [RUNTIME_REFERENCE.md](RUNTIME_REFERENCE.md),
and [DATA_GOVERNANCE_RETENTION.md](DATA_GOVERNANCE_RETENTION.md).
