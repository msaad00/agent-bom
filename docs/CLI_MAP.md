# CLI Command Map

`agent-bom` ships 48 top-level commands (plus an inline `upgrade`) under a
single Click entry point. The CLI groups them into 7 help categories — run
`agent-bom --help` to see this layout live. Grouping is defined in
[`../src/agent_bom/cli/_grouped_help.py`](../src/agent_bom/cli/_grouped_help.py).

Many commands are themselves groups with subcommands (e.g. `cloud`, `identity`,
`runtime`, `mcp`). This map covers the top-level surface; run `<command> --help`
for subcommands.

---

## Scanning

Inventory, package, image, IaC, cloud, and skills scanning entry points.

| Command | What it does |
|---|---|
| `agents` | Discover local AI agents + MCP servers, scan packages, build blast radius. The primary scan. |
| `skills` | Scan skills / instruction files for packages, servers, trust, findings. |
| `image` | Scan a container image. |
| `fs` | Scan a filesystem / disk image. |
| `iac` | Scan IaC: Dockerfile, Terraform, CloudFormation, Helm, Kubernetes. |
| `sbom` | Generate or scan an SBOM (CycloneDX / SPDX). |
| `cloud` | Cloud posture + estate inventory (AWS/Azure/GCP), CIS benchmarks. |
| `check` | Pre-install check for one package: allow / warn / block. |
| `verify` | Package integrity + SLSA provenance verification. |
| `secrets` | Secret detection. |
| `code` | SAST scanning with CWE-based compliance mapping. |

## Runtime

Live MCP enforcement, replay, and runtime monitoring.

| Command | What it does |
|---|---|
| `proxy` | Wrap a target MCP server for traffic inspection and policy decisions. |
| `runtime` | Group: `runtime proxy`, `runtime audit`, plus configure/bootstrap. |
| `watch` | Continuous / scheduled monitoring. |
| `firewall` | Inter-agent firewall decisions group. |
| `gateway` | Secure-by-default gateway group. |
| `sidecar-injector` | Inject runtime proxy sidecars. |

## MCP

Discovery, inventory, introspection, and MCP server operations.

| Command | What it does |
|---|---|
| `mcp` | Group: run the MCP **server** (`mcp server`), introspect, inventory. |
| `where` | Show every MCP discovery path + existence status. |
| `registry` | Query the MCP server security-metadata registry. |

## Reporting

Graph, mesh, dashboard, and narrative reporting workflows.

| Command | What it does |
|---|---|
| `graph` | Build / export the context graph. |
| `mesh` | Agent-mesh view. |
| `report` | Reporting group (history, narrative, exports). |

## Governance

Policy, trust, fleet, FinOps, identity, API, scheduling, and control-plane ops.

| Command | What it does |
|---|---|
| `policy` | Policy-as-code group. |
| `trust` | Trust-boundary commands. |
| `fleet` | Fleet inventory group. |
| `cost` | LLM cost / FinOps group (forecast, budget, chargeback). |
| `identity` | Non-human identity group (credential-expiry, access review). |
| `serve` | Run the local API + bundled dashboard. |
| `api` | API control-plane command. |
| `schedule` | Scheduled scans. |
| `remediate` | Generate / apply remediation plans. |
| `teardown` | Deployment teardown. |
| `run` | Run a configured operation. |
| `manifest` | Agent manifest operations. |
| `plugins` | Plugin entry-point group. |
| `profiles` | Deploy profiles group. |
| `guard` | Pre-install CVE guard for pip/npm. |
| `audit` / `audit-drain-dlq` | Audit-chain replay and DLQ drain. |

## Database

Local cache, vuln database, and framework catalog maintenance.

| Command | What it does |
|---|---|
| `db` | Local cache, vuln DB, and framework-catalog maintenance group. |

## Utilities

| Command | What it does |
|---|---|
| `upgrade` | Check for / install agent-bom updates (inline command). |
| `completions` | Shell completion helpers. |
| `doctor` | Environment / install diagnostics. |
| `samples` | Generate inspectable sample stacks. |
| `quickstart` | One-command guided onboarding. |
| `interactive` | Interactive mode. |
| `scanners` | List available scanners. |

---

## Intentional aliases

Some commands are reachable by more than one name on purpose — the same command
object is registered in two places so both the flat and grouped form work:

| Flat (top-level) | Grouped | Notes |
|---|---|---|
| `agent-bom proxy …` | `agent-bom runtime proxy …` | Same `proxy_cmd`. Top-level for discoverability; grouped form keeps runtime commands together. |
| `agent-bom proxy-bootstrap` | `agent-bom runtime bootstrap` | Same command, flat + grouped. |
| `agent-bom audit` | `agent-bom runtime audit` | Same `audit_replay_cmd` (proxy audit-log replay). |
| `agent-bom audit-drain-dlq` | `agent-bom runtime drain-dlq` | Same command, flat + grouped. |
| _(none)_ | `agent-bom runtime configure` | `proxy_configure_cmd` is grouped-only — no flat alias. |

These are deliberate ergonomic aliases, not duplicate logic. The grouped
(`runtime …`) form is the organizing home; the flat forms exist because runtime
enforcement and audit are common enough first steps to deserve top-level verbs.
