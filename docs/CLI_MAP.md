# CLI Command Map

`agent-bom` exposes a grouped command surface under a single Click entry point.
The CLI groups visible commands into help categories — run `agent-bom --help`
to see the current layout live. Grouping is defined in
[`../src/agent_bom/cli/_grouped_help.py`](../src/agent_bom/cli/_grouped_help.py).

Many commands are themselves groups with subcommands (e.g. `cloud`, `connect`,
`identity`, `runtime`, `mcp`). This map covers the top-level surface; run
`<command> --help` for subcommands.

---

## Front door (canonical verbs)

The onboarding path is `connect` → `scan` → `graph` → `report`, with `up` to run
the platform locally. These verbs front the same evidence model.

| Command | What it does |
|---|---|
| `connect` | Read-only onboard a cloud or data source (`aws`/`azure`/`gcp`/`snowflake`). Prints the exact read-only grant + opt-in env var; performs no network I/O until you opt in. |
| `scan` | Discover agents, extract dependencies, scan for vulnerabilities. Accepts an optional positional `PATH`. Front-door equivalent of `agents`. |
| `graph` | Export the transitive dependency / context graph from a saved JSON scan report. |
| `report` | Reporting group — history, diff, analytics, narrative, dashboard. |
| `up` | Run the platform locally (API + bundled dashboard). Alias of `serve`. |

## Scanning

Inventory, package, image, IaC, cloud, and skills scanning entry points.

| Command | What it does |
|---|---|
| `agents` | Discover local AI agents + MCP servers, scan packages, build blast radius. The primary scan. |
| `skills` | Scan skills / instruction files for packages, servers, trust, findings. |
| `image` | Scan a container image. |
| `fs` | Scan a filesystem / disk image. |
| `iac` | Scan IaC: Dockerfile, Terraform, CloudFormation, Helm, Kubernetes. |
| `sbom` | Ingest an existing SBOM (CycloneDX / SPDX) and scan its components. |
| `ingest` | Ingest operator-provided evidence (e.g. `ingest hardware` firmware attestation) into the graph. |
| `cloud` | Cloud posture + estate inventory for AWS/Azure/GCP, CIS benchmarks, and cloud registry sweeps. Group: `scan` (all configured clouds), `aws`/`azure`/`gcp` aliases, `inventory`, `registry-scan` (ECR/ACR/GAR sweep), `resilience`, and AWS EBS `side-scan`. |
| `check` | Pre-install check for one package: allow / warn / block. |
| `verify` | Package integrity + SLSA provenance verification. |
| `secrets` | Secret detection. |
| `code` | Native AST and AI-component analysis for prompts, guardrails, tool signatures, SDKs, and model references. It does not execute Semgrep. |

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
| `findings` | Findings workbench for CLI users: `list` normalized findings (lifecycle columns when bulk-ingest metadata exists), `push` external scanner or normalized JSON to `POST /v1/findings/bulk`, triage queue items, decisions, and signed OpenVEX export. |

## Governance

Policy, trust, fleet, FinOps, identity, API, scheduling, and control-plane ops.

| Command | What it does |
|---|---|
| `policy` | Policy-as-code group. |
| `trust` | Trust-boundary commands. |
| `fleet` | Fleet inventory group — `sync` discovers local MCP agents and pushes to `POST /v1/fleet/sync` (requires `--push-url` or `AGENT_BOM_PUSH_URL`; loopback HTTP allowed for local pilots). |
| `cost` | LLM cost / FinOps group (forecast, budget, chargeback). |
| `identity` | Non-human identity group (credential-expiry, access review). |
| `serve` | Run the local API + bundled dashboard. |
| `api` | API control-plane command. |
| `schedule` | Scheduled scans. |
| `remediate` | Generate (and optionally `--apply` / `--open-pr`) a prioritized advisory remediation plan. |
| `capabilities` | Show every gated capability: state (ENABLED/OFF/DEGRADED/UNKNOWN), why, and how to unlock. |
| `graph-evidence` | Export retained graph history or an evidence manifest. |
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
| `agent-bom up` | `agent-bom serve` | `up` is a hidden alias of `serve` (same flags) — the canonical front-door verb for running the platform locally. |
| `agent-bom scan` | `agent-bom agents` | `scan` is the canonical front-door verb; `agents` remains the discoverable visible command. Both discover + scan. |
| `agent-bom proxy …` | `agent-bom runtime proxy …` | Same `proxy_cmd`. Top-level for discoverability; grouped form keeps runtime commands together. |
| `agent-bom proxy-bootstrap` | `agent-bom runtime bootstrap` | Same command, flat + grouped. |
| `agent-bom audit` | `agent-bom runtime audit` | Same `audit_replay_cmd` (proxy audit-log replay). |
| `agent-bom audit-drain-dlq` | `agent-bom runtime drain-dlq` | Same command, flat + grouped. |
| _(none)_ | `agent-bom runtime configure` | `proxy_configure_cmd` is grouped-only — no flat alias. |

These are deliberate ergonomic aliases, not duplicate logic. The grouped
(`runtime …`) form is the organizing home; the flat forms exist because runtime
enforcement and audit are common enough first steps to deserve top-level verbs.

---

## Cloud and Data-Source Boundary

`agent-bom connect` is the common onboarding door for all read-only sources:
AWS, Azure, GCP, and Snowflake. The operational scan surface then splits by what
the source is:

| Source | Command home | Why |
|---|---|---|
| AWS / Azure / GCP | `agent-bom cloud ...` | provider APIs expose estate inventory, IAM, network posture, CIS checks, registry sweeps, and side-scan workflows |
| Snowflake | `agent-bom agents --snowflake` plus `connect snowflake` | Snowflake is a warehouse/governance source: Cortex, grants, query/activity evidence, lineage, and CIS/posture metadata |

Both paths normalize into the same `Finding` and `ContextGraph` model; the
split is only the operator command and provider API boundary.

---

## Headless control-plane ingest

Push scanner or CI evidence into a running control plane without the dashboard:

| Command | API | Notes |
|---|---|---|
| `findings push <file>` | `POST /v1/findings/bulk` | Accepts normalized findings JSON or Trivy / Grype / Syft output. Defaults `--api-url` to `http://127.0.0.1:8422` for local pilots. |
| `fleet sync` | `POST /v1/fleet/sync` | Local discovery only — no dry-run preview without a push URL. |
| `mcp` tool `ingest_external_scan` | same bulk route when `AGENT_BOM_API_URL` + credentials are set | Parse-only when credentials are absent. |

Ingested external findings land in the unified `GET /v1/findings` queue (and
`GET /v1/compliance/hub/findings` for hub-native clients). The dashboard
`/findings` page reads the unified list — lifecycle **Status** / **Last seen**
columns appear only when rows carry bulk-ingest lifecycle metadata; scan-only
rows omit those fields by design.

Air-gap installs: set `AGENT_BOM_SKIP_UPDATE_CHECK=1` or `AGENT_BOM_OFFLINE=1`
before any CLI invocation to suppress the background PyPI version check (the
check starts before subcommand flags are parsed).
