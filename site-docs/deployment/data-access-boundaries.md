# Data Access Boundaries and Operator Control

> **You do not need to read this unless** you are answering "what can
> agent-bom read?" / "where does the data stay?" / "which controls
> disable each path?" For the maintainer-access boundary see
> [Customer Data and Support Boundary](customer-data-and-support-boundary.md).

`agent-bom` is designed to answer a narrow security question: where are AI
agents, MCP servers, tool paths, packages, credentials references, and related
runtime risks exposed?

It should not feel like a general-purpose endpoint collector, DLP agent, or
hosted inventory platform. Operators should be able to explain exactly what a
deployment can read, where the data stays, and which controls disable or narrow
each path.

## Product contract

Default posture:

- customer-controlled deployment first: local CLI, customer EKS, customer
  Postgres, customer object storage, customer SIEM
- no mandatory hosted control plane
- no hidden telemetry or analytics
- read-only scanning unless the operator explicitly runs a remediation or proxy
  enforcement workflow
- credential values are not stored, transmitted, validated, or used by default
- support data is customer-selected and explicit

This contract applies across local laptops, endpoint fleet rollout, CI,
Kubernetes, cloud inventory, and the API/UI control plane.

## What each mode can read

| Mode | Typical use | What it can read | What it must not do by default |
|---|---|---|---|
| Local agent/MCP discovery | developer laptop or endpoint inventory | known MCP and agent config paths, declared command, args, URLs, env var names | read arbitrary personal files, read env var values, execute MCP servers |
| Project scan | repo, CI, or checked-out app | requested project files needed for package, IaC, prompt, model, dataset, or secret classification | scan outside the requested scope, upload source code, validate secrets |
| Cloud inventory | AWS, Azure, GCP, Snowflake, Databricks, SaaS integrations | metadata reachable by the operator-provided read-only identity | mutate resources, grant permissions, exfiltrate provider data |
| Endpoint fleet sync | managed laptops reporting posture | generated inventory and scan summaries chosen by the endpoint command | silently collect user documents, browser history, or unrelated endpoint telemetry |
| API/UI control plane | team operations and review | tenant-scoped jobs, findings, fleet, graph, policy, audit, and auth state | bypass tenant/RBAC checks, expose one tenant to another |
| Proxy/gateway | optional runtime enforcement | MCP requests and responses that pass through the configured proxy path | inspect unrelated app traffic, run outside explicit proxy configuration |

## Connectors, plugins, and roles

Connectors and extension points follow the same boundary as built-in scans:
agentless, scoped, read-only by default, and stronger only when an operator
chooses it.

- connectors use operator-provided connector identities and should start with
  read-only scopes
- connectors must not write remote systems, escalate permissions, or reuse
  discovered credentials
- stronger connector actions require explicit connector configuration, RBAC
  permission, and audit evidence
- plugins and skills are scoped by operator-selected paths or registry entries
- plugins and skills must not silently install, read unscoped files, or export
  data without approval
- roles stay least-privilege by default: viewer reads allowed tenant evidence,
  analyst runs and reviews workflows, admin manages keys, policies, and tenant
  settings

## Sensitive data handling

`agent-bom` separates detection from collection.

For MCP configs, credential evidence is based on environment variable names such
as `OPENAI_API_KEY`, `DATABASE_URL`, or `AWS_SECRET_ACCESS_KEY`. The scanner
does not read the corresponding environment variable values.

For explicit project scans, some scanners must read file contents inside the
requested scope to classify risks. Examples include hardcoded secret detection,
prompt risk checks, IaC checks, model manifests, and package manifests. Reports
should retain only the minimum useful evidence: relative path, line number where
needed, finding type, severity, and redacted labels. Secret findings do not keep
the matched value or a prefix of the matched value.

For runtime proxy/gateway use, only traffic routed through the configured
proxy/gateway is in scope. Runtime detection can redact secrets or PII before
logging when those controls are enabled. Operators should treat proxy mode as a
deliberate enforcement surface, not as passive local discovery.

The UI and reports should show the security story around a sensitive finding,
not the sensitive value itself. Allowed context includes the tenant, user or
subject identifier, device identifier, agent or MCP server name, resource,
finding type, severity, relative path, line number, and attack path. Reports
must not show the matched secret value, a secret prefix, environment variable
value, personal file contents, raw prompt payload, raw request body, or raw
response body.

## Operator controls

Operators can narrow or disable major data paths:

| Control | Effect |
|---|---|
| `agent-bom agents --dry-run` | preview planned file/API access before scanning |
| `--inventory <file>` | scan only the provided inventory |
| `--project <dir>` | restrict project-oriented discovery to the requested directory |
| `--config-dir <dir>` | read MCP configs from one operator-selected directory |
| `--no-scan` | inventory only; skip vulnerability lookups |
| `--offline` | disable external vulnerability/enrichment network calls |
| `--no-skill` / `--skill-only` | disable or isolate skill/instruction scanning |
| API keys and RBAC roles | restrict who can view, run, mutate, export, or administer |
| tenant scoping | keep findings, jobs, audit, fleet, and graph data tenant-local |
| retention settings | keep operational data for explicit time windows |
| optional integrations | send data to Slack, Jira, SIEM, Vanta, Drata, OTEL, or archive stores only when configured |

## Auth, RBAC, and tenant boundaries

The control plane is not a shared flat bucket of findings. Tenant identity,
API-key scope, browser sessions, trusted-proxy headers, SCIM/OIDC/SAML role
signals, and route permissions determine what a caller can see or change.

The product expectation is:

- `viewer` can inspect allowed tenant-scoped evidence
- `analyst` can run and review operational workflows
- `admin` can manage protected settings such as keys, policies, and tenant data
- cross-tenant access is denied by default and covered by tests
- support access is explicit, auditable, and revocable

The `/v1/auth/policy` operator posture endpoint includes a
`data_access_boundaries` section generated from code. CI tests pin the contract
so the implementation, API surface, and docs cannot drift silently.

The same code-generated contract is available from the CLI:

```bash
agent-bom trust
agent-bom trust --format json
```

## Cloud least privilege

Cloud and SaaS scans should use dedicated read-only identities. A deployment
should prefer:

- read-only IAM roles or service principals
- scoped API tokens for SaaS connectors
- short-lived credentials where the platform supports them
- customer-managed secret stores
- separate identities per environment or tenant

`agent-bom` should report when evidence depends on a configured provider
identity, but it should not broaden that identity or use discovered credentials
to escalate access.

## Endpoint and laptop rollouts

For endpoint teams, the safe rollout model is explicit and inspectable:

- use MDM or an endpoint manager to run a known command
- start with `--dry-run`, `--no-scan`, or inventory-only modes when piloting
- scope project scans to managed developer workspaces or approved paths
- avoid collecting unrelated home-directory content
- push only the inventory and evidence classes the operator chooses
- keep fleet data in the customer control plane

This keeps local use focused on AI/MCP security posture instead of becoming a
general endpoint surveillance tool.

## How teams can verify the boundary

Teams should be able to verify the trust contract without trusting marketing
claims:

- review `docs/PERMISSIONS.md` for enumerated read and network behavior
- run `agent-bom agents --dry-run` before scanning
- run `agent-bom trust --format json` to inspect the machine-readable boundary
  contract used by the API and UI
- run `--offline` or `--no-scan` to prove network paths are optional
- inspect API audit logs and tenant-scoped route tests
- inspect generated reports for redaction markers instead of secret values
- deploy in a customer VPC/EKS account with customer-owned Postgres, KMS,
  object storage, and SIEM destinations

The operating rule is simple: find relevant AI/MCP/cloud-agent risk, keep
evidence minimal and redacted, keep data customer-controlled, and make every
broader data path an explicit operator choice.
