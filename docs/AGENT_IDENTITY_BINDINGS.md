# Agent evidence identity

Push inventory with `agent-bom fleet sync --push-url https://control-plane.example`
using the deployment's configured credentials. Inspect the returned fleet
records and retain their tenant-scoped `agent_id` for control-plane operations.
The current CLI includes a canonical inventory ID with each agent.

Custom `POST /v1/fleet/sync` producers must supply a non-empty, source-scoped
`canonical_id` for each agent. Name-only payloads return 422. Duplicate IDs,
ambiguous existing identities, and attempts to rebind an ID from another source
return 409. Keep the ID constant when changing a display name. Provider-native
IDs must include their provider/account/deployment scope; a name is not a
provider identity.

Persisted observations carry `agent_id` and/or `agent_canonical_id` separately
from their display labels. Inventory bindings establish inventory membership;
they do not authenticate a workload or prove that an action executed. Runtime
identity verification still belongs to the authenticated gateway boundary.

The manifest returns `agent_ids` and `agent_binding` on server rows. Graph
relationships and UI ownership use those IDs or explicit inventory membership.
Old observations without identity evidence remain `unbound`, even if their
label is currently unique. Recollect inventory to establish new identity-bearing
receipts; do not backfill identities by matching names. Legacy records remain
available rather than being silently reassigned or deleted.

Agent detail accepts an exact canonical ID in `/v1/agents/{identifier}`. Legacy
name URLs remain a navigation convenience only when the name is unique; an
ambiguous name returns 409. Scan-history and finding joins require explicit
agent and server IDs. Findings without identity-bearing evidence remain in the
source scan but are not attributed to an individual agent through a name.

This is fail-closed attribution: missing identity produces an unknown binding,
not a guessed owner, permission, runtime relationship, or clean assessment.

## One project, one agent

A project scan (`agent-bom scan -p <dir>`, or an API scan of a directory)
observes the same project through several collectors: its MCP config
(`.mcp.json`, `.vscode/mcp.json`, …), package manifests, AI-component imports,
code-defined framework agents, filesystem, and SAST. Discovery collapses every
collector rooted at the same directory into one `project:<dir name>` agent whose
canonical ID is the manifest-rooted project ID. The contributing collectors are
listed in the agent's `metadata.evidence_sources`; code-defined agent
constructs are recorded as `metadata.code_agents` (and on the graph node as
`code_agents`) rather than as extra agents. Framework agents that take part in
multi-agent delegation keep their own graph nodes. Only servers with the
`mcp-server` surface count as MCP servers.

Every surface counts agents the same way: distinct canonical agent IDs in the
tenant's completed scans, latest observation first. `/v1/inventory`,
`/v1/agents` (unless the API host is bound to the tenant; see
[ENTERPRISE_DEPLOYMENT.md](ENTERPRISE_DEPLOYMENT.md)), posture counts,
inventory summary, and the graph report the same number for the same scans.
