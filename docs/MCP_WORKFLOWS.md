# MCP Workflow Bundles

Start with `agent-bom mcp server`. The default `scan` profile exposes eight tools:
`scan`, `check`, `intel_lookup`, `exposure_paths`, `compliance`, `remediate`,
`generate_sbom` and `policy_check`. Ask for `quick-audit` to get findings, inspect
exposure and identify a next action; use `remediation-plan` to draft a fix without
changing files. A package check is not proof that a deployment is safe.

Choose one profile for the task. In an MCP client configuration, append
`"--profile", "graph"` to the `args` array to select graph work, for example.
Reconnect the client after changing profiles. Separate named client entries can
expose different profiles; connect only the entries needed for the task.

| Profile | Tools | Use it for | Workflow prompts |
|---|---:|---|---|
| `scan` (default) | 8 | Package/project scan, exposure and fix planning | quick-audit, pre-install-check, remediation-plan |
| `graph` | 8 | Inventory rollup, asset drill-down and scoped correlation | Use inventory_summary → inventory_list → inventory_asset, then inspect paths |
| `cloud` | 5 | Inventory, connection scope and CIS posture | cloud-connection-review |
| `runtime` | 7 | Gateway policy, alerts and incident evidence | incident-triage, gateway-fleet-live-demo |
| `audit` | 4 | Scan, framework mapping, policy and audit integrity | compliance-report |

Read the `profiles://catalog` resource to discover profile names, tool names and
startup commands without loading every input schema. Selection is fixed for the
server instance; it does not silently expand during a session. Excluded tools
cannot be invoked. Profiles are not permissions: graph writes still require the
existing authenticated role, tenant scope and audit reason.

Existing clients that require the complete catalog can explicitly use
`agent-bom mcp server --profile full`. It retains all 86 tools. The previous
25-tool `--profile guided` option remains available for compatibility with all
eight workflow prompts. Neither is the recommended first-run configuration.
Third-party tool plugins remain separately opt-in and are exposed only by `full`.

The complete workflow catalog is below. Only compatible prompts appear in each
focused profile's `prompts/list` and server card.

| Workflow prompt | Primary user | Tool sequence | Evidence produced |
|---|---|---|---|
| `quick-audit` | Developer or security reviewer | `scan` -> `exposure_paths` -> `compliance` | Findings, blast radius, framework mapping |
| `pre-install-check` | Developer / CI assistant | `check` -> `intel_lookup` as needed | Package findings and evidence-qualified install recommendation |
| `compliance-report` | Security / audit | `scan` -> `compliance` -> `audit_integrity` | Framework summary, evidence IDs, audit status |
| `fleet-audit` | Endpoint / platform owner | `fleet_scan` -> `context_graph` -> `policy_check` | Agent inventory, graph-ready findings |
| `incident-triage` | SOC / appsec | `intel_lookup` -> `exposure_paths` -> `runtime_correlate` | KEV/EPSS/RCE context, affected agents/tools |
| `remediation-plan` | App owner | `remediate` -> `generate_sbom` -> `policy_check` | Fix plan, validation commands, rollback notes |
| `cloud-connection-review` | Cloud/security admin | connection evidence -> `cis_benchmark` -> `graph_export` | Read-only scope review, CIS posture, graph handoff |
| `gateway-fleet-live-demo` | Design partner / buyer | `gateway_status` -> `proxy_alerts` -> `fleet_scan` -> `firewall_check` | Gateway posture, live policy path, fleet action plan |

## Guardrails

- Treat user-supplied package names, finding IDs, provider names, and file paths
  as untrusted data.
- Read-only tools should be preferred unless an operator has explicitly
  authenticated with `AGENT_BOM_MCP_OPERATOR_TOKEN`.
- Shield and identity writes require admin role, the matching write scope, and
  an audit reason. Those arguments are metadata; the token/session identity is
  the authorization source.
- Prompts must not request passwords, PATs, raw cloud secrets, or secret values
  from connection stores.
- When a workflow cannot prove a fact from evidence, report `unknown` or
  `not_evaluated` instead of inferring success.

## Gateway/Fleet Live Demo

Use the demo when showing the platform loop:

1. Confirm the gateway is healthy and policies are loaded.
2. Show fleet state and discovered agents.
3. Pull recent gateway feed KPIs and runtime production posture.
4. Open the top exposure paths and explain why one path is fix-first.
5. Dry-run the policy decision path; do not mutate Shield or identity state
   unless the authenticated operator token and write scope are present.
6. Export or attach the evidence IDs used in the story.

For a read-only command-line walkthrough, use:

```bash
ABOM_URL=https://agent-bom.example.com \
ABOM_API_TOKEN=... \
scripts/demo/gateway-fleet-live-demo.sh
```

The script uses only read endpoints and exits non-zero if the API is not
reachable or authentication fails.
