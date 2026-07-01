# MCP Workflow Bundles

agent-bom exposes many tools, but agents should not have to guess the order.
The MCP server card advertises eight workflow prompts that map common jobs to
safe tool sequences, expected evidence, and clear stop conditions.

| Workflow prompt | Primary user | Tool sequence | Evidence produced |
|---|---|---|---|
| `quick-audit` | Developer or security reviewer | `scan` -> `exposure_paths` -> `compliance` | Findings, blast radius, framework mapping |
| `pre-install-check` | Developer / CI assistant | `check` -> `registry_lookup` -> `should_i_deploy` | Install allow/warn/block decision |
| `compliance-report` | Security / audit | `compliance` -> `audit_integrity` -> report export | Framework summary, evidence IDs, audit status |
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
ABOM_URL=https://demo.agent-bom.com \
ABOM_API_TOKEN=... \
scripts/demo/gateway-fleet-live-demo.sh
```

The script uses only read endpoints and exits non-zero if the API is not
reachable or authentication fails.
