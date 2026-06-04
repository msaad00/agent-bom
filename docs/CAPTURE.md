# Screenshot capture protocol

Published screenshots in `docs/images/` must come from the live product
running against the bundled demo data, with the agent and scope chosen so
the resulting graph is actually informative. PR #1445 regressed
`mesh-live.png` to a near-empty graph because the captured agent
had no servers in the local data — this protocol exists so that does not
happen again.

The canonical published web UI is the packaged Next.js dashboard served by
`agent-bom serve`. Do not publish README or docs screenshots from archived
pre-Next.js views or from the Snowflake Streamlit compatibility surface.
For release PRs, use the operational checklist in
[`docs/release/SCREENSHOT_REFRESH_CHECKLIST.md`](release/SCREENSHOT_REFRESH_CHECKLIST.md)
before replacing any published product image.

## Canonical capture environment

1. Clean checkout on the release tag.
2. Fresh local DB with the bundled offline vuln catalog.
3. Build the bundled dashboard, then start the API against an empty SQLite
   path so only demo data is present:

   ```bash
   pip install -e ".[ui,api]"
   make build-ui
   agent-bom serve --persist /tmp/agent-bom-capture.db --allow-insecure-no-auth
   ```

   Use the packaged UI path for captures. Do not shoot screenshots from the
   Next.js dev server, or you risk the transient `Compiling...` badge showing
   up in published assets.

4. Generate the bundled demo report offline, then push that exact payload to
   the API so the stored job matches the terminal demo and does not pull in
   local workstation discovery:

   ```bash
   agent-bom agents --demo --offline -f json -o /tmp/agent-bom-demo-report.json
   curl -X POST -H 'content-type: application/json' \
     --data-binary @/tmp/agent-bom-demo-report.json \
     http://127.0.0.1:8422/v1/results/push
   ```

## Per-screenshot scope

| Asset | Page | Required scope | Rationale |
|---|---|---|---|
| `dashboard-live.png` | `/?capture=1` (Risk overview) | All agents · top crop showing the gauge, posture sub-scores, score breakdown, and the start of the attack-path list | The published README should not use one tall stitched dashboard asset when two shorter frames tell the story more clearly |
| `dashboard-paths-live.png` | `/?capture=1` (Risk overview) | All agents · mid-page crop showing the attack-path list, exposure KPI band, and the first backlog charts | Keeps the fix-first path list readable in GitHub while still proving the KPI / backlog context lives on the same page |
| `mesh-live.png` | `/mesh?capture=1` | Focused agent mesh graph across selected agents, MCP servers, tools, packages, credentials, and findings | Public README, Docker Hub, and marketplace surfaces should show one readable graph proof, not duplicate dark/light theme captures |
| `gateway-policies-live.png` | `/gateway?capture=1` | One advisory baseline gateway policy, two rules, one dry-run evaluation, and a clean top-frame policy posture | Proves the runtime policy surface without requiring a live proxy session during README capture |
| `security-graph-live.png` | `/security-graph?capture=1` | Capture the fix-first attack-path queue with snapshot pressure, graph evidence export, and remediation handoff | Shows the operator workflow before raw topology so the public image is readable and action oriented |
| `lineage-graph-live.png` | `/graph?capture=1` | Capture an expanded but bounded topology view across environment, identity, MCP, package, credential, model, dataset, and finding nodes | Shows broader graph evidence without turning the README frame into whole-tenant edge spaghetti |
| `context-map-live.png` | `/context?capture=1` | Capture one agent-scoped context map with reachable MCP servers and the lateral movement side panel | Shows a non-CVE topology view so README proof is not only package-to-finding blast radius |
| `fleet-state-live.png` | `/fleet?capture=1` | Seed fleet sync, set one agent owner/environment, approve it, then expand that row before capture | Shows environment and lifecycle state as control-plane evidence instead of implying the local scan alone owns review state |
| `identity-audit-live.png` | `/audit?capture=1` | Use a stable `AGENT_BOM_AUDIT_HMAC_KEY`, issue/rotate/revoke one agent identity, filter resource to `identity`, and capture HMAC counters plus lifecycle rows | Shows IAM lifecycle evidence and tamper-evident audit posture from the real identity API |
| `dependency-map-live.png` | `/insights?capture=1` | Capture the supply chain dependency map with scan pipeline counts and package risk distribution | Proves package risk visualization from the same pushed scan payload |
| `remediation-live.png` | `/remediation` | All frameworks tab | Shows the full prioritized fix list |

### Dashboard layout (current)

The Risk overview redesign (post-#1496 operator UX drilldown) replaced
the older single-column attack-path layout. The published media now ships
as two dashboard frames rather than one stitched full-page export:

1. `dashboard-live.png`
   Header, top counters, F-grade gauge, security posture card, score breakdown, and the start of the attack-path list
2. `dashboard-paths-live.png`
   Top attack paths, exposure KPIs, severity/source charts, and the first compound-issue cards

A capture set that misses either frame is incomplete. Re-shoot from the
packaged UI and crop deliberately; do not publish another full-page stitched
dashboard asset unless the layout materially changes again.

Use the agent with filesystem and database servers as the graph proof shot in
the current demo inventory. It brings multiple tools, reachable packages, and
the densest CVE cluster
(`pillow@9.0.0`, `cryptography@39.0.0`, `werkzeug@2.2.2`). Capturing under
an unscoped or lower-signal agent risks a flatter graph. Use
`/mesh?capture=1` for the product graph, then crop deliberately so the visible
frame contains the graph controls, legend, nodes, and dependency/finding edges
without the left navigation or a large empty canvas. Do not publish duplicate
dark/light theme copies in the public README or Docker Hub description unless
the section is specifically proving a theme bug fix. Do not publish a docs-only
slide or card view in place of the graph screenshot.

The README graph proof should show more than the mesh path. Keep
`security-graph-live.png`, `lineage-graph-live.png`, and `context-map-live.png`
in the open graph gallery so readers can see fix-first paths, expanded but
bounded topology, and focused lateral context without expanding every details
block.

For repeatable docs refreshes, use the deterministic Playwright harness from
the UI package after the graph schema and UI build are current:

```bash
cd ui
npm run capture:product-proof
```

The harness routes seeded scan, fleet, gateway, IAM, environment, runtime, and
package evidence into the real Next.js pages. It is suitable for README proof
captures, not for claiming those exact entities were discovered from a buyer
environment.

For environment and IAM proof, keep the claim precise. The demo graph scan
stores agents, MCP servers, tools, credentials, packages, findings, provider,
and graph edges. Environment review state and identity lifecycle are seeded
control-plane records. Use the real APIs for capture:

```bash
AGENT_BOM_AUDIT_HMAC_KEY=readme-capture-audit-hmac-key-32-plus-bytes \
AGENT_BOM_TRUST_PROXY_AUTH=1 \
AGENT_BOM_TRUST_PROXY_AUTH_SECRET=test-proxy-secret-with-32-plus-bytes \
  agent-bom serve --persist /tmp/agent-bom-capture.db --allow-insecure-no-auth

curl -H 'X-Agent-Bom-Role: admin' \
  -H 'X-Agent-Bom-Tenant-ID: default' \
  -H 'X-Agent-Bom-Proxy-Secret: test-proxy-secret-with-32-plus-bytes' \
  -X POST http://127.0.0.1:8422/v1/fleet/sync

# Then update owner/environment with PUT /v1/fleet/{agent_id}, approve with
# PUT /v1/fleet/{agent_id}/state, and issue/rotate/revoke an identity through
# /v1/identities. Capture `/audit?capture=1` with resource filter `identity`.
```

For public release screenshots, sanitize demo agent labels before pushing the
payload to the capture API. Keep the generated inventory, findings,
relationships, and traversal shape intact, but use generic agent names in the
visible UI.

For `gateway-policies-live.png`, seed a policy into the capture store before
capturing the route. Use trusted proxy auth only for the write calls, then
restart `agent-bom serve` in local capture mode for the screenshot:

```bash
AGENT_BOM_TRUST_PROXY_AUTH=1 \
AGENT_BOM_TRUST_PROXY_AUTH_SECRET=test-proxy-secret-with-32-plus-bytes \
  agent-bom serve --persist /tmp/agent-bom-capture.db --allow-insecure-no-auth

curl -X POST http://127.0.0.1:8422/v1/gateway/policies \
  -H 'content-type: application/json' \
  -H 'X-Agent-Bom-Role: admin' \
  -H 'X-Agent-Bom-Tenant-ID: default' \
  -H 'X-Agent-Bom-Proxy-Secret: test-proxy-secret-with-32-plus-bytes' \
  -d '{"name":"Baseline MCP runtime policy","mode":"audit","enabled":true,"bound_agents":["cursor","claude-desktop"],"rules":[{"id":"deny-shell","action":"block","block_tools":["execute_command","exec","shell"]},{"id":"watch-secrets","action":"warn"}]}'
curl -X POST http://127.0.0.1:8422/v1/gateway/evaluate \
  -H 'content-type: application/json' \
  -H 'X-Agent-Bom-Role: admin' \
  -H 'X-Agent-Bom-Tenant-ID: default' \
  -H 'X-Agent-Bom-Proxy-Secret: test-proxy-secret-with-32-plus-bytes' \
  -d '{"tool_name":"execute_command","arguments":{"command":"cat /etc/passwd","reason":"README capture policy smoke"}}'
```

## Accuracy guardrail

`tests/test_demo_inventory_accuracy.py` enforces that:

- every demo package resolves to at least one real advisory in the
  bundled offline DB (or is on a small audited allowlist), and
- the demo always yields at least one HIGH or CRITICAL finding so the
  hero screenshot story stays credible.

If a future change to `src/agent_bom/demo.py` would publish a screenshot
claiming CVEs against a clean version, that test fails before the change
can land.
