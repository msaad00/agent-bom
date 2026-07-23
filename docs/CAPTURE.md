# Screenshot capture protocol

Published screenshots in `docs/images/` must come from packaged Next.js
product routes using the deterministic, explicitly synthetic capture fixture,
with the agent and scope chosen so the resulting graph is informative. The
fixture validates UI contracts; it is not evidence from a buyer estate.
PR #1445 regressed `mesh-live.png` to a near-empty graph because the captured agent
had no servers in the local data — this protocol exists so that does not
happen again.

The canonical web artifact is the packaged Next.js dashboard bundled with
`agent-bom serve`. The deterministic harness runs that same standalone build
directly. Do not publish README or docs screenshots from archived
pre-Next.js views or from the Snowflake Streamlit compatibility surface.
For release PRs, use the operational checklist in
[`docs/release/SCREENSHOT_REFRESH_CHECKLIST.md`](release/SCREENSHOT_REFRESH_CHECKLIST.md)
before replacing any published product image.

## Canonical capture environment

1. Use a clean checkout on the release tag.
2. Install the pinned UI toolchain, build the production dashboard, and run
   the deterministic capture harness:

   ```bash
   cd ui
   npm ci
   npm run build
   npm run capture:product-proof
   ```

   The harness starts `.next/standalone/server.js` unless `CAPTURE_BASE_URL`
   points to an already-running packaged build. It never uses the Next.js
   development server, so transient compilation state cannot enter published
   assets.

3. Inspect all 13 PNGs and the manifest at the final README display size. The
   harness stages files and publishes them only after every page passes.

Backend-connected release evidence is a separate end-to-end smoke. For that
check, start `agent-bom serve` with a fresh SQLite database, generate the
bundled demo report offline, and push that exact payload so no workstation
discovery enters the test:

```bash
pip install -e ".[ui,api]"
agent-bom serve --persist /tmp/agent-bom-capture.db --allow-insecure-no-auth
agent-bom scan --demo --offline -f json -o /tmp/agent-bom-demo-report.json
curl -X POST -H 'content-type: application/json' \
  --data-binary @/tmp/agent-bom-demo-report.json \
  http://127.0.0.1:8422/v1/results/push
```

This backend smoke proves the API/storage path; it does not generate the
deterministic public screenshot set.

## Per-screenshot scope

| Asset | Page | Required scope | Rationale |
|---|---|---|---|
| `dashboard-live.png` | `/?capture=1` (Overview) | Posture grade, unique findings breakdown, scan coverage, operational lanes | Command-center top frame |
| `dashboard-paths-live.png` | `/?capture=1` (Overview) | Unique exposure paths, recent scans, activity | Lower overview frame |
| `cloud-accounts-live.png` | `/connections?capture=1` | Connections header and provider gallery across cloud, code, AI, and data | Onboarding surface |
| `new-scan-live.png` | `/scan?capture=1` | New Scan modes — connected account, ad-hoc, public repo URL | Scan scope clarity |
| `mesh-live.png` | `/mesh?capture=1` | Capture-mode scopes developer-copilot + sre-runbook-agent on shared filesystem MCP with path focus off and labeled edges | README mesh proof must differ from lineage: multi-agent shared server, not the same single CVE chain |
| `gateway-policies-live.png` | `/runtime?tab=gateway&capture=1` | KPI rollup, enforcement posture, and recent tool-call evidence | Proves runtime gateway observability without a live proxy session during capture |
| `security-graph-live.png` | `/security-graph?capture=1` | Capture a prioritized attack path with graph evidence export and remediation handoff | Shows the operator workflow before raw topology so the public image is readable and action oriented |
| `lineage-graph-live.png` | `/graph?capture=1` | Scoped developer-copilot attack path through GitHub MCP, explicit `next@` package node, and DEMO-VULN | Keeps the package-hop lineage story; relationship labels disambiguate Uses vs Has CVE |
| `context-map-live.png` | `/context?capture=1` | developer-copilot scope with capture path focus off — create_pull_request, GITHUB credential, MCP servers | Proof text must not require DEMO-VULN; lateral tools/creds topology is the hero |
| `fleet-state-live.png` | `/fleet?capture=1` | Expanded quarantined agent row with owner, environment, and enforcement state | Shows environment and lifecycle state as control-plane evidence instead of implying the local scan alone owns review state |
| `identity-audit-live.png` | `/audit?capture=1` | Identity-resource posture summary with auth, key, and tenant-quota panels | Shows the visible IAM posture frame from the deterministic capture fixture |
| `dependency-map-live.png` | `/findings?capture=1` | Capture findings queue with seeded package and CVE evidence | Proves package/CVE posture from the same seeded demo estate |
| `remediation-live.png` | `/remediation` | All frameworks tab | Shows the full prioritized fix list |

### Dashboard layout (current)

The Risk overview redesign (post-#1496 operator UX drilldown) replaced
the older single-column attack-path layout. The published media now ships
as two dashboard frames rather than one stitched full-page export:

1. `dashboard-live.png`
   Overview command center — posture grade, unique findings, scan coverage, and operational lanes
2. `dashboard-paths-live.png`
   Unique exposure paths, recent scans, and activity
3. `cloud-accounts-live.png`
   Connected evidence sources with provider catalog
4. `new-scan-live.png`
   New Scan form with scope chips and public repo URL mode

A capture set that misses either frame is incomplete. Re-shoot from the
packaged UI and crop deliberately; do not publish another full-page stitched
dashboard asset unless the layout materially changes again.

Use `developer-copilot` as the public graph proof scope. The seeded path links
that agent to GitHub MCP, a package, and `DEMO-VULN-21441` without implying
whole-estate density. Use `/mesh?capture=1` for the product graph, then frame it
so the title, graph controls, legend, nodes, and dependency/finding edges remain
visible without the left navigation or a large empty canvas. Do not publish duplicate
dark/light theme copies in the public README or Docker Hub description unless
the section is specifically proving a theme bug fix. Do not publish a docs-only
slide or card view in place of the graph screenshot.

The README graph proof should show more than the mesh path. Keep
`security-graph-live.png`, `lineage-graph-live.png`, and `context-map-live.png`
in the open graph gallery so readers can see fix-first paths, a filtered
lineage drilldown, and focused lateral context without expanding every details
block.

For repeatable docs refreshes, use the deterministic Playwright harness from
the UI package after the graph schema and UI build are current:

```bash
cd ui
npm run build
npm run capture:product-proof
```

### Security-graph investigation OS refresh

After the graph investigation OS series and demo estate reseed land on the
deployed control plane, recapture the live operator proof (not only the
deterministic harness fixture):

```bash
# Prefer a seeded demo API with non-empty findings + attack paths.
export CAPTURE_BASE_URL="${CAPTURE_BASE_URL:-https://demo.example}"
cd ui
npm run capture:product-proof
# Inspect docs/images/security-graph-live.png (and lineage/mesh if chrome changed).
```

Do not commit a replacement `security-graph-live.png` until the demo estate
findings smoke is green on that environment. Document the commands here even
when the PNG itself is deferred.


Without `CAPTURE_BASE_URL`, the harness starts the current standalone
production build. It routes deterministic scan, fleet, gateway, IAM,
environment, runtime, and package responses into the shipped Next.js pages,
fails on browser/network/API contract errors, and publishes the full set only
after every capture succeeds. It is suitable for README UI proof, not for
claiming those exact entities came from the backend or a buyer environment.

The capture harness must refresh every asset listed in
`docs/images/product-screenshots.json`; adding a new manifest entry without a
matching Playwright capture is a stale-evidence bug. Inspect each generated PNG
at README scale before publishing: text must stay inside cards and controls,
long identifiers must wrap or truncate, graph labels must remain legible, and no
browser chrome, dev overlay, local path, or stale version stamp may be visible.

For separate end-to-end environment and IAM validation, use the real APIs.
That operational smoke is backend evidence and does not replace the
deterministic public screenshot workflow:

```bash
AGENT_BOM_AUDIT_HMAC_KEY=readme-capture-audit-hmac-key-32-plus-bytes \
AGENT_BOM_TRUST_PROXY_AUTH=1 \
AGENT_BOM_TRUST_PROXY_AUTH_SECRET=test-proxy-secret-with-32-plus-bytes \
  agent-bom serve --persist /tmp/agent-bom-capture.db --allow-insecure-no-auth

curl -H 'X-Agent-Bom-Role: admin' \
  -H 'X-Agent-Bom-Tenant-ID: default' \
  -H 'X-Agent-Bom-Proxy-Secret: test-proxy-secret-with-32-plus-bytes' \
  -X POST http://127.0.0.1:8422/v1/fleet/sync

# Then update owner/environment with PUT /v1/fleet/{agent_id}, quarantine with
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
