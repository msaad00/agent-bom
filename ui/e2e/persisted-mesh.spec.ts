import { expect, test } from "@playwright/test";

const source = "agent:aws:production:planner";
const target = "agent:ingested:worker";
const snapshot = "correlated-estate";
const generation = "b".repeat(32);
const node = (id: string, label: string, data_sources: string[]) => ({ id, entity_type: "agent", label, attributes: {}, severity: "unknown", risk_score: 0, status: "active", data_sources, dimensions: {}, compliance_tags: [] });
const planner = node(source, "Cloud planner", ["aws"]);
const worker = node(target, "Ingested worker", ["ci-ingest"]);

for (const theme of ["light", "dark"] as const) for (const width of [1440, 390]) {
  test(`persisted mesh preserves cross-source delegation ${theme} ${width}`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width, height: 1000 });
    await page.addInitScript(value => localStorage.setItem("agent-bom-theme", value), theme);
    const incident: URL[] = [];
    const legacy: string[] = [];
    await page.route("**/v1/**", route => {
      const url = new URL(route.request().url());
      if (url.pathname === "/v1/auth/me") return route.fulfill({ json: { authenticated: true, auth_required: false, tenant_id: "fixture-tenant", auth_method: "anonymous", role: "admin", configured_modes: [], recommended_ui_mode: "no_auth", memberships: [] } });
      if (url.pathname === "/v1/graph/snapshots") return route.fulfill({ json: [{ scan_id: snapshot, created_at: "2026-09-23T12:00:00Z", node_count: 200, edge_count: 190, risk_summary: {}, snapshot_kind: "correlation" }] });
      if (url.pathname === "/v1/graph/agents") return route.fulfill({ json: { scan_id: snapshot, agents: [worker, planner], pagination: { total: 93, limit: 24, next_cursor: "next-agents" } } });
      if (url.pathname === "/v1/graph/incident-edges") {
        incident.push(url);
        const selected = url.searchParams.get("node_id") === source ? planner : worker;
        return route.fulfill({ json: { scan_id: snapshot, snapshot_generation: generation, node_id: selected.id, found: true, direction: "both", limit: 24, node: selected,
          nodes: [selected.id === source ? worker : planner], edges: [{ id: "delegation", source, target, relationship: "delegates_to", direction: "directed", weight: 1, evidence: { basis: "configured_delegation" }, provenance: { source: "fixture" } }],
          next_cursor: null, completeness: { complete: true, truncated: false, sampled: false, status: "complete", total: 1, returned: 1, scope: "incident_edge_page", missing_endpoint_count: 0 } } });
      }
      if (url.pathname === "/v1/agents" || /^\/v1\/scan\//.test(url.pathname)) legacy.push(url.pathname);
      return route.fulfill({ json: {} });
    });
    await page.goto(`/security-graph?lens=mesh&scan=${snapshot}&agent=${encodeURIComponent(source)}`);
    await expect(page.getByRole("heading", { name: "Agent Mesh", exact: true })).toBeVisible();
    await expect(page.getByRole("combobox", { name: "Agent scope" })).toHaveValue(source);
    const inspector = page.getByRole("complementary", { name: "Agent neighborhood inspector" });
    await expect(inspector.getByRole("heading", { name: "Cloud planner", exact: true })).toBeVisible();
    await expect(page.getByTestId("context-overview-title").filter({ hasText: "Ingested worker" })).toBeVisible();
    await expect(page.getByText("93 recorded agents · snapshot scope")).toBeVisible();
    expect(incident.length).toBeGreaterThan(0);
    expect(incident.every(url => url.searchParams.get("scan_id") === snapshot)).toBe(true);
    expect(incident[0]?.searchParams.get("node_id")).toBe(source);
    expect(legacy).toEqual([]);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
    await page.screenshot({ path: testInfo.outputPath(`mesh-${theme}-${width}.png`), fullPage: true });
    await page.getByRole("combobox", { name: "Agent scope" }).selectOption(target);
    await expect(inspector.getByRole("heading", { name: "Ingested worker", exact: true })).toBeVisible();
    expect(incident.at(-1)?.searchParams.get("node_id")).toBe(target);
  });
}
