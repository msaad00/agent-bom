import { expect, test } from "@playwright/test";
import { readFile } from "node:fs/promises";

const scan = "assessment-fixture";
const revision = "a".repeat(32);
const node = (id: string, entity_type: string, label: string) => ({
  id, entity_type, label, status: "active", risk_score: 0, severity: "none", severity_id: 0,
  attributes: {}, compliance_tags: [], data_sources: ["fixture"], dimensions: {},
});
const nodes = [node("agent:one", "agent", "Example agent"), node("server:one", "server", "Example server")];
const edges = [{ id: "edge:one", source: "agent:one", target: "server:one", relationship: "uses", direction: "directed", weight: 1, traversable: true, evidence: {} }];

for (const theme of ["light", "dark"]) {
  test(`explicit compromise assumption and export ${theme}`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.addInitScript(value => localStorage.setItem("agent-bom-theme", value), theme);
    const requests: Record<string, unknown>[] = [];
    await page.route("**/health", route => route.fulfill({ json: { status: "ok" } }));
    await page.route("**/v1/**", route => {
      const path = new URL(route.request().url()).pathname;
      if (path === "/v1/auth/me") return route.fulfill({ json: { authenticated: true, auth_required: false, tenant_id: "fixture", role: "viewer", configured_modes: [], recommended_ui_mode: "no_auth", memberships: [] } });
      if (path === "/v1/graph/snapshots") return route.fulfill({ json: [{ scan_id: scan, created_at: "2026-10-10T00:00:00Z", node_count: 2, edge_count: 1, risk_summary: {} }] });
      if (path === "/v1/inventory/summary") return route.fulfill({ json: { scan_id: scan, tenant_id: "fixture", total_assets: 2, evidence_scope: "historical_snapshot", snapshot_generation: revision } });
      if (path.startsWith("/v1/graph/node/")) return route.fulfill({ json: { scan_id: scan, snapshot_generation: revision, node: nodes[0], edges_out: edges, edges_in: [], neighbors: ["server:one"], sources: [], impact: { upstream_agents: [], affected_count: 0 } } });
      if (path === "/v1/graph/compromise") {
        requests.push(route.request().postDataJSON());
        return route.fulfill({ json: {
          schema_version: "compromise.direct.v1", tenant_id: "fixture", scan_id: scan, snapshot_generation: revision,
          root_node_id: "agent:one", assumed_control_node_id: "agent:one", assessed_at: "2026-10-10T00:00:00Z",
          scope: "direct_outgoing_relationships", current_access: "not_evaluated", execution: "not_established",
          collection_coverage: "unknown", relationships_examined: 1, truncated: false,
          actions: [{ source_edge_id: "edge:one", target_node_id: "server:one", permission: "unknown", observation: "not_recorded", binding_ids: [], reason_codes: ["evaluated_action_not_recorded"] }],
        } });
      }
      if (path === "/v1/graph" || path === "/v1/graph/query") return route.fulfill({ json: {
        scan_id: scan, nodes, edges, attack_paths: [], interaction_risks: [], roots: ["agent:one"], direction: "forward", max_depth: 1, truncated: false, depth_by_node: { "agent:one": 0, "server:one": 1 }, budget: {},
        stats: { total_nodes: 2, total_edges: 1, node_types: { agent: 1, server: 1 }, severity_counts: {}, relationship_types: { uses: 1 }, attack_path_count: 0, interaction_risk_count: 0 },
        pagination: { total: 2, offset: 0, limit: 250, has_more: false },
      } });
      return route.fulfill({ status: 503, json: { detail: "Not provided by this fixture" } });
    });
    await page.goto(`/graph?lens=lineage&scan=${scan}&node=agent:one&rollup=0`);
    const drawer = page.getByTestId("graph-entity-drawer");
    await expect(drawer).toBeVisible();
    await expect(page.locator(".react-flow__node")).toHaveCount(2);
    const panel = drawer.locator("details").filter({ has: page.locator("summary", { hasText: "Assess assumed compromise" }) });
    await panel.locator("summary").click();
    await expect(panel.getByRole("button", { name: "Assess evidence" })).toBeDisabled();
    expect(requests).toHaveLength(0);
    await panel.getByLabel("Assume control of this node").check();
    await panel.getByRole("button", { name: "Assess evidence" }).click();
    await expect(panel.getByText("Action unknown", { exact: false })).toBeVisible();
    expect(requests).toEqual([expect.objectContaining({ root_node_id: "agent:one", scan_id: scan, snapshot_generation: revision, assume_control: true })]);
    await expect(panel.getByText(/Successful execution is not established/)).toBeVisible();
    expect(await panel.evaluate(element => element.scrollWidth <= element.clientWidth)).toBe(true);
    await panel.scrollIntoViewIfNeeded();
    await page.screenshot({ path: testInfo.outputPath(`compromise-${theme}.png`) });
    const pending = page.waitForEvent("download");
    await panel.getByRole("button", { name: "Export assessment JSON" }).click();
    const download = await pending;
    const exported = JSON.parse(await readFile((await download.path())!, "utf8"));
    expect(exported.snapshot_generation).toBe(revision);
    expect(exported.actions[0].permission).toBe("unknown");
  });
}
