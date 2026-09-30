import { expect, test } from "@playwright/test";

const root = "agent:root";
const left = "server:left", right = "server:right";
const node = (id: string) => ({ id, label: id.split(":")[1], entity_type: id.startsWith("agent:") ? "agent" : "server", attributes: {}, severity: "none", severity_id: 0, risk_score: 0, status: "active", data_sources: ["fixture"], dimensions: {}, compliance_tags: [] });
for (const theme of ["light", "dark"]) for (const width of [390, 1440]) {
  test(`collapse preserves independent graph evidence ${theme} ${width}`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width, height: 1000 });
    await page.addInitScript(value => localStorage.setItem("agent-bom-theme", value), theme);
    let requests = 0;
    await page.route("**/v1/**", route => {
      const url = new URL(route.request().url());
      if (url.pathname === "/v1/auth/me") return route.fulfill({ json: { authenticated: true, auth_required: false, tenant_id: "fixture", auth_method: "anonymous", role: "admin", configured_modes: [], recommended_ui_mode: "no_auth", memberships: [] } });
      if (url.pathname === "/v1/jobs") return route.fulfill({ json: { jobs: [], total: 0 } });
      if (url.pathname === "/v1/graph/agents") return route.fulfill({ json: { scan_id: "snapshot", agents: [node(root)], pagination: { total: 1 } } });
      if (url.pathname === "/v1/graph/incident-edges") {
        requests++;
        const id = url.searchParams.get("node_id")!;
        const children = id === root ? (url.searchParams.has("cursor") ? ["server:later"] : [left, right]) : [`${id}-child`];
        return route.fulfill({ json: { scan_id: "snapshot", snapshot_generation: "a".repeat(32), node_id: id, found: true, direction: "both", limit: 24, node: node(id), nodes: children.map(node), edges: children.map(target => ({ id: `${id}-${target}`, source: id, target, relationship: "uses", direction: "directed", weight: 1, evidence: {} })), next_cursor: id === root && !url.searchParams.has("cursor") ? "root-next" : null, completeness: { complete: true, truncated: false, sampled: false, status: "complete", total: null, returned: children.length, scope: "incident_edge_page", missing_endpoint_count: 0 } } });
      }
      return route.fulfill({ json: {} });
    });
    await page.goto("/graph?lens=context&scan=snapshot");
    const inspector = page.getByRole("complementary", { name: "Agent neighborhood inspector" });
    await inspector.getByText(/^Loaded entities \(\d+\)$/).click();
    for (const id of [left, right]) {
      await inspector.getByRole("button", { name: `${id.split(":")[1]} ${id}`, exact: true }).click();
      await inspector.getByRole("button", { name: "Expand connections", exact: true }).click();
      await expect(inspector.getByRole("button", { name: "Collapse connections", exact: true })).toBeVisible();
    }
    await inspector.getByRole("button", { name: "root agent:root", exact: true }).click();
    await inspector.getByRole("button", { name: "Load more relationships", exact: true }).click();
    await expect(page.getByRole("status").filter({ hasText: "loaded entities" })).toContainText("6 loaded entities · 5 loaded relationships");
    await inspector.getByRole("button", { name: "left server:left", exact: true }).click();
    await inspector.getByRole("button", { name: "Collapse connections", exact: true }).click();
    await expect(page.getByRole("status").filter({ hasText: "loaded entities" })).toContainText("5 loaded entities · 4 loaded relationships");
    await expect(inspector.getByRole("button", { name: "right-child server:right-child", exact: true })).toBeVisible();
    await expect(inspector.getByRole("button", { name: "later server:later", exact: true })).toBeVisible();
    await expect(inspector.getByRole("button", { name: "left-child server:left-child", exact: true })).toHaveCount(0);
    expect(requests).toBe(4);
    const canvas = page.getByLabel("Persisted neighborhood canvas", { exact: true });
    await page.getByRole("button", { name: "Fit all entities", exact: true }).click();
    await expect.poll(() => canvas.evaluate(element => {
      const bounds = element.getBoundingClientRect();
      return [...element.querySelectorAll(".react-flow__node")].every(node => {
        const box = node.getBoundingClientRect();
        return box.x >= bounds.x && box.right <= bounds.right && box.y >= bounds.y && box.bottom <= bounds.bottom;
      });
    })).toBe(true);
    await page.getByRole("button", { name: "Readable view of selected entity", exact: true }).click();
    await expect.poll(() => page.locator('.react-flow__node[data-id="server:left"]').evaluate(element => {
      const box = element.getBoundingClientRect();
      const bounds = element.closest('.context-map-canvas')!.getBoundingClientRect();
      return box.x >= bounds.x && box.right <= bounds.right && box.y >= bounds.y && box.bottom <= bounds.bottom;
    })).toBe(true);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
    await page.evaluate(() => window.scrollTo({ top: 0, behavior: "instant" }));
    await page.screenshot({ path: testInfo.outputPath(`collapse-${theme}-${width}.png`), fullPage: true });
  });
}
