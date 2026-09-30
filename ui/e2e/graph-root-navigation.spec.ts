import { expect, test } from "@playwright/test";

const first = "agent:first";
const exact = "server:with spaces/+&?";
const generation = "a".repeat(32);
const node = (id: string, label: string) => ({ id, label, entity_type: id.startsWith("agent:") ? "agent" : "server", attributes: {}, severity: "none", severity_id: 0, risk_score: 0, status: "active", data_sources: ["fixture"], dimensions: {}, compliance_tags: [] });
for (const theme of ["light", "dark"]) for (const width of [390, 1440]) {
  test(`canonical graph roots survive navigation ${theme} ${width}`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width, height: 1000 });
    await page.addInitScript(value => localStorage.setItem("agent-bom-theme", value), theme);
    const requested: string[] = [];
    await page.route("**/v1/**", route => {
      const url = new URL(route.request().url());
      if (url.pathname === "/v1/auth/me") return route.fulfill({ json: { authenticated: true, auth_required: false, tenant_id: "fixture", auth_method: "anonymous", role: "admin", configured_modes: [], recommended_ui_mode: "no_auth", memberships: [] } });
      if (url.pathname === "/v1/jobs" || url.pathname === "/v1/graph/snapshots") return route.fulfill({ status: 503, json: { detail: "List unavailable" } });
      if (url.pathname === "/v1/graph/agents") return route.fulfill({ json: { scan_id: "snapshot", agents: [node(first, "First agent")], pagination: { total: 1 } } });
      if (url.pathname === "/v1/graph/incident-edges") {
        const id = url.searchParams.get("node_id")!;
        requested.push(id);
        const found = id !== "server:missing";
        return route.fulfill({ json: { scan_id: "snapshot", snapshot_generation: generation, node_id: id, found, direction: "both", limit: 24,
          node: found ? node(id, id === exact ? "Exact file server" : "Second server") : null,
          nodes: found ? [node(first, "First agent")] : [], edges: found ? [{ id: "relation", source: id, target: first, relationship: "uses", direction: "directed", weight: 1, evidence: { basis: "configured" } }] : [],
          next_cursor: null, completeness: { complete: true, truncated: false, sampled: false, status: "complete", total: found ? 1 : 0, returned: found ? 1 : 0, scope: "incident_edge_page", missing_endpoint_count: 0 } } });
      }
      return route.fulfill({ json: {} });
    });
    const params = new URLSearchParams({ lens: "context", scan: "snapshot", root: exact, agent: "Carried display name" });
    await page.goto(`/graph?${params}`);
    const inspector = page.getByRole("complementary", { name: "Agent neighborhood inspector" });
    await expect(inspector.getByRole("heading", { name: "Exact file server", exact: true })).toBeVisible();
    await expect(page.getByLabel("Agent scope", { exact: true })).toHaveValue(exact);
    expect(requested).toEqual([exact]);
    await expect(page.getByRole("alert").filter({ hasText: "Unable to load completed scans" })).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
    await page.evaluate(() => window.scrollTo({ top: 0, behavior: "instant" }));
    await page.screenshot({ path: testInfo.outputPath(`exact-root-${theme}-${width}.png`), fullPage: true });
    params.set("root", "server:second");
    await page.evaluate(href => window.history.pushState(null, "", href), `/graph?${params}`);
    await expect(inspector.getByRole("heading", { name: "Second server", exact: true })).toBeVisible();
    await expect(inspector.getByRole("heading", { name: "Exact file server", exact: true })).toHaveCount(0);
    params.set("root", exact); params.set("lens", "mesh");
    await page.evaluate(href => window.history.pushState(null, "", href), `/graph?${params}`);
    await expect(page.getByRole("heading", { name: "Agent Mesh", exact: true })).toBeVisible();
    await expect(inspector.getByRole("heading", { name: "Exact file server", exact: true })).toBeVisible();
    expect(requested).toEqual([exact, "server:second", exact]);
    params.set("root", "server:missing");
    await page.evaluate(href => window.history.pushState(null, "", href), `/graph?${params}`);
    await expect(page.getByLabel("Agent scope", { exact: true })).toHaveValue("server:missing");
    await expect.poll(() => requested.at(-1)).toBe("server:missing");
    await expect(page.locator(".react-flow__node")).toHaveCount(0);
    expect(requested).not.toContain(first);
  });
}
