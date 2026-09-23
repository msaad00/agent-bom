import { expect, test } from "@playwright/test";
const root = "agent:endpoint-a:desktop";
const peer = "agent:endpoint-b:desktop";
const server = "server:endpoint-a:files";
const generation = "a".repeat(32);
const node = (id: string, entity_type: string, label: string) => ({ id, entity_type, label, attributes: {}, severity: "none", severity_id: 0, risk_score: 0, status: "active", data_sources: ["fixture"], dimensions: {}, compliance_tags: [] });
const agent = node(root, "agent", "Desktop");
const service = node(server, "server", "File server");
const pkg = node("package:fixture", "package", "Fixture package");
const relation = (source: string, target: string, relationship: string) => ({ id: `${source}-${target}`, source, target, relationship, direction: source === root ? "bidirectional" : "directed", weight: 1, evidence: { basis: "configured" } });
for (const theme of ["light", "dark"] as const) for (const width of [1440, 390]) {
  test(`persisted Context exact identity and generation ${theme} ${width}`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width, height: 1000 });
    await page.addInitScript(value => localStorage.setItem("agent-bom-theme", value), theme);
    const requests: URL[] = [];
    let stale = false;
    let legacyRequests = 0;
    await page.route("**/v1/**", route => {
      const url = new URL(route.request().url());
      const path = url.pathname;
      if (path === "/v1/auth/me") return route.fulfill({ json: { authenticated: true, auth_required: false, tenant_id: "fixture-tenant", auth_method: "anonymous", role: "admin", configured_modes: [], recommended_ui_mode: "no_auth", memberships: [] } });
      if (path === "/v1/jobs") return route.fulfill({ json: { jobs: [{ job_id: "job-fixture", status: "done" }], total: 1 } });
      if (path === "/v1/scan/job-fixture") return route.fulfill({ json: { job_id: "job-fixture", status: "done", result: { scan_id: "persisted-fixture", agents: [] } } });
      if (path === "/v1/graph/agents") return route.fulfill({ json: { scan_id: "persisted-fixture", agents: [agent, node(peer, "agent", "Desktop")], pagination: { total: 2, limit: 24 } } });
      if (path.endsWith("/context-graph")) { legacyRequests++; return route.fulfill({ json: {} }); }
      if (path === "/v1/graph/incident-edges") {
        requests.push(url);
        if (stale) return route.fulfill({ status: 400, json: { detail: "Invalid or stale incident relationship page; restart from the first page" } });
        const id = url.searchParams.get("node_id")!;
        const isRoot = id === root;
        return route.fulfill({ json: { scan_id: "persisted-fixture", snapshot_generation: generation, node_id: id, found: true, direction: url.searchParams.get("direction"), limit: 24, node: isRoot ? agent : service,
          nodes: isRoot ? [service] : [pkg], edges: [isRoot ? relation(root, server, "uses") : relation(server, pkg.id, "depends_on")], next_cursor: isRoot ? null : "next-page", completeness: { complete: isRoot, truncated: !isRoot, sampled: false, status: isRoot ? "complete" : "truncated", total: null, returned: 1, scope: "incident_edge_page", missing_endpoint_count: 0 } } });
      }
      return route.fulfill({ json: {} });
    });
    await page.goto(`/graph?lens=context${theme === "light" && width === 1440 ? "&scan=persisted-fixture" : ""}`);
    const inspector = page.getByRole("complementary", { name: "Agent neighborhood inspector" });
    await expect(inspector.getByRole("heading", { name: "Desktop", exact: true })).toBeVisible();
    await expect(page.getByRole("combobox", { name: "Agent scope" })).toHaveValue(root);
    expect(requests[0]?.searchParams.get("scan_id")).toBe("persisted-fixture");
    expect(legacyRequests).toBe(0);
    await expect(inspector).toContainText("Recorded connection");
    await expect(page.locator(".react-flow__edge-path").first()).toHaveAttribute("marker-start", /url/);
    await expect(page.locator(".react-flow__edge-path").first()).toHaveAttribute("marker-end", /url/);
    await inspector.getByText("Loaded entities", { exact: true }).click();
    await inspector.getByRole("button", { name: /File server.*server:endpoint-a:files/ }).click();
    await inspector.getByRole("button", { name: "Expand connections", exact: true }).click();
    await expect(inspector.getByRole("button", { name: "Load more relationships" })).toBeVisible();
    expect(requests.at(-1)?.searchParams.get("node_id")).toBe(server);
    expect(requests.at(-1)?.searchParams.get("snapshot_generation")).toBe(generation);
    await expect(page.getByRole("status").filter({ hasText: "loaded entities" })).toContainText("3 loaded entities · 2 loaded relationships · total unknown");
    await expect(inspector.getByRole("link", { name: "Investigate reach & permissions" })).toHaveAttribute("href", `/security-graph?scan=persisted-fixture&investigate=1&root=${encodeURIComponent(server)}&lens=lineage`);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
    await page.evaluate(() => window.scrollTo(0, 0));
    await page.screenshot({ path: testInfo.outputPath(`persisted-context-${theme}-${width}.png`), fullPage: true });
    stale = true;
    await inspector.getByRole("button", { name: "Load more relationships" }).click();
    await expect(page.getByRole("alert").filter({ hasText: "Snapshot changed" })).toContainText("Snapshot changed");
    await expect(page.getByRole("status").filter({ hasText: "loaded entities" })).toContainText("0 loaded entities");
    stale = false;
    await page.getByRole("button", { name: "Restart neighborhood" }).click();
    await expect(page.getByRole("status").filter({ hasText: "loaded entities" })).toContainText("2 loaded entities");
    expect(requests.at(-1)?.searchParams.has("snapshot_generation")).toBe(false);
  });
}

test("high-degree Context starts compact and focuses a returned canonical entity", async ({ page }) => {
  const services = Array.from({ length: 24 }, (_, i) => node(`server:hub:${i}`, "server", `Service ${i}`));
  await page.route("**/v1/**", route => {
    const url = new URL(route.request().url());
    if (url.pathname === "/v1/auth/me") return route.fulfill({ json: { authenticated: true, auth_required: false, tenant_id: "fixture", auth_method: "anonymous", role: "admin", configured_modes: [], recommended_ui_mode: "no_auth", memberships: [] } });
    if (url.pathname === "/v1/jobs") return route.fulfill({ json: { jobs: [{ job_id: "hub", status: "done" }], total: 1 } });
    if (url.pathname === "/v1/scan/hub") return route.fulfill({ json: { job_id: "hub", status: "done", result: { agents: [] } } });
    if (url.pathname === "/v1/graph/agents") return route.fulfill({ json: { scan_id: "hub", agents: [agent], pagination: { total: 1 } } });
    if (url.pathname === "/v1/graph/incident-edges") return route.fulfill({ json: { scan_id: "hub", snapshot_generation: generation, node_id: root, found: true, direction: "both", limit: 24, node: agent, nodes: services, edges: services.map(service => relation(root, service.id, "uses")), next_cursor: "more", completeness: { status: "truncated", complete: false, truncated: true, sampled: false, total: null, returned: 24, missing_endpoint_count: 0, scope: "incident_edge_page" } } });
    return route.fulfill({ json: {} });
  });
  await page.goto("/graph?lens=context");
  const status = page.getByRole("status").filter({ hasText: "loaded entities" });
  await expect(status).toContainText("25 loaded entities · 24 loaded relationships · total unknown. Canvas: 8 entities");
  await expect(page.locator(".react-flow__node")).toHaveCount(8);
  await page.getByRole("button", { name: "Expand canvas", exact: true }).click();
  await expect(page.locator(".react-flow__node")).toHaveCount(24);
  await page.getByRole("button", { name: "Compact canvas", exact: true }).click();
  const inspector = page.getByRole("complementary", { name: "Agent neighborhood inspector" });
  await inspector.getByText("Loaded entities", { exact: true }).click();
  await inspector.getByRole("button", { name: "Service 23 server:hub:23", exact: true }).click();
  await inspector.getByRole("button", { name: "Focus here" }).click();
  await expect(page.locator('.react-flow__node[data-id="server:hub:23"]')).toBeVisible();
  await expect(page.locator(".react-flow__node")).toHaveCount(8);
});
