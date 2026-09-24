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
    let fullReportRequests = 0;
    await page.route("**/v1/**", route => {
      const url = new URL(route.request().url());
      const path = url.pathname;
      if (path === "/v1/auth/me") return route.fulfill({ json: { authenticated: true, auth_required: false, tenant_id: "fixture-tenant", auth_method: "anonymous", role: "admin", configured_modes: [], recommended_ui_mode: "no_auth", memberships: [] } });
      if (path === "/v1/jobs") return route.fulfill({ json: { jobs: [{ job_id: "job-fixture", status: "done" }], total: 1 } });
      if (path === "/v1/scan/job-fixture") { fullReportRequests++; return route.fulfill({ status: 500, json: {} }); }
      if (path === "/v1/scan/job-fixture/status") return route.fulfill({ json: { job_id: "job-fixture", status: "done", graph_scan_id: "persisted-fixture" } });
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
    expect(fullReportRequests).toBe(0);
    await expect(inspector).toContainText("Bidirectional ↔ Recorded connection");
    // Focusing the root changes card dimensions without changing node IDs.
    await inspector.getByRole("button", { name: "Focus here", exact: true }).click();
    await expect(page.getByTestId("context-overview-title")).toHaveCount(0);
    await expect.poll(async () => page.getByLabel("Persisted neighborhood canvas", { exact: true }).evaluate(canvas => {
      const bounds = canvas.getBoundingClientRect();
      return [...canvas.querySelectorAll(".react-flow__node")].every(node => {
        const box = node.getBoundingClientRect();
        return box.x >= bounds.x && box.right <= bounds.right && box.y >= bounds.y && box.bottom <= bounds.bottom;
      });
    })).toBe(true);
    await page.getByRole("button", { name: "Back to neighborhood", exact: true }).click();
    await expect(page.getByTestId("context-overview-title")).toHaveCount(2);

    await expect(page.locator(".react-flow__edge-path").first()).toHaveAttribute("marker-start", /url/);
    await expect(page.locator(".react-flow__edge-path").first()).toHaveAttribute("marker-end", /url/);
    await inspector.getByText(/^Loaded entities \(\d+\)$/).click();
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
  let incidentRequests = 0;
  const services = Array.from({ length: 24 }, (_, i) => node(`server:hub:${i}`, "server", `Service ${i}`));
  await page.route("**/v1/**", route => {
    const url = new URL(route.request().url());
    if (url.pathname === "/v1/auth/me") return route.fulfill({ json: { authenticated: true, auth_required: false, tenant_id: "fixture", auth_method: "anonymous", role: "admin", configured_modes: [], recommended_ui_mode: "no_auth", memberships: [] } });
    if (url.pathname === "/v1/jobs") return route.fulfill({ json: { jobs: [{ job_id: url.searchParams.get("offset") === "24" ? "older" : "hub", status: "done" }], total: 25 } });
    if (url.pathname === "/v1/scan/hub/status") return route.fulfill({ json: { job_id: "hub", status: "done", graph_scan_id: "hub" } });
    if (url.pathname === "/v1/graph/agents") return route.fulfill({ json: { scan_id: "hub", agents: [agent], pagination: { total: 1 } } });
    if (url.pathname === "/v1/graph/incident-edges") { incidentRequests++; return route.fulfill({ json: { scan_id: "hub", snapshot_generation: generation, node_id: root, found: true, direction: "both", limit: 24, node: agent, nodes: services, edges: services.map(service => relation(root, service.id, "uses")), next_cursor: "more", completeness: { status: "truncated", complete: false, truncated: true, sampled: false, total: null, returned: 24, missing_endpoint_count: 0, scope: "incident_edge_page" } } }); }
    return route.fulfill({ json: {} });
  });
  await page.goto("/graph?lens=context");
  const status = page.getByRole("status").filter({ hasText: "loaded entities" });
  await expect(status).toContainText("25 loaded entities · 24 loaded relationships · total unknown. Canvas: 8 entities");
  await expect(page.locator(".react-flow__node")).toHaveCount(8);
  const canvas = page.getByLabel("Persisted neighborhood canvas");
  await expect.poll(() => canvas.evaluate(element => {
    const bounds = element.getBoundingClientRect();
    return [...element.querySelectorAll<HTMLElement>(".react-flow__node")].every(node => {
      const box = node.getBoundingClientRect();
      return box.x >= bounds.x && box.right <= bounds.right && box.y >= bounds.y && box.bottom <= bounds.bottom;
    });
  })).toBe(true);
  const title = page.getByTestId("context-overview-title").first();
  expect(await title.evaluate(element => {
    const node = element.closest<HTMLElement>(".react-flow__node")!;
    return parseFloat(getComputedStyle(element).fontSize) * node.getBoundingClientRect().width / node.offsetWidth;
  })).toBeGreaterThanOrEqual(12);
  const requestsBeforePaging = incidentRequests;
  await page.getByRole("button", { name: "Next scans", exact: true }).click();
  await expect(page.getByRole("option", { name: "older", exact: true })).toBeAttached();
  await expect(page.getByLabel("Completed scan")).toHaveValue("hub");
  expect(incidentRequests).toBe(requestsBeforePaging);
  await page.getByRole("button", { name: "Expand canvas", exact: true }).click();
  await expect(page.locator(".react-flow__node")).toHaveCount(24);
  await page.getByRole("button", { name: "Compact canvas", exact: true }).click();
  const inspector = page.getByRole("complementary", { name: "Agent neighborhood inspector" });
  await inspector.getByText(/^Loaded entities \(\d+\)$/).click();
  await inspector.getByRole("button", { name: "Service 23 server:hub:23", exact: true }).click();
  await inspector.getByRole("button", { name: "Focus here" }).click();
  await expect(page.locator('.react-flow__node[data-id="server:hub:23"]')).toBeVisible();
  await expect(page.locator(".react-flow__node")).toHaveCount(2);
  const loadedBefore = await status.textContent();
  const requestCount = incidentRequests;
  await page.getByRole("button", { name: "Back to neighborhood", exact: true }).click();
  await expect(page.locator(".react-flow__node")).toHaveCount(8);
  await expect(inspector.getByRole("heading", { name: "Service 23", exact: true })).toBeVisible();
  expect(loadedBefore).toContain("25 loaded entities · 24 loaded relationships");
  await expect(status).toContainText("25 loaded entities · 24 loaded relationships");
  expect(incidentRequests).toBe(requestCount);
  await inspector.getByLabel("Find loaded entity").fill("server:hub:12");
  await expect(inspector.getByRole("button", { name: "Service 12 server:hub:12", exact: true })).toBeVisible();
  await expect(inspector.getByRole("button", { name: "Service 23 server:hub:23", exact: true })).toHaveCount(0);
});

test("missing snapshot identity remains unavailable instead of guessing the job ID", async ({ page }) => {
  let graphRequests = 0;
  await page.route("**/v1/**", route => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/v1/auth/me") return route.fulfill({ json: { authenticated: true, auth_required: false, tenant_id: "fixture", auth_method: "anonymous", role: "admin", configured_modes: [], recommended_ui_mode: "no_auth", memberships: [] } });
    if (path === "/v1/jobs") return route.fulfill({ json: { jobs: [{ job_id: "unmapped", status: "done" }], total: 1 } });
    if (path === "/v1/scan/unmapped/status") return route.fulfill({ json: { job_id: "unmapped", status: "done", graph_scan_id: null } });
    if (path === "/v1/graph/agents" || path === "/v1/graph/incident-edges") graphRequests++;
    return route.fulfill({ json: {} });
  });
  await page.goto("/graph?lens=context");
  await expect(page.getByRole("alert").filter({ hasText: "Persisted snapshot identity unavailable" })).toBeVisible();
  expect(graphRequests).toBe(0);
});

test("client navigation to another explicit snapshot replaces the Context workspace", async ({ page }) => {
  const incidentScans: string[] = [];
  await page.route("**/v1/**", route => {
    const url = new URL(route.request().url());
    const scan = url.searchParams.get("scan_id") || "first";
    if (url.pathname === "/v1/auth/me") return route.fulfill({ json: { authenticated: true, auth_required: false, tenant_id: "fixture", auth_method: "anonymous", role: "admin", configured_modes: [], recommended_ui_mode: "no_auth", memberships: [] } });
    if (url.pathname === "/v1/jobs") return route.fulfill({ json: { jobs: [], total: 0 } });
    if (url.pathname === "/v1/graph/agents") return route.fulfill({ json: { scan_id: scan, agents: [agent], pagination: { total: 1 } } });
    if (url.pathname === "/v1/graph/incident-edges") {
      incidentScans.push(scan);
      return route.fulfill({ json: { scan_id: scan, snapshot_generation: generation, node_id: root, found: true, direction: "both", limit: 24, node: agent, nodes: [service], edges: [relation(root, server, "uses")], next_cursor: null, completeness: { status: "complete", complete: true, truncated: false, total: null, returned: 1, missing_endpoint_count: 0, scope: "incident_edge_page" } } });
    }
    return route.fulfill({ json: {} });
  });
  await page.goto("/graph?lens=context&scan=first");
  const inspector = page.getByRole("complementary", { name: "Agent neighborhood inspector" });
  await expect(inspector.getByRole("link", { name: "Investigate reach & permissions" })).toHaveAttribute("href", /scan=first&/);
  await page.evaluate(() => window.history.pushState(null, "", "/graph?lens=context&scan=second"));
  await expect(inspector.getByRole("link", { name: "Investigate reach & permissions" })).toHaveAttribute("href", /scan=second&/);
  expect(incidentScans).toEqual(["first", "second"]);
  await page.getByRole("button", { name: /Cloud/ }).click();
  await expect(page).toHaveURL(/scan=second&lens=cloud/);
});

for (const theme of ["light", "dark"] as const) for (const width of [1440, 390]) {
  test(`conditional admin evidence stays disclosed ${theme} ${width}`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width, height: 1000 });
    await page.addInitScript(value => localStorage.setItem("agent-bom-theme", value), theme);
    const role = { ...node("role:conditional", "role", "Deployment role"), attributes: {
      admin_equivalence_status: "conditional_admin", admin_equivalence_resource_scopes: ["arn:aws:iam::123456789012:*"]
    } };
    await page.route("**/v1/**", route => {
      const url = new URL(route.request().url());
      if (url.pathname === "/v1/auth/me") return route.fulfill({ json: { authenticated: true, auth_required: false, tenant_id: "fixture", auth_method: "anonymous", role: "admin", configured_modes: [], recommended_ui_mode: "no_auth", memberships: [] } });
      if (url.pathname === "/v1/jobs") return route.fulfill({ json: { jobs: [{ job_id: "iam", status: "done" }], total: 1 } });
      if (url.pathname === "/v1/scan/iam/status") return route.fulfill({ json: { job_id: "iam", status: "done", graph_scan_id: "iam" } });
      if (url.pathname === "/v1/graph/agents") return route.fulfill({ json: { scan_id: "iam", agents: [agent], pagination: { total: 1 } } });
      if (url.pathname === "/v1/graph/incident-edges") return route.fulfill({ json: { scan_id: "iam", snapshot_generation: generation, node_id: root, found: true, direction: "both", limit: 24, node: agent, nodes: [role], edges: [relation(root, role.id, "assumes")], next_cursor: null, completeness: { status: "complete", complete: true, truncated: false, sampled: false, total: 1, returned: 1, missing_endpoint_count: 0, scope: "incident_edge_page" } } });
      return route.fulfill({ json: {} });
    });
    await page.goto("/graph?lens=context");
    const inspector = page.getByLabel("Agent neighborhood inspector");
    await inspector.getByText(/^Loaded entities \(\d+\)$/).click();
    await inspector.getByRole("button", { name: /Deployment role.*role:conditional/ }).click();
    await expect(inspector.getByText("Conditional admin", { exact: true })).not.toBeVisible();
    await inspector.getByText("Recorded identity", { exact: true }).click();
    await expect(inspector.getByText("Conditional admin", { exact: true })).toBeVisible();
    await expect(inspector.getByText(/request context has not been verified/)).toBeVisible();
    await expect(inspector.getByText(/Scope: arn:aws:iam/)).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
    await page.screenshot({ path: testInfo.outputPath(`admin-${theme}-${width}.png`), fullPage: true });
  });
}
