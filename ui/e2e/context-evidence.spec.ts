import { expect, test } from "@playwright/test";

for (const theme of ["light", "dark"] as const) {
  test(`Context distinguishes package evidence and relationship branches in ${theme}`, async ({ page }, testInfo) => {
    await page.addInitScript(value => localStorage.setItem("agent-bom-theme", value), theme);
    const nodes = [
      { id: "agent:a", kind: "agent", label: "Analyst agent", metadata: {} },
      { id: "s", kind: "server", label: "Repo MCP", metadata: {} },
      { id: "v", kind: "vulnerability", label: "CVE-fixture", metadata: { severity: "critical" } },
      { id: "t", kind: "tool", label: "create_pull_request", metadata: {} },
      { id: "c", kind: "credential", label: "CREDENTIAL_REFERENCE", metadata: {} },
    ];
    const edges = [
      { source: "agent:a", target: "s", kind: "uses", metadata: {} },
      { source: "s", target: "v", kind: "vulnerable_to", metadata: { packages: ["example-package@1.0"] } },
      { source: "s", target: "t", kind: "provides", metadata: {} },
      { source: "s", target: "c", kind: "exposes", metadata: {} },
    ];
    await page.route("**/v1/**", route => {
      const path = new URL(route.request().url()).pathname;
      if (path.startsWith("/v1/auth/")) return route.fulfill({ json: { authenticated: true, tenant_id: "fixture", role: "analyst", permissions: ["read"] } });
      if (path === "/v1/jobs") return route.fulfill({ json: { jobs: [{ job_id: "fixture", status: "done", created_at: "2026-09-22T00:00:00Z" }, { job_id: "fixture2", status: "done", created_at: "2026-09-21T00:00:00Z" }], total: 2 } });
      if (path === "/v1/scan/fixture" || path === "/v1/scan/fixture2") return route.fulfill({ json: { job_id: "fixture", status: "done", result: { agents: [], blast_radius: [] } } });
      if (path.endsWith("/context-graph")) return route.fulfill({ json: { nodes, edges, lateral_paths: [], interaction_risks: [], stats: { total_nodes: 5, total_edges: 4, agent_count: 1, shared_server_count: 0, shared_credential_count: 0, lateral_path_count: 0, max_lateral_depth: 0, highest_path_risk: 0, interaction_risk_count: 0 } } });
      return route.fulfill({ status: 503, json: { detail: "Outside graph evidence fixture" } });
    });
    await page.goto("/graph?lens=context");
    await expect(page.getByText(/Paths are investigation leads/)).toBeVisible();
    await expect(page.getByText("Affected package: example-package@1.0", { exact: true })).toBeVisible();
    const labels = ["Configured server", "Package vulnerability", "Advertises tool", "Credential reference"];
    for (const label of labels) await expect(page.getByRole("button", { name: `Inspect relationship: ${label}`, exact: true })).toBeVisible();
    const receipt = page.getByRole("button", { name: "Inspect relationship: Package vulnerability", exact: true });
    await receipt.focus();
    await receipt.press("Enter");
    const details = page.getByRole("complementary", { name: "Agent neighborhood inspector" });
    await expect(details).toContainText("Repo MCP → CVE-fixture");
    await expect(details).toContainText("example-package@1.0");
    await expect(details).toContainText("does not prove a successful call");
    await page.getByRole("button", { name: "Close inspection", exact: true }).click();
    // Labels must size with their text and occupy separate branches after fit.
    await expect.poll(async () => {
      const boxes = await Promise.all(labels.map(label => page.getByRole("button", { name: `Inspect relationship: ${label}`, exact: true }).boundingBox()));
      return boxes.every((box, i) => box && boxes.slice(i + 1).every(other => other && (box.x + box.width <= other.x || other.x + other.width <= box.x || box.y + box.height <= other.y || other.y + other.height <= box.y)));
    }).toBe(true);
    await page.screenshot({ path: testInfo.outputPath(`context-evidence-${theme}.png`) });
    await page.locator('.react-flow__node[data-id="v"]').click();
    const inspector = page.getByRole("complementary", { name: "Agent neighborhood inspector" });
    await expect(inspector.getByRole("heading", { name: "CVE-fixture", exact: true })).toBeVisible();
    await inspector.getByRole("button", { name: "Close inspection", exact: true }).click();
    await page.locator("select").filter({ has: page.locator('option[value="fixture2"]') }).selectOption("fixture2");
    await expect(inspector.getByRole("heading", { name: "CVE-fixture", exact: true })).toHaveCount(0);
  });
}

for (const scenario of [
  { theme: "light", width: 1440, height: 1000 },
  { theme: "dark", width: 1440, height: 1000 },
  { theme: "light", width: 390, height: 844 },
] as const) {
  test(`Context neighborhood exploration stays evidence scoped ${scenario.theme} ${scenario.width}`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width: scenario.width, height: scenario.height });
    await page.addInitScript(theme => localStorage.setItem("agent-bom-theme", theme), scenario.theme);
    const nodes = [
      { id: "agent:a", kind: "agent", label: "Analyst agent", metadata: {} },
      { id: "server:a", kind: "server", label: "Repository MCP", metadata: {} },
      { id: "vulnerability:a", kind: "vulnerability", label: "CVE-fixture", metadata: { severity: "high" } },
      { id: "tool:a", kind: "tool", label: "read_repository", metadata: {} },
      { id: "credential:a", kind: "credential", label: "CREDENTIAL_REFERENCE", metadata: {} },
      { id: "agent:peer", kind: "agent", label: "Peer agent", metadata: {} },
      { id: "server:peer", kind: "server", label: "Peer MCP", metadata: {} },
      { id: "tool:deep", kind: "tool", label: "peer_only_tool", metadata: {} },
      { id: "agent:unrelated", kind: "agent", label: "Unrelated agent", metadata: {} },
    ];
    const edges = [
      { source: "agent:a", target: "server:a", kind: "uses", metadata: {} },
      { source: "server:a", target: "vulnerability:a", kind: "vulnerable_to", metadata: { packages: ["fixture-package@1.0"] } },
      { source: "server:a", target: "tool:a", kind: "provides", metadata: {} },
      { source: "server:a", target: "credential:a", kind: "exposes", metadata: {} },
      { source: "agent:peer", target: "server:a", kind: "uses", metadata: {} },
      { source: "agent:peer", target: "server:peer", kind: "uses", metadata: {} },
      { source: "server:peer", target: "tool:deep", kind: "provides", metadata: {} },
    ];
    await page.route("**/v1/**", route => {
      const path = new URL(route.request().url()).pathname;
      if (path.startsWith("/v1/auth/")) return route.fulfill({ json: { authenticated: true, tenant_id: "fixture", role: "analyst", permissions: ["read"] } });
      if (path === "/v1/jobs") return route.fulfill({ json: { jobs: [{ job_id: "fixture", status: "done", created_at: "2026-09-22T00:00:00Z" }], total: 1 } });
      if (path === "/v1/scan/fixture") return route.fulfill({ json: { job_id: "fixture", status: "done", result: { agents: [{ name: "a", agent_type: "custom", servers: [] }], blast_radius: [] } } });
      if (path.endsWith("/context-graph")) return route.fulfill({ json: { nodes, edges, lateral_paths: [], interaction_risks: [], stats: { total_nodes: nodes.length, total_edges: edges.length, agent_count: 3, shared_server_count: 0, shared_credential_count: 0, lateral_path_count: 0, max_lateral_depth: 0, highest_path_risk: 0, interaction_risk_count: 0 } } });
      return route.fulfill({ status: 503, json: { detail: "Outside neighborhood fixture" } });
    });
    await page.goto("/graph?lens=context");
    await page.locator("select").filter({ has: page.locator('option[value="a"]') }).selectOption("a");
    await page.getByRole("button", { name: "Neighborhood", exact: true }).click();
    const inspector = page.getByRole("complementary", { name: "Agent neighborhood inspector" });
    await expect(inspector).toBeVisible();
    await expect(page.getByLabel("Neighborhood depth", { exact: true })).toHaveValue("2");
    await expect(page.locator('.react-flow__node[data-id="agent:peer"]')).toBeAttached();
    await expect(page.locator('.react-flow__node[data-id="agent:unrelated"]')).toHaveCount(0);
    await expect(page.locator('.react-flow__node[data-id="tool:deep"]')).toHaveCount(0);
    await expect(page.locator(".react-flow__node")).toHaveCount(6);
    await expect(page.locator(".react-flow__edge")).toHaveCount(5);
    await expect(inspector).toContainText(/unknown|not established|not prove|not proof/i);
    await expect(inspector.locator("summary").filter({ hasText: /^agent\s+2$/ })).toBeVisible();
    await expect(inspector.locator("summary").filter({ hasText: /^tool\s+1$/ })).toBeVisible();
    await page.getByLabel("Relationship direction", { exact: true }).selectOption("out");
    await expect(page.locator('.react-flow__node[data-id="agent:peer"]')).toHaveCount(0);
    await page.getByLabel("Relationship direction", { exact: true }).selectOption("both");
    await page.getByLabel("Neighborhood depth", { exact: true }).selectOption("1");
    await expect(page.locator('.react-flow__node[data-id="tool:a"]')).toHaveCount(0);
    await page.getByLabel("Neighborhood depth", { exact: true }).selectOption("2");
    if (scenario.width < 768) {
      await inspector.locator("summary").filter({ hasText: /^agent\s+2$/ }).click();
      await inspector.getByRole("button", { name: "Peer agent", exact: true }).click();
    } else await page.locator('.react-flow__node[data-id="agent:peer"]').click();
    await expect(inspector).toContainText("Peer agent");
    await inspector.getByRole("button", { name: "Expand connections", exact: true }).click();
    await expect(page.locator('.react-flow__node[data-id="server:peer"]')).toBeAttached();
    await expect(page.locator('.react-flow__node[data-id="agent:unrelated"]')).toHaveCount(0);
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
    await inspector.scrollIntoViewIfNeeded();
    await page.screenshot({ path: testInfo.outputPath(`context-neighborhood-${scenario.theme}-${scenario.width}.png`), fullPage: true });
    await page.getByRole("button", { name: "Close inspection", exact: true }).click();
    await page.getByRole("button", { name: "Reset neighborhood", exact: true }).click();
    await expect(page.getByLabel("Neighborhood depth", { exact: true })).toHaveValue("2");
  });
}
