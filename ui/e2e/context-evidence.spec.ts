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
    const details = page.getByRole("region", { name: "Relationship evidence" });
    await expect(details).toContainText("Repo MCP → CVE-fixture");
    await expect(details).toContainText("example-package@1.0");
    await expect(details).toContainText("does not establish permission");
    await details.getByRole("button", { name: "Close relationship" }).click();
    // Labels must size with their text and occupy separate branches after fit.
    await expect.poll(async () => {
      const boxes = await Promise.all(labels.map(label => page.getByRole("button", { name: `Inspect relationship: ${label}`, exact: true }).boundingBox()));
      return boxes.every((box, i) => box && boxes.slice(i + 1).every(other => other && (box.x + box.width <= other.x || other.x + other.width <= box.x || box.y + box.height <= other.y || other.y + other.height <= box.y)));
    }).toBe(true);
    await page.screenshot({ path: testInfo.outputPath(`context-evidence-${theme}.png`) });
    await page.locator('.react-flow__node[data-id="v"]').click();
    await expect(page.getByRole("tablist", { name: "Node detail sections" })).toBeVisible();
    await page.locator("select").filter({ has: page.locator('option[value="fixture2"]') }).selectOption("fixture2");
    await expect(page.getByRole("tablist", { name: "Node detail sections" })).toHaveCount(0);
  });
}
