import { expect, test, type Page, type TestInfo } from "@playwright/test";

const scanId = "scan-dense-graph";
const previousScanId = "scan-dense-graph-prev";
const createdAt = "2026-05-08T16:00:00Z";

type GraphNode = {
  id: string;
  entity_type: string;
  label: string;
  category_uid: number;
  class_uid: number;
  type_uid: number;
  status: string;
  risk_score: number;
  severity: string;
  severity_id: number;
  first_seen: string;
  last_seen: string;
  attributes: Record<string, unknown>;
  compliance_tags: string[];
  data_sources: string[];
  dimensions: Record<string, string>;
};

type GraphEdge = {
  id: string;
  source: string;
  target: string;
  relationship: string;
  direction: "directed" | "bidirectional";
  weight: number;
  traversable: boolean;
  first_seen: string;
  last_seen: string;
  evidence: Record<string, unknown>;
  activity_id: number;
};

function node(
  id: string,
  entityType: string,
  label: string,
  severity = "none",
  riskScore = 0,
  attributes: Record<string, unknown> = {},
): GraphNode {
  const severityRank: Record<string, number> = { none: 0, low: 1, medium: 2, high: 3, critical: 4 };
  return {
    id,
    entity_type: entityType,
    label,
    category_uid: 0,
    class_uid: 0,
    type_uid: 0,
    status: "active",
    risk_score: riskScore,
    severity,
    severity_id: severityRank[severity] ?? 0,
    first_seen: createdAt,
    last_seen: createdAt,
    attributes,
    compliance_tags: [],
    data_sources: ["e2e"],
    dimensions: {},
  };
}

function edge(source: string, target: string, relationship: string, weight = 1): GraphEdge {
  return {
    id: `${source}->${target}:${relationship}`,
    source,
    target,
    relationship,
    direction: "directed",
    weight,
    traversable: true,
    first_seen: createdAt,
    last_seen: createdAt,
    evidence: {},
    activity_id: 1,
  };
}

function buildDenseGraph() {
  const nodes: GraphNode[] = [
    node("agent:desktop", "agent", "Desktop Agent", "high", 8.8, { agent_type: "desktop" }),
    node("server:filesystem", "server", "filesystem MCP", "high", 8.2, { command: "npx @modelcontextprotocol/server-filesystem" }),
    node("server:repo", "server", "repository MCP", "high", 7.9, { command: "npx @modelcontextprotocol/server-repository" }),
    node("cred:repo-token", "credential", "Repository token", "high", 8.4),
    node("tool:write-file", "tool", "write_file", "medium", 5.8),
  ];
  const edges: GraphEdge[] = [
    edge("agent:desktop", "server:filesystem", "uses"),
    edge("agent:desktop", "server:repo", "uses"),
    edge("server:repo", "cred:repo-token", "exposes_cred"),
    edge("cred:repo-token", "tool:write-file", "reaches_tool"),
  ];

  for (const server of ["filesystem", "repo"]) {
    const serverId = `server:${server}`;
    for (let index = 1; index <= 8; index += 1) {
      const packageId = `pkg:${server}:${index}`;
      const vulnId = `cve:${server}:${index}`;
      const severity = index % 3 === 0 ? "critical" : "high";
      nodes.push(node(packageId, "package", `${server}-package-${index}`, severity, 7 + index / 10));
      nodes.push(node(vulnId, "vulnerability", `CVE-2026-${server === "filesystem" ? "10" : "20"}${index}`, severity, 8 + index / 10));
      edges.push(edge(serverId, packageId, "depends_on"));
      edges.push(edge(packageId, vulnId, "vulnerable_to", 1.5));
    }
  }

  return {
    scan_id: scanId,
    tenant_id: "default",
    created_at: createdAt,
    nodes,
    edges,
    attack_paths: [
      {
        source: "agent:desktop",
        target: "cve:filesystem:3",
        hops: ["agent:desktop", "server:filesystem", "pkg:filesystem:3", "cve:filesystem:3"],
        edges: [
          "agent:desktop->server:filesystem:uses",
          "server:filesystem->pkg:filesystem:3:depends_on",
          "pkg:filesystem:3->cve:filesystem:3:vulnerable_to",
        ],
        composite_risk: 9.4,
        summary: "Desktop Agent can reach a critical vulnerable package through filesystem MCP.",
        credential_exposure: [],
        tool_exposure: ["write_file"],
        vuln_ids: ["CVE-2026-103"],
      },
    ],
    interaction_risks: [],
    stats: {
      total_nodes: nodes.length,
      total_edges: edges.length,
      node_types: { agent: 1, server: 2, package: 16, vulnerability: 16, credential: 1, tool: 1 },
      severity_counts: { critical: 4, high: 17, medium: 1 },
      relationship_types: { uses: 2, depends_on: 16, vulnerable_to: 16, exposes_cred: 1, reaches_tool: 1 },
      attack_path_count: 1,
      interaction_risk_count: 0,
      max_attack_path_risk: 9.4,
      highest_interaction_risk: 0,
    },
    pagination: {
      total: nodes.length,
      offset: 0,
      limit: 250,
      has_more: false,
    },
  };
}

async function routeGraphPage(page: Page, graph = buildDenseGraph()) {

  await page.route("**/health", async (route) => {
    await route.fulfill({ contentType: "application/json", body: JSON.stringify({ status: "ok" }) });
  });
  await page.route("**/v1/auth/me", async (route) => {
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        authenticated: true,
        auth_required: false,
        configured_modes: [],
        recommended_ui_mode: "no_auth",
        auth_method: null,
        subject: null,
        role: null,
        role_summary: null,
        tenant_id: "default",
        memberships: [],
        request_id: "req-graph-e2e",
        trace_id: "trace-graph-e2e",
        span_id: "span-graph-e2e",
      }),
    });
  });
  await page.route("**/v1/posture/counts", async (route) => {
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ critical: 4, high: 17, medium: 1, low: 0, total: 22, kev: 0, compound_issues: 1 }),
    });
  });
  await page.route("**/v1/graph/snapshots?**", async (route) => {
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify([
        { scan_id: scanId, created_at: createdAt, node_count: graph.nodes.length, edge_count: graph.edges.length, risk_summary: graph.stats.severity_counts },
        { scan_id: previousScanId, created_at: "2026-05-08T15:00:00Z", node_count: 12, edge_count: 20, risk_summary: { high: 8 } },
      ]),
    });
  });
  await page.route("**/v1/graph/diff?**", async (route) => {
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        nodes_added: ["cve:filesystem:3", "cve:repo:3"],
        nodes_removed: [],
        nodes_changed: ["agent:desktop"],
        edges_added: [["pkg:filesystem:3", "cve:filesystem:3", "vulnerable_to"]],
        edges_removed: [],
      }),
    });
  });
  await page.route("**/v1/graph?**", async (route) => {
    await route.fulfill({ contentType: "application/json", body: JSON.stringify(graph) });
  });
}

async function captureGraphScreenshot(page: Page, testInfo: TestInfo, theme: "dark" | "light") {
  await expect(page.getByRole("heading", { name: "Lineage Graph" })).toBeVisible();
  await expect(page.getByText("Relevant paths", { exact: true }).first()).toBeHidden();
  // Evidence, lens selection, and advanced controls now share one
  // collapsed-by-default shelf so the canvas owns the fold. Nested controls
  // remain available on demand without becoming first-view chrome.
  await expect(page.getByText("Advanced controls", { exact: true })).toBeHidden();
  const evidenceControls = page.getByTestId("graph-evidence-controls");
  await expect(evidenceControls).not.toHaveAttribute("open", "");
  await expect(evidenceControls.getByText("Filters and evidence", { exact: true })).toBeVisible();

  const largeOverview = page.getByTestId("large-graph-overview");
  const application = page.getByRole("application");
  const desktopNode = application.getByText("Desktop Agent", { exact: true });
  // Graph mode is selected after the bounded graph finishes loading. Under a
  // busy CI worker, branching on an immediate `isVisible()` can choose the
  // React Flow path before either renderer has mounted. Wait for one truthful
  // renderer signal, then assert against that renderer.
  await expect.poll(async () =>
    (await largeOverview.isVisible()) || (await desktopNode.isVisible()),
  ).toBe(true);
  if (await largeOverview.isVisible()) {
    await expect(largeOverview).toBeVisible();
    await expect(page.getByText("Pan, zoom, search, filter, and select nodes for evidence.")).toBeVisible();
  } else {
    await expect(desktopNode).toBeVisible();
    await expect(application.getByText("CVE-2026-103", { exact: true })).toBeVisible();
    // Topology with the legend collapsed — proves the nodes fill the canvas
    // and read clearly at default zoom.
    await application.screenshot({
      path: testInfo.outputPath(`lineage-graph-canvas-${theme}.png`),
    });
    // Open the on-canvas legend so the per-entity-type icons are captured.
    const legendToggle = page.getByRole("button", { name: /show legend/i });
    if (await legendToggle.isVisible()) {
      await legendToggle.click();
    } else {
      await evidenceControls.locator(":scope > summary").click();
    }
    // Graph chrome may render the legend in the evidence shelf instead of on
    // the canvas. Verify that either route keeps the legend readable.
    await expect(page.getByText("Legend", { exact: true }).first()).toBeVisible();
    await page.screenshot({
      path: testInfo.outputPath(`lineage-graph-legend-${theme}.png`),
      fullPage: false,
    });
  }
  await page.screenshot({
    path: testInfo.outputPath(`lineage-graph-dense-${theme}.png`),
    fullPage: true,
  });
}

for (const theme of ["dark", "light"] as const) {
  test(`lineage graph dense ${theme} view stays focused and screenshot-ready`, async ({ page }, testInfo) => {
    await routeGraphPage(page);
    await page.addInitScript((selectedTheme) => {
      window.localStorage.setItem("agent-bom-theme", selectedTheme);
    }, theme);

    await page.goto("/graph", { waitUntil: "domcontentloaded" });
    await page.waitForURL((url) => url.pathname === "/graph" && url.searchParams.has("layers"), {
      waitUntil: "domcontentloaded",
    });
    await captureGraphScreenshot(page, testInfo, theme);
  });
}

test("lineage graph controls zoom, move, persist, lock, fit, and auto-layout", async ({ page }) => {
  await routeGraphPage(page);
  await page.goto("/graph", { waitUntil: "domcontentloaded" });
  await page.waitForURL((url) => url.pathname === "/graph" && url.searchParams.has("layers"));

  const canvas = page.locator(".react-flow").last();
  const node = canvas.locator(".react-flow__node").first();
  await expect(node).toBeVisible();
  const before = await node.boundingBox();
  expect(before).not.toBeNull();

  await expect(page.getByRole("button", { name: "Edit layout" })).toBeHidden();
  await page.getByText("Layout", { exact: true }).click();
  await page.getByRole("button", { name: "Edit layout" }).click();
  const editableNode = await node.boundingBox();
  const canvasBox = await canvas.boundingBox();
  expect(editableNode).not.toBeNull();
  expect(canvasBox).not.toBeNull();
  await page.mouse.move(
    editableNode!.x + editableNode!.width / 2,
    editableNode!.y + editableNode!.height / 2,
  );
  await page.mouse.down();
  await page.mouse.move(canvasBox!.x + 220, canvasBox!.y + 220, { steps: 8 });
  await page.mouse.up();
  await expect.poll(() => page.evaluate(() =>
    Object.keys(localStorage).some((key) => key.startsWith("agent-bom:graph-presentation:v1:")),
  )).toBe(true);

  await canvas.hover();
  await page.mouse.wheel(0, -240);
  await page.getByRole("button", { name: "Fit visible graph" }).click();
  await page.getByRole("button", { name: "Auto-layout graph" }).click();
  await page.getByRole("button", { name: "Lock layout" }).click();
  await expect(page.getByRole("button", { name: "Edit layout" })).toBeVisible();
});


for (const activation of ["pointer", "keyboard"] as const) {
  test(`SBOM finding group restores every relationship with ${activation} activation`, async ({ page }) => {
    const source = node("source:sbom", "source_file", "SBOM: reviewed-project.cdx.json");
    const pkg = node("package:reviewed", "package", "Reviewed package", "high", 0, { name: "reviewed-package", version: "1.0" });
    const findings = Array.from({ length: 22 }, (_, index) => node(`finding:${index}`, "vulnerability", `Fixture finding ${index}`, "high"));
    const graph = buildDenseGraph();
    graph.nodes = [source, pkg, ...findings];
    graph.edges = [
      edge(source.id, pkg.id, "contains"),
      ...findings.flatMap((finding) => [edge(pkg.id, finding.id, "has_cve"), edge(source.id, finding.id, "has_cve")]),
    ].map((relationship) => ({ ...relationship, traversable: false, evidence: { source: "bounded SBOM fixture" } }));
    graph.pagination = { total: 24, offset: 0, limit: 250, has_more: false };
    await routeGraphPage(page, graph);
    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.goto(`/graph?scan=${scanId}&rollup=0`);
    const pill = page.getByRole("button", { name: "Expand 22 findings", exact: true });
    await expect(pill).toBeVisible();
    await expect(page.locator(".react-flow__node")).toHaveCount(3);
    await expect(page.locator(".react-flow__edge")).toHaveCount(3);
    if (activation === "keyboard") {
      await pill.focus();
      await pill.press("Enter");
    } else {
      await pill.hover();
      await pill.click();
    }
    await expect(pill).toHaveCount(0);
    await expect(page.locator(".react-flow__edge")).toHaveCount(45);
    await page.getByRole("button", { name: "Fit View", exact: true }).click();
    await expect(page.locator(".react-flow__node")).toHaveCount(24);
    const renderedEdges = await page.locator(".react-flow__edge").evaluateAll((elements) => elements.map((element) => element.getAttribute("data-id")));
    expect(new Set(renderedEdges).size).toBe(45);
    const packageNode = page.getByTestId(`rf__node-${pkg.id}`);
    await packageNode.hover();
    await packageNode.click();
    await expect(page.getByRole("heading", { name: "Reviewed package", exact: true })).toBeVisible();
  });
}
test("graph minimap mask follows light and dark themes without remounting", async ({ page }) => {
  await routeGraphPage(page);
  await page.goto("/graph?view=investigation", { waitUntil: "domcontentloaded" });
  const mask = page.locator(".react-flow__minimap-mask");
  await expect(mask).toBeVisible();
  for (const theme of ["light", "dark"] as const) {
    await page.evaluate((value) => {
      document.documentElement.dataset.theme = value;
    }, theme);
    const expected = theme === "light"
      ? "rgba(226, 232, 240, 0.82)"
      : "rgba(24, 24, 27, 0.82)";
    await expect(mask).toHaveCSS("fill", expected);
  }
});

test("grouped findings remain legible in both themes", async ({ page }, testInfo) => {
  await routeGraphPage(page);
  const graph = buildDenseGraph();
  graph.nodes = [node("pkg:example", "package", "example@1.0.0")];
  graph.edges = [];
  graph.attack_paths = [];
  for (let index = 0; index < 22; index++) {
    const finding = `finding:${index}`;
    graph.nodes.push(node(finding, "vulnerability", `Fixture finding ${index}`, "high"));
    graph.edges.push(edge("pkg:example", finding, "vulnerable_to"));
  }
  await page.route("**/v1/graph?**", async (route) => {
    await route.fulfill({ json: graph });
  });
  await page.goto("/graph?view=investigation", { waitUntil: "domcontentloaded" });
  const pill = page.getByTestId("cluster-pill");
  await expect(pill).toBeVisible();
  for (const theme of ["light", "dark"] as const) {
    await page.evaluate((value) => { document.documentElement.dataset.theme = value; }, theme);
    const contrasts = await pill.evaluate((element) => {
      // Rasterize computed CSS colors so the check also handles Tailwind's
      // oklch colors. Composite translucent text/fills against the real surface.
      const canvas = document.createElement("canvas");
      canvas.width = canvas.height = 1;
      const context = canvas.getContext("2d")!;
      const rgba = (color: string) => {
        context.clearRect(0, 0, 1, 1);
        context.fillStyle = color;
        context.fillRect(0, 0, 1, 1);
        return Array.from(context.getImageData(0, 0, 1, 1).data);
      };
      const composite = (front: number[], back: number[]) =>
        front.slice(0, 3).map((value, index) =>
          value * front[3]! / 255 + back[index]! * (1 - front[3]! / 255));
      const luminance = (rgb: number[]) => rgb.map((value) => {
        const channel = value / 255;
        return channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4;
      }).reduce((sum, value, index) => sum + value * [0.2126, 0.7152, 0.0722][index]!, 0);
      const surface = rgba(getComputedStyle(document.documentElement).getPropertyValue("--surface"));
      const background = composite(rgba(getComputedStyle(element).backgroundColor), surface);
      return [...element.querySelectorAll("span")].map((label) => {
        const foreground = composite(rgba(getComputedStyle(label).color), background);
        const light = Math.max(luminance(foreground), luminance(background));
        const dark = Math.min(luminance(foreground), luminance(background));
        return (light + 0.05) / (dark + 0.05);
      });
    });
    expect(contrasts).toHaveLength(2);
    for (const contrast of contrasts) expect(contrast).toBeGreaterThanOrEqual(4.5);
    await pill.screenshot({ path: testInfo.outputPath(`finding-group-${theme}.png`) });
  }
});
