import { expect, test, type Locator, type Page, type TestInfo } from "@playwright/test";

const scanId = "scan-large-overview";
const createdAt = "2026-05-08T16:00:00Z";

for (const theme of ["light", "dark"] as const) {
  for (const width of [1440, 390]) {
    test(`shared scope counts stay readable in ${theme} at ${width}px`, async ({ page }, testInfo) => {
      await routeLargeGraphPage(page);
      await page.setViewportSize({ width, height: 900 });
      await page.addInitScript(value => localStorage.setItem("agent-bom-theme", value), theme);
      await page.route("**/v1/graph/rollup?**", route => route.fulfill({ json: {
        scan_id: scanId, tenant_id: "default", created_at: createdAt, mode: "rollup", filters: {},
        top_level: ["one", "two"].map(name => ({
          id: `account:${name}`, label: `Scope ${name}`, entity_type: "account", severity: "high",
          is_container: true, has_children: true, direct_child_count: 1,
          aggregate: { descendant_count: 1, by_type: { package: 1 }, severity_counts: { high: 1 },
            worst_severity: "high", worst_severity_rank: 3, internet_exposed: false,
            toxic_combo: false, exposed_count: 0, toxic_count: 0 },
        })),
        edges: [], summary: { total_nodes: 3, total_edges: 2, top_level_count: 2, container_count: 2 },
        aggregate_count_metadata: { basis: "returned_entry_descendants", definition: "Descendants of returned scopes.",
          distinct_descendants: 1, descendant_memberships: 2, shared_descendants: 1, extra_memberships: 1,
          additive: false, source_truncated: false, reason: "" },
        completeness: { status: "complete", complete: true, truncated: false, returned: 2, total: 2 },
      } }));
      await page.goto(`/graph?scan=${scanId}&rollup=1`);
      const notice = page.getByText(/This level: 1 unique descendant · 2 scope memberships/);
      await expect(notice).toBeVisible();
      await expect(page.getByTestId("graph-evidence-controls").locator("summary").first()).toContainText("2 nodes and scopes · 1,241 nodes in snapshot");
      await expect(page.getByTestId("graph-evidence-controls").locator("summary").first()).not.toContainText("bounded canvas");
      expect(await notice.evaluate(el => el.scrollWidth <= el.clientWidth)).toBe(true);
      await notice.scrollIntoViewIfNeeded();
      await page.screenshot({ path: testInfo.outputPath(`shared-scopes-${theme}-${width}.png`) });
    });
  }
}

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
  direction: "directed";
  weight: number;
  traversable: boolean;
  first_seen: string;
  last_seen: string;
  evidence: Record<string, unknown>;
  activity_id: number;
};

function node(id: string, entityType: string, label: string, severity = "none", riskScore = 0): GraphNode {
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
    attributes: {},
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

function buildLargeGraph() {
  const nodes: GraphNode[] = [node("agent:large", "agent", "Large Estate Agent", "high", 9)];
  const edges: GraphEdge[] = [edge("agent:large", "pkg:0", "uses")];

  for (let index = 0; index < 620; index += 1) {
    const packageId = `pkg:${index}`;
    const vulnerabilityId = `cve:${index}`;
    nodes.push(node(packageId, "package", `large-package-${index}`, "high", 7.2));
    nodes.push(node(vulnerabilityId, "vulnerability", `CVE-2026-${String(index).padStart(4, "0")}`, "high", 8));
    if (index > 0) {
      edges.push(edge(`pkg:${index - 1}`, packageId, "depends_on"));
    }
    edges.push(edge(packageId, vulnerabilityId, "vulnerable_to", 1.2));
  }

  for (let index = 0; index < 620; index += 1) {
    edges.push(edge(`pkg:${index}`, `pkg:${(index + 301) % 620}`, "related_to", 0.8));
  }

  return {
    scan_id: scanId,
    tenant_id: "default",
    created_at: createdAt,
    nodes,
    edges,
    attack_paths: [],
    interaction_risks: [],
    stats: {
      total_nodes: nodes.length,
      total_edges: edges.length,
      node_types: { agent: 1, package: 620, vulnerability: 620 },
      severity_counts: { high: nodes.length },
      relationship_types: { uses: 1, depends_on: 619, vulnerable_to: 620, related_to: 620 },
      attack_path_count: 0,
      interaction_risk_count: 0,
      max_attack_path_risk: 0,
      highest_interaction_risk: 0,
    },
    pagination: {
      total: nodes.length,
      offset: 0,
      limit: 500,
      has_more: true,
    },
  };
}

async function routeLargeGraphPage(page: Page, environmentFixture = false) {
  const graph = buildLargeGraph();
  if (environmentFixture) graph.nodes.forEach((item, index) => {
    item.dimensions = { cloud_provider: "aws", environment: index % 3 ? "production" : "development" };
    item.attributes = { ...item.attributes, account_scope: index % 2 ? "payments" : "analytics", region: "us-east-1" };
  });
  const root = graph.nodes.find((entry) => entry.id === "pkg:42") ?? graph.nodes[0];
  const focusedNodes = graph.nodes.filter((entry) => ["agent:large", "pkg:41", "pkg:42", "pkg:43"].includes(entry.id));
  const focusedEdges = graph.edges.filter((entry) =>
    focusedNodes.some((node) => node.id === entry.source) && focusedNodes.some((node) => node.id === entry.target),
  );

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
        request_id: "req-large-overview",
        trace_id: "trace-large-overview",
        span_id: "span-large-overview",
      }),
    });
  });
  await page.route("**/v1/posture/counts", async (route) => {
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ critical: 0, high: 621, medium: 0, low: 0, total: 621, kev: 0, compound_issues: 0 }),
    });
  });
  await page.route("**/v1/posture", async (route) => {
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        score: 72,
        grade: "C",
        findings: { critical: 0, high: 621, medium: 0, low: 0, total: 621 },
        last_scan_at: createdAt,
      }),
    });
  });
  await page.route("**/v1/graph/snapshots?**", async (route) => {
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify([
        {
          scan_id: scanId,
          created_at: createdAt,
          node_count: graph.nodes.length,
          edge_count: graph.edges.length,
          risk_summary: graph.stats.severity_counts,
        },
      ]),
    });
  });
  await page.route("**/v1/graph/diff?**", async (route) => {
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ nodes_added: [], nodes_removed: [], nodes_changed: [], edges_added: [], edges_removed: [] }),
    });
  });
  await page.route("**/v1/graph/search**", async (route) => {
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        query: "large-package-42",
        results: [root],
        pagination: { total: 1, offset: 0, limit: 16, has_more: false },
      }),
    });
  });
  await page.route("**/v1/graph/attack-paths?**", async (route) => {
    await route.fulfill({ contentType: "application/json", body: JSON.stringify(graph) });
  });
  await page.route("**/v1/graph/scenarios", async (route) => {
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ schema: "graph.scenarios.v1", count: 0, scenarios: [] }),
    });
  });
  await page.route("**/v1/graph/rollup?**", async (route) => {
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        scan_id: scanId,
        tenant_id: "default",
        created_at: createdAt,
        mode: "rollup",
        filters: {},
        top_level: [],
        summary: {
          total_nodes: graph.nodes.length,
          total_edges: graph.edges.length,
          top_level_count: 0,
          container_count: 0,
        },
      }),
    });
  });
  await page.route("**/v1/graph/query", async (route) => {
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        scan_id: scanId,
        tenant_id: "default",
        created_at: createdAt,
        nodes: focusedNodes,
        edges: focusedEdges,
        attack_paths: [],
        interaction_risks: [],
        stats: {
          total_nodes: focusedNodes.length,
          total_edges: focusedEdges.length,
          node_types: { agent: 1, package: 3 },
          severity_counts: { high: focusedNodes.length },
          relationship_types: { uses: 1, depends_on: 2 },
          attack_path_count: 0,
          interaction_risk_count: 0,
          max_attack_path_risk: 0,
          highest_interaction_risk: 0,
        },
        roots: ["pkg:42"],
        direction: "both",
        max_depth: 4,
        max_nodes: 800,
        max_edges: 8000,
        timeout_ms: 2500,
        budget: {},
        depth_by_node: { "pkg:42": 0, "pkg:41": 1, "pkg:43": 1, "agent:large": 2 },
        truncated: false,
      }),
    });
  });
  await page.route("**/v1/graph?**", async (route) => {
    await route.fulfill({ contentType: "application/json", body: JSON.stringify(graph) });
  });
}

async function expectSigmaCanvases(page: Page) {
  const stage = page.getByTestId("sigma-graph-overview-canvas");
  await expect(stage).toBeVisible();
  await page.waitForFunction(() => {
    const container = document.querySelector<HTMLElement>('[data-testid="sigma-graph-overview-canvas"]');
    if (!container) return false;
    const canvases = [...container.querySelectorAll("canvas")];
    return canvases.some((canvas) => canvas.width > 1 && canvas.height > 1);
  });
  const canvasSummary = await stage.evaluate((element) => {
    const canvases = [...element.querySelectorAll("canvas")];
    return {
      count: canvases.length,
      drawable: canvases.filter((canvas) => canvas.width > 1 && canvas.height > 1).length,
    };
  });
  expect(canvasSummary.count).toBeGreaterThan(0);
  expect(canvasSummary.drawable).toBeGreaterThan(0);
}

async function captureRenderedRegion(page: Page, region: Locator, path: string) {
  // The region is laid out asynchronously behind a canvas renderer, so a single
  // boundingBox() read can land before the element has non-zero geometry. Poll
  // for real geometry instead: that is the structural claim worth asserting.
  // The poll re-resolves the locator on every attempt, so it rides out the
  // re-renders that detach an already-resolved element handle.
  await expect
    .poll(async () => (await region.boundingBox())?.width ?? 0, { timeout: 15_000 })
    .toBeGreaterThan(0);

  const box = await region.boundingBox();
  expect(box).not.toBeNull();
  if (!box) return;

  // The screenshot is a debugging artifact, not an assertion — every functional
  // claim about this region is already covered by the canvas-pixel checks. A
  // capture that times out under a loaded runner must not fail the suite.
  //
  // scrollIntoViewIfNeeded belongs here rather than above it: it waits for the
  // element to hold a stable bounding box, which a continuously animating sigma
  // canvas never does, and it operates on a resolved handle that a re-render can
  // detach. Both failure modes are "the screenshot did not happen", not "the
  // graph did not render" — so neither may fail the suite.
  try {
    await region.scrollIntoViewIfNeeded({ timeout: 5_000 });
    await page.screenshot({
      path,
      animations: "disabled",
      clip: box,
      timeout: 15_000,
    });
  } catch (error) {
    console.warn(`screenshot capture skipped for ${path}: ${(error as Error).message}`);
  }
}

test("broad graph defaults to the WebGL overview above threshold", async ({ page }, testInfo: TestInfo) => {
  test.setTimeout(60_000);
  const failedGraphResponses: string[] = [];
  page.on("response", (response) => {
    if (response.status() >= 500 && response.url().includes("/v1/graph/")) {
      failedGraphResponses.push(response.url());
    }
  });
  await routeLargeGraphPage(page);

  await page.goto("/graph?vulnOnly=0&severity=&depth=3&pageSize=500&layers=agent,package", {
    waitUntil: "domcontentloaded",
  });

  // No renderer flag: a broad estate now renders on Sigma by default, the
  // hand-rolled 2D canvas is retired.
  const sigma = page.getByTestId("sigma-graph-overview");
  await expect(sigma).toBeVisible({ timeout: 30_000 });
  await expect(sigma.getByText("Estate map", { exact: true })).toBeVisible();
  await expect(page.getByText(/Displayed:/)).toBeVisible();
  await expectSigmaCanvases(page);
  expect(failedGraphResponses).toEqual([]);
  await captureRenderedRegion(
    page,
    sigma,
    testInfo.outputPath("sigma-graph-overview.png"),
  );
});

/**
 * The WebGL overview used to paint a fixed `#050505` stage with near-white
 * labels, so on a light page the biggest element on screen was a black
 * rectangle. Sigma cannot use CSS classes, so the only way to know it tracks
 * the theme is to read what the stage behind it actually painted.
 */
for (const theme of ["dark", "light"] as const) {
  test(`webgl overview stage follows the ${theme} theme by default`, async ({ page }, testInfo: TestInfo) => {
    test.setTimeout(60_000);
    await routeLargeGraphPage(page);
    await page.addInitScript((selected) => {
      window.localStorage.setItem("agent-bom-theme", selected);
    }, theme);

    await page.goto("/graph?vulnOnly=0&severity=&depth=3&pageSize=500&layers=agent,package", {
      waitUntil: "domcontentloaded",
    });
    const sigma = page.getByTestId("sigma-graph-overview");
    await expect(sigma).toBeVisible({ timeout: 30_000 });
    await expectSigmaCanvases(page);

    // Sigma's own canvases are transparent; the stage is the element behind
    // them, which used to be a hardcoded `bg-[#050505]`.
    const stage = await page
      .getByTestId("sigma-graph-overview-canvas")
      .evaluate((element) => getComputedStyle(element.parentElement!).backgroundColor);
    const channels = stage.match(/\d+/g)!.slice(0, 3).map(Number);
    const luminance = (channels[0]! + channels[1]! + channels[2]!) / 3;
    if (theme === "light") expect(luminance).toBeGreaterThan(160);
    else expect(luminance).toBeLessThan(96);

    await captureRenderedRegion(page, sigma, testInfo.outputPath(`sigma-webgl-${theme}.png`));
  });
}

/**
 * The WebGL canvas hands assistive technology nothing on its own; it carries a
 * text equivalent naming every node and relationship it draws.
 */
test("webgl overview exposes its nodes and edges as text", async ({ page }) => {
  test.setTimeout(60_000);
  await routeLargeGraphPage(page);

  await page.goto("/graph?vulnOnly=0&severity=&depth=3&pageSize=500&layers=agent,package", {
    waitUntil: "domcontentloaded",
  });
  await expect(page.getByTestId("sigma-graph-overview")).toBeVisible({ timeout: 30_000 });

  const canvas = page.getByTestId("sigma-graph-overview-canvas");
  await expect(canvas).toHaveAttribute("role", "img");
  await expect(canvas).toHaveAttribute("aria-describedby", "sigma-graph-overview-text");

  const equivalent = page.getByRole("region", {
    name: "Graph contents, text equivalent",
    includeHidden: true,
  });
  await expect(equivalent).toBeAttached();
  await expect(equivalent.getByRole("table", { includeHidden: true })).toBeAttached();
  // Real rows, not an empty shell: the fixture draws well over a thousand nodes.
  const rows = equivalent.locator("tbody tr");
  expect(await rows.count()).toBeGreaterThan(10);
  await expect(equivalent).toContainText(/Listing \d+ of [\d,]+ drawn nodes/);
  await expect(equivalent).toContainText(/Listing \d+ of [\d,]+ drawn relationships/);
});

test("retired renderer=webgl opt-in still lands on the WebGL overview", async ({ page }, testInfo: TestInfo) => {
  test.setTimeout(60_000);
  await routeLargeGraphPage(page);

  // The flag is a backward-compatible no-op now; a deep link that still carries
  // it must not break — it resolves to the same default Sigma overview.
  await page.goto("/graph?renderer=webgl&vulnOnly=0&severity=&depth=3&pageSize=500&layers=agent,package", {
    waitUntil: "domcontentloaded",
  });

  const sigma = page.getByTestId("sigma-graph-overview");
  await expect(sigma).toBeVisible({ timeout: 30_000 });
  // Exact: the surface's screen-reader text equivalent names the renderer too.
  await expect(sigma.getByText("Estate map", { exact: true })).toBeVisible();
  await expect(sigma.getByText(/Select an asset to investigate its related evidence/)).toBeVisible();
  await expectSigmaCanvases(page);
  await captureRenderedRegion(page, sigma, testInfo.outputPath("sigma-webgl-overview.png"));
});


test("identity investigation links preserve the selected root during client navigation", async ({ page }) => {
  // App Router can render the destination before its history update commits.
  // Make that ordering deterministic instead of relying on machine speed.
  await page.addInitScript(() => {
    const push = history.pushState.bind(history);
    history.pushState = (data, unused, url) => {
      if (String(url).startsWith("/security-graph")) {
        setTimeout(() => push(data, unused, url), 500);
      } else push(data, unused, url);
    };
  });
  await page.route("**/v1/**", (route) => route.fulfill({ status: 404, json: { detail: "Unavailable in fixture" } }));
  await routeLargeGraphPage(page);
  await page.route("**/v1/graph/nhi/governance", (route) => route.fulfill({ json: {
    scan_id: scanId, counts: { over_granted: 1 },
    identities: [{ node_id: "pkg:42", name: "Investigated identity", risk_score: 86 }],
  } }));
  await page.goto("/identity");
  await page.getByRole("tab", { name: "Discovered identity risk" }).click();
  const query = page.waitForRequest((request) => request.url().endsWith("/v1/graph/query") && request.method() === "POST");
  await page.getByRole("link", { name: "Investigated identity 86" }).click();
  expect((await query).postDataJSON()).toMatchObject({ scan_id: scanId, roots: ["pkg:42"], max_depth: 1, max_nodes: 80, max_edges: 320 });
  await expect(page.getByRole("textbox", { name: "Search nodes, tags, severities, or attributes" })).toHaveValue("Investigated identity");
  await expect(page).toHaveURL(/root=pkg%3A42/);
  await expect(page.getByTestId("sigma-graph-overview")).toBeHidden();
});


test("root investigations expose depth and direction controls with bounded requests", async ({ page }) => {
  await page.route("**/v1/**", (route) => route.fulfill({ status: 404, json: { detail: "Fixture unavailable" } }));
  await routeLargeGraphPage(page);
  const initial = page.waitForRequest((request) => request.url().endsWith("/v1/graph/query"));
  await page.goto(`/graph?scan=${scanId}&root=pkg%3A42`);
  expect((await initial).postDataJSON()).toMatchObject({ roots: ["pkg:42"], max_depth: 1, max_nodes: 80 });
  await expect(page.getByRole("combobox", { name: "Traversal depth" })).toHaveValue("1");
  await expect(page.getByTestId("graph-headline-metrics")).toHaveCount(0);
  await expect(page.getByText("Analysis status unavailable", { exact: true })).toHaveCount(0);
  const deeper = page.waitForRequest((request) => request.url().endsWith("/v1/graph/query") && request.postDataJSON().max_depth === 2);
  await page.getByRole("combobox", { name: "Traversal depth" }).selectOption("2");
  expect((await deeper).postDataJSON()).toMatchObject({ roots: ["pkg:42"], scan_id: scanId, max_nodes: 80, max_edges: 320 });
  const reverse = page.waitForRequest((request) => request.url().endsWith("/v1/graph/query") && request.postDataJSON().direction === "reverse");
  await page.getByRole("combobox", { name: "Traversal direction" }).selectOption("reverse");
  expect((await reverse).postDataJSON()).toMatchObject({ roots: ["pkg:42"], max_depth: 2 });
});

for (const width of [1100, 1440]) {
  test(`focused graph remains visible beside resized details at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 1000 });
    await routeLargeGraphPage(page);
    await page.goto(`/graph?scan=${scanId}&root=pkg%3A42`);
    const drawer = page.getByTestId("graph-entity-drawer");
    const canvas = page.locator(".react-flow");
    const selected = canvas.locator('[data-id="pkg:42"]');
    await expect(selected).toBeVisible();
    const visibleBesideDetails = async () => {
      const nodeBounds = await selected.boundingBox();
      const canvasBounds = await canvas.boundingBox();
      const drawerBounds = await drawer.boundingBox();
      return Boolean(nodeBounds && canvasBounds && drawerBounds &&
        canvasBounds.x + canvasBounds.width <= drawerBounds.x + 1 &&
        nodeBounds.x >= canvasBounds.x &&
        nodeBounds.x + nodeBounds.width <= drawerBounds.x + 1);
    };
    await expect.poll(visibleBesideDetails).toBe(true);
    await drawer.getByRole("separator", { name: "Resize drawer" }).press("ArrowLeft");
    await page.getByRole("button", { name: "Focus selection", exact: true }).click();
    await expect.poll(visibleBesideDetails).toBe(true);
    await page.getByRole("button", { name: "Switch to light theme" }).click();
    await expect.poll(visibleBesideDetails).toBe(true);
  });
}

test("scope summary does not inherit the unrelated node-page warning", async ({ page }) => {
  await routeLargeGraphPage(page);
  await page.route("**/v1/graph/rollup?**", (route) => route.fulfill({ json: {
    scan_id: scanId, tenant_id: "default", created_at: createdAt, mode: "rollup", filters: {},
    top_level: [{ id: "org:estate", label: "Complete estate scope", entity_type: "org", severity: "high",
      is_container: true, has_children: true, direct_child_count: 620,
      aggregate: { descendant_count: 1240, by_type: { package: 620, vulnerability: 620 },
        severity_counts: { high: 1240 }, worst_severity: "high", worst_severity_rank: 3,
        internet_exposed: false, toxic_combo: false, exposed_count: 0, toxic_count: 0 } }],
    edges: [], summary: { total_nodes: 1241, total_edges: 1860, top_level_count: 1, container_count: 1 },
    completeness: { status: "complete", returned: 1, total: 1, truncated: false, reasons: [] },
  } }));
  await page.goto("/security-graph");
  await expect(page.getByRole("group", { name: "Complete estate scope, org", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Summary", exact: true }).click();
  await expect(page.getByRole("region", { name: "Risk-prioritized estate scopes" })).toContainText("Complete estate scope");
  await expect(page.getByText(/This node view includes only part/)).toHaveCount(0);
  await expect(page.getByText("node_page_limit", { exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Drill in", exact: true })).toBeVisible();
});


test("blast radius distinguishes related nodes from assets and keeps the type breakdown optional", async ({ page }) => {
  await routeLargeGraphPage(page);
  const root = node("pkg:42", "package", "large-package-42", "high", 7.2);
  await page.route("**/v1/graph/node/**", (route) => route.fulfill({ json: {
    node: root, edges_in: [], edges_out: [], neighbors: [], sources: [],
    impact: { affected_count: 3, affected_by_type: { package: 1, agent: 1, vulnerability: 1 }, max_depth_reached: 2 },
  } }));
  await page.route("**/v1/graph/impact?**", (route) => route.fulfill({ json: {
    node_id: root.id, affected_count: 3, affected_nodes: ["pkg:41", "agent:large", "cve:41"],
    affected_by_type: { package: 1, agent: 1, vulnerability: 1 }, max_depth_reached: 2,
  } }));
  await page.goto(`/graph?scan=${scanId}&root=pkg%3A42`);
  await page.getByRole("button", { name: "Show blast radius", exact: true }).click();
  await expect(page.getByText("3 upstream related nodes connected to large-package-42", { exact: true })).toBeVisible();
  const breakdown = page.locator("details").filter({ has: page.locator("summary", { hasText: "Related nodes by type (3)" }) });
  await expect(breakdown).not.toHaveAttribute("open", "");
  await breakdown.locator("summary").click();
  await expect(breakdown.getByText("Vulnerability: 1", { exact: true })).toBeVisible();
  await expect(page.getByText(/Graph relationships do not establish compromise/)).toBeVisible();
});

for (const theme of ["light", "dark"] as const) {
  test(`summary package traversal preserves finding evidence in ${theme}`, async ({ page }, testInfo) => {
    await routeLargeGraphPage(page);
    await page.addInitScript((value) => localStorage.setItem("agent-bom-theme", value), theme);
    await page.setViewportSize({ width: 1440, height: 1000 });
    const root = node("pkg:42", "package", "pyyaml@5.3", "none", 0);
    const finding = "vulnerability:CVE-2020-14343";
    await page.route("**/v1/graph/rollup?**", (route) => route.fulfill({ json: {
      scan_id: scanId, tenant_id: "default", created_at: createdAt, mode: "rollup", filters: {},
      top_level: [{ ...root, is_container: false, has_children: false, direct_child_count: 0,
        aggregate: { descendant_count: 0, by_type: {}, severity_counts: {}, worst_severity: "none",
          worst_severity_rank: 0, internet_exposed: false, toxic_combo: false, exposed_count: 0, toxic_count: 0 } }],
      edges: [], summary: { total_nodes: 1241, total_edges: 1860, top_level_count: 1, container_count: 0 },
      completeness: { status: "complete", returned: 1, total: 1, truncated: false, reasons: [] },
    } }));
    await page.route("**/v1/graph/node/**", (route) => route.fulfill({ json: {
      node: root, edges_out: [edge(root.id, finding, "vulnerable_to")], edges_in: [edge(finding, root.id, "affects")],
      neighbors: [finding], sources: ["scan"], impact: { affected_count: 0, affected_by_type: {}, max_depth_reached: 0 },
    } }));
    await page.goto(`/graph?scan=${scanId}`);
    await page.getByRole("button", { name: "Summary", exact: true }).click();
    await page.getByRole("button", { name: "Inspect pyyaml@5.3 (pkg:42)", exact: true }).click();
    await expect(page.getByTestId("graph-drawer-panel-overview").getByText("Findings", { exact: true })).toBeVisible();
    await expect(page.getByText("No known findings on this package node")).toHaveCount(0);
    await page.screenshot({ path: testInfo.outputPath(`package-evidence-${theme}.png`) });
  });

  test(`package instance summary identifies the selected image in ${theme}`, async ({ page }, testInfo) => {
    await routeLargeGraphPage(page);
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.addInitScript((value) => localStorage.setItem("agent-bom-theme", value), theme);
    await page.route("**/v1/graph/rollup?**", route => route.fulfill({ json: {
      scan_id: scanId, tenant_id: "default", created_at: createdAt, mode: "rollup", filters: {},
      top_level: ["billing", "claims"].map((name, index) => ({ id: `pkg:${42 + index}`, label: "pyyaml@5.3", entity_type: "package", severity: "high",
        context: { image: `${name}:1.0`, environment: "production", account: "northstar-001" },
        is_container: false, has_children: false, direct_child_count: 0,
        aggregate: { descendant_count: 0, by_type: {}, severity_counts: {}, worst_severity: "none", worst_severity_rank: 0,
          internet_exposed: false, toxic_combo: false, exposed_count: 0, toxic_count: 0 } })),
      edges: [], summary: { total_nodes: 2, total_edges: 0, top_level_count: 2, container_count: 0 },
      completeness: { status: "complete", complete: true, truncated: false, returned: 2, total: 2 },
    } }));
    await page.goto("/graph");
    await page.getByRole("button", { name: "Summary", exact: true }).click();
    const summary = page.getByTestId("graph-rollup-decision-surface");
    await expect(summary.getByText(/image: billing:1.0/)).toBeVisible();
    await expect(summary.getByText(/image: claims:1.0/)).toBeVisible();
    await summary.locator("summary", { hasText: "Node ID" }).first().click();
    await expect(summary.getByText("pkg:42", { exact: true })).toBeVisible();
    await page.screenshot({ path: testInfo.outputPath(`package-context-${theme}.png`) });
    const request = page.waitForRequest(req => req.url().endsWith("/v1/graph/query") && req.postDataJSON().roots?.includes("pkg:42"));
    await summary.getByRole("button", { name: "Inspect pyyaml@5.3 (pkg:42)", exact: true }).click();
    expect((await request).postDataJSON()).toMatchObject({ roots: ["pkg:42"] });
  });
}

for (const theme of ["light", "dark"] as const) {
  test(`leaf scope rows remain compact and inspectable on mobile ${theme}`, async ({ page }, testInfo) => {
    await routeLargeGraphPage(page);
    await page.setViewportSize({ width: 390, height: 844 });
    await page.addInitScript(value => localStorage.setItem("agent-bom-theme", value), theme);
    await page.route("**/v1/graph/rollup?**", route => route.fulfill({ json: {
      scan_id: scanId, tenant_id: "default", created_at: createdAt, mode: "rollup", filters: {},
      top_level: Array.from({ length: 13 }, (_, i) => ({ id: `pkg:${i}`, label: `CVE-2026-${1000 + i}`, entity_type: "vulnerability", severity: "high",
        is_container: false, has_children: false, direct_child_count: 0,
        aggregate: { descendant_count: 0, by_type: {}, severity_counts: {}, worst_severity: "none", worst_severity_rank: 0,
          internet_exposed: false, toxic_combo: false, exposed_count: 0, toxic_count: 0 } })),
      edges: [], summary: { total_nodes: 13, total_edges: 0, top_level_count: 13, container_count: 0 },
      completeness: { status: "complete", complete: true, truncated: false, returned: 13, total: 13 },
    } }));
    await page.goto(`/graph?scan=${scanId}`);
    await page.getByRole("button", { name: "Summary", exact: true }).click();
    const summary = page.getByTestId("graph-rollup-decision-surface");
    await expect(summary.getByRole("article")).toHaveCount(12);
    const row = summary.getByRole("article").first();
    expect((await row.boundingBox())!.height).toBeLessThanOrEqual(140);
    const grid = page.getByTestId("graph-rollup-card-grid");
    expect((await grid.boundingBox())!.height).toBeLessThanOrEqual(844 * 0.6 + 1);
    await summary.getByRole("button", { name: "Next scope page", exact: true }).click();
    await expect(summary.getByRole("article")).toHaveCount(1);
    await expect(summary.getByRole("button", { name: "Inspect CVE-2026-1012 (pkg:12)", exact: true })).toBeVisible();
    await summary.locator("summary", { hasText: "Node ID" }).click();
    await expect(summary.getByText("pkg:12", { exact: true })).toBeVisible();
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await page.screenshot({ path: testInfo.outputPath(`compact-leaf-${theme}.png`), fullPage: true });
  });
}

for (const theme of ["light", "dark"] as const) {
  for (const width of [390, 1440]) {
    test(`environment map focus and controls ${theme} ${width}`, async ({ page }, testInfo) => {
      test.setTimeout(60_000);
      await routeLargeGraphPage(page, true);
      await page.setViewportSize({ width, height: 900 });
      await page.addInitScript(value => localStorage.setItem("agent-bom-theme", value), theme);
      await page.goto("/graph?vulnOnly=0&severity=&depth=3&pageSize=500&layers=agent,package&rollup=0");
      const sigma = page.getByTestId("sigma-graph-overview");
      await expect(sigma).toBeVisible();
      await expectSigmaCanvases(page);
      await sigma.getByText("Map controls", { exact: true }).click();
      await sigma.getByLabel("Map grouping").selectOption("environment");
      await expect(sigma.getByText(/Environment groups/)).toBeVisible();
      await page.screenshot({ path: testInfo.outputPath(`environment-overview-${theme}-${width}.png`), fullPage: true });
      await sigma.getByLabel("Find a displayed asset").fill("agent:large");
      await sigma.getByRole("button", { name: "Large Estate Agent · agent:large", exact: true }).click();
      await expect(sigma.getByLabel("Focused graph asset")).toBeVisible();
      await expect(sigma.getByRole("button", { name: "Clear focus" })).toBeVisible();
      await page.screenshot({ path: testInfo.outputPath(`environment-map-${theme}-${width}.png`), fullPage: true });
      if (width === 390) await page.getByRole("complementary").getByRole("button", { name: "Close", exact: true }).click();
      else await sigma.getByRole("button", { name: "Clear focus" }).click();
      await expect(sigma.getByLabel("Focused graph asset")).toHaveCount(0);
    });
  }
}

test("estate map renders a recorded scan without fabricating environment metadata", async ({ page }, testInfo) => {
  test.setTimeout(60_000);
  await routeLargeGraphPage(page);
  const { readFile } = await import("node:fs/promises");
  const artifact = process.env.GRAPH_SCAN_ARTIFACT;
  const fixture = buildLargeGraph();
  fixture.nodes = [node("agent:dependencies", "agent", "Dependency fixture"), ...Array.from({ length: 701 }, (_, i) => node(`dependency:${i}`, "package", `dependency-${i}`))];
  fixture.edges = fixture.nodes.slice(1).map(item => edge("agent:dependencies", item.id, "depends_on"));
  fixture.stats = { ...fixture.stats, total_nodes: fixture.nodes.length, total_edges: fixture.edges.length, severity_counts: { high: 0 }, node_types: { agent: 1, package: 701, vulnerability: 0 }, relationship_types: { uses: 0, depends_on: 701, vulnerable_to: 0, related_to: 0 } };
  const graph = artifact ? JSON.parse(await readFile(artifact, "utf8")) : fixture;
  // The builder artifact is the stored graph; the API adds its response pagination envelope.
  const response = { ...graph, pagination: { total: graph.nodes.length, offset: 0, limit: graph.nodes.length, has_more: false } };
  await page.route("**/v1/graph?**", route => route.fulfill({ json: response }));
  await page.route("**/v1/graph/attack-paths?**", route => route.fulfill({ json: { ...response, pagination: { total: graph.attack_paths.length, offset: 0, limit: 100, has_more: false } } }));
  await page.route("**/v1/graph/snapshots?**", route => route.fulfill({ json: [{ scan_id: graph.scan_id, created_at: graph.created_at, node_count: graph.nodes.length, edge_count: graph.edges.length, risk_summary: graph.stats.severity_counts }] }));
  const start = performance.now();
  await page.goto("/graph?rollup=0&vulnOnly=0&severity=&layers=agent,server,package,framework,vulnerability,container,cloudResource,tool,credential");
  // Real dependency scans collapse sibling packages initially; expand through the public control.
  const collapsedPackages = page.getByRole("button", { name: /^Expand \d+ members$/ });
  await expect(collapsedPackages.first()).toBeVisible();
  await collapsedPackages.first().click();
  const sigma = page.getByTestId("sigma-graph-overview");
  await expect(sigma).toBeVisible();
  await expectSigmaCanvases(page);
  const readyMs = performance.now() - start;
  await sigma.getByText("Map controls", { exact: true }).click();
  const groupingStart = performance.now();
  await sigma.getByLabel("Map grouping").selectOption("environment");
  await expect(sigma.getByText(/Environment groups/)).toBeVisible();
  const groupingMs = performance.now() - groupingStart;
  console.info(JSON.stringify({ evidence: artifact ? "local offline repository scan" : "synthetic CI fixture", nodes: graph.nodes.length, edges: graph.edges.length, readyMs, groupingMs }));
  await sigma.getByText(/Environment groups/).click();
  await expect(sigma.getByText(/Unknown fields stay unknown/)).toBeVisible();
  await expect(sigma.getByText(`Displayed: ${graph.nodes.length.toLocaleString()}/${graph.nodes.length.toLocaleString()} nodes, ${graph.edges.length.toLocaleString()}/${graph.edges.length.toLocaleString()} edges.`, { exact: true })).toBeVisible();
  await expectSigmaCanvases(page);
  await page.evaluate(() => new Promise<void>(resolve => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))));
  await page.screenshot({ path: testInfo.outputPath("recorded-scan-map.png"), fullPage: true });
});
