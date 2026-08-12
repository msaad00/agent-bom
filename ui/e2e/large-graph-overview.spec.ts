import { expect, test, type Locator, type Page, type TestInfo } from "@playwright/test";

const scanId = "scan-large-overview";
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

async function routeLargeGraphPage(page: Page) {
  const graph = buildLargeGraph();
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

async function expectCanvasHasPixels(page: Page) {
  const canvas = page.getByTestId("large-graph-overview-canvas");
  await expect(canvas).toBeVisible();
  await expect
    .poll(
      async () =>
        page
          .evaluate(() => {
            const canvasElement = document.querySelector<HTMLCanvasElement>(
              '[data-testid="large-graph-overview-canvas"]',
            );
            if (!canvasElement || canvasElement.width <= 1 || canvasElement.height <= 1) return 0;
            const context = canvasElement.getContext("2d");
            if (!context) return 0;
            const { width, height } = canvasElement;
            const pixels = context.getImageData(0, 0, width, height).data;
            let count = 0;
            for (let index = 0; index < pixels.length; index += 16) {
              const red = pixels[index] ?? 0;
              const green = pixels[index + 1] ?? 0;
              const blue = pixels[index + 2] ?? 0;
              if (red + green + blue > 40) count += 1;
            }
            return count;
          })
          .catch(() => 0),
      { timeout: 15_000 },
    )
    .toBeGreaterThan(20);
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

test("large graph overview renders above threshold", async ({ page }, testInfo: TestInfo) => {
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

  await expect(page.getByTestId("large-graph-overview")).toBeVisible();
  await expect(page.getByText("Large graph overview")).toBeVisible();
  await expect(page.getByText(/Draw budget:/)).toBeVisible();
  await expect(page.getByText("Pan, zoom, search, filter, and select nodes for evidence.")).toBeVisible();
  await expectCanvasHasPixels(page);
  await expect(page.getByRole("button", { name: "Search", exact: true })).toBeEnabled({ timeout: 15_000 });
  expect(failedGraphResponses).toEqual([]);
  await captureRenderedRegion(
    page,
    page.getByTestId("large-graph-overview"),
    testInfo.outputPath("large-graph-overview.png"),
  );
});

/**
 * Both overview renderers used to paint a fixed `#050505` stage with near-white
 * labels, so on a light page the biggest element on screen was a black
 * rectangle. Canvas and WebGL cannot use CSS classes, so the only way to know
 * they track the theme is to read what they actually painted.
 */
for (const theme of ["dark", "light"] as const) {
  test(`large graph overview paints the ${theme} page background`, async ({ page }, testInfo: TestInfo) => {
    test.setTimeout(60_000);
    await routeLargeGraphPage(page);
    await page.addInitScript((selected) => {
      window.localStorage.setItem("agent-bom-theme", selected);
    }, theme);

    await page.goto("/graph?vulnOnly=0&severity=&depth=3&pageSize=500&layers=agent,package", {
      waitUntil: "domcontentloaded",
    });
    await expect(page.getByTestId("large-graph-overview")).toBeVisible();
    await expectCanvasHasPixels(page);

    const painted = await page
      .getByTestId("large-graph-overview-canvas")
      .evaluate((element) => {
        const canvas = element as HTMLCanvasElement;
        const viewportHeight = window.innerHeight;
        const pixel = canvas
          .getContext("2d")!
          .getImageData(2, 2, 1, 1).data;
        const style = getComputedStyle(document.body);
        return {
          stage: [pixel[0], pixel[1], pixel[2]],
          background: style.getPropertyValue("--background").trim(),
          height: canvas.clientHeight,
          viewportHeight,
        };
      });

    // Writing `canvas.height` from `clientHeight` used to feed the element's
    // own intrinsic size, so every draw grew it: 21,604px on this fixture,
    // with the user looking at an empty slice of stage.
    expect(painted.height).toBeLessThan(painted.viewportHeight * 1.5);

    // The stage is the page background, so its luminance has to sit on the
    // correct side of mid-grey for the theme in play.
    const luminance =
      (painted.stage[0]! + painted.stage[1]! + painted.stage[2]!) / 3;
    if (theme === "light") expect(luminance).toBeGreaterThan(160);
    else expect(luminance).toBeLessThan(96);

    await captureRenderedRegion(
      page,
      page.getByTestId("large-graph-overview"),
      testInfo.outputPath(`large-graph-overview-${theme}.png`),
    );
  });

  test(`webgl overview stage follows the ${theme} theme`, async ({ page }, testInfo: TestInfo) => {
    test.setTimeout(60_000);
    await routeLargeGraphPage(page);
    await page.addInitScript((selected) => {
      window.localStorage.setItem("agent-bom-theme", selected);
    }, theme);

    await page.goto(
      "/graph?renderer=webgl&vulnOnly=0&severity=&depth=3&pageSize=500&layers=agent,package",
      { waitUntil: "domcontentloaded" },
    );
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
 * The canvas renderers hand assistive technology nothing on their own. Both
 * carry a text equivalent naming every node and relationship they draw.
 */
test("canvas overview exposes its nodes and edges as text", async ({ page }) => {
  test.setTimeout(60_000);
  await routeLargeGraphPage(page);

  await page.goto("/graph?vulnOnly=0&severity=&depth=3&pageSize=500&layers=agent,package", {
    waitUntil: "domcontentloaded",
  });
  await expect(page.getByTestId("large-graph-overview")).toBeVisible();

  const canvas = page.getByTestId("large-graph-overview-canvas");
  await expect(canvas).toHaveAttribute("role", "img");
  await expect(canvas).toHaveAttribute("aria-describedby", "large-graph-overview-text");

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

test("sigma webgl overview renders when explicitly requested", async ({ page }, testInfo: TestInfo) => {
  test.setTimeout(60_000);
  await routeLargeGraphPage(page);

  await page.goto("/graph?renderer=webgl&vulnOnly=0&severity=&depth=3&pageSize=500&layers=agent,package", {
    waitUntil: "domcontentloaded",
  });

  const sigma = page.getByTestId("sigma-graph-overview");
  await expect(sigma).toBeVisible({ timeout: 30_000 });
  // Exact: the surface's screen-reader text equivalent names the renderer too.
  await expect(sigma.getByText("WebGL graph overview", { exact: true })).toBeVisible();
  await expect(sigma.getByText(/Sigma\.js renderer for broad estate scans/)).toBeVisible();
  await expectSigmaCanvases(page);
  await captureRenderedRegion(page, sigma, testInfo.outputPath("sigma-webgl-overview.png"));
});
