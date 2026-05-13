import { expect, test, type Page, type TestInfo } from "@playwright/test";

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
    nodes.push(node(packageId, "package", `large-package-${index}`, "high", 7.2));
    if (index > 0) {
      edges.push(edge(`pkg:${index - 1}`, packageId, "depends_on"));
    }
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
      node_types: { agent: 1, package: 620 },
      severity_counts: { high: 621 },
      relationship_types: { uses: 1, depends_on: 619, related_to: 620 },
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
  await page.route("**/v1/graph/snapshots?limit=40", async (route) => {
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify([
        { scan_id: scanId, created_at: createdAt, node_count: graph.nodes.length, edge_count: graph.edges.length, risk_summary: graph.stats.severity_counts },
      ]),
    });
  });
  await page.route("**/v1/graph/diff?**", async (route) => {
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ nodes_added: [], nodes_removed: [], nodes_changed: [], edges_added: [], edges_removed: [] }),
    });
  });
  await page.route("**/v1/graph/search?**", async (route) => {
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        query: "large-package-42",
        results: [root],
        pagination: { total: 1, offset: 0, limit: 16, has_more: false },
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
  await page.waitForFunction(() => {
    const canvas = document.querySelector<HTMLCanvasElement>('[data-testid="large-graph-overview-canvas"]');
    return Boolean(canvas && canvas.width > 1 && canvas.height > 1);
  });
  const coloredSamples = await canvas.evaluate((element) => {
    const canvasElement = element as HTMLCanvasElement;
    const context = canvasElement.getContext("2d");
    if (!context) return 0;
    const { width, height } = canvasElement;
    const pixels = context.getImageData(0, 0, width, height).data;
    let count = 0;
    for (let index = 0; index < pixels.length; index += 400) {
      const red = pixels[index] ?? 0;
      const green = pixels[index + 1] ?? 0;
      const blue = pixels[index + 2] ?? 0;
      if (red + green + blue > 40) count += 1;
    }
    return count;
  });
  expect(coloredSamples).toBeGreaterThan(20);
}

test("large graph overview renders above threshold and search drills back into React Flow", async ({ page }, testInfo: TestInfo) => {
  await routeLargeGraphPage(page);

  await page.goto("/graph?vulnOnly=0&severity=&depth=3&pageSize=500&layers=agent,package");
  await page.waitForLoadState("networkidle");
  await page.locator("select").nth(2).selectOption("");
  await page.getByLabel("Vulnerable only").uncheck();

  await expect(page.getByTestId("large-graph-overview")).toBeVisible();
  await expect(page.getByText("Switches on at 500 nodes or 1,200 edges.")).toBeVisible();
  await expect(page.getByText("React Flow-only affordances")).toBeVisible();
  await expectCanvasHasPixels(page);
  await page.screenshot({ path: testInfo.outputPath("large-graph-overview.png"), fullPage: true });

  await page.getByPlaceholder("Search nodes, tags, severities, or attributes").fill("large-package-42");
  await page.getByRole("button", { name: "Search", exact: true }).click();
  await page.getByRole("button", { name: "large-package-42" }).click();

  await expect(page.getByText("Root-centered investigation:")).toBeVisible();
  await expect(page.getByRole("heading", { name: "large-package-42" })).toBeVisible();
  await expect(page.getByTestId("large-graph-overview")).toHaveCount(0);
});
