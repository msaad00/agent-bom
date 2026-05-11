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

async function routeGraphPage(page: Page) {
  const graph = buildDenseGraph();

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
  await page.route("**/v1/graph/snapshots?limit=40", async (route) => {
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
  await expect(page.getByRole("button", { name: "Relevant paths", exact: true })).toBeVisible();
  await expect(page.getByText("Attack paths", { exact: true })).toBeVisible();
  await expect(page.locator('[data-testid="cluster-pill"]').first()).toBeVisible();
  await expect(page.getByTestId("graph-compression-summary")).toContainText(/compressed|rendered/);
  await expect(page.locator("summary").filter({ hasText: "Legend" })).toBeVisible();
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

    await page.goto("/graph");
    await page.waitForLoadState("networkidle");
    await captureGraphScreenshot(page, testInfo, theme);
  });
}
