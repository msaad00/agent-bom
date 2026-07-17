import { expect, test, type Page, type TestInfo } from "@playwright/test";

// Non-empty fixture with one critical agent->vulnerability exposure path so the
// security graph page renders the exposure command center, metrics, and evidence panel.
const scanId = "scan-cockpit-fixture";
const createdAt = "2026-05-27T16:00:00Z";

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
    data_sources: ["scan"],
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
    evidence: { cvss_score: 9.8, epss_score: 0.71, is_kev: true },
    activity_id: 1,
  };
}

function buildCockpitGraph() {
  const nodes: GraphNode[] = [
    node("agent:desktop", "agent", "claude-desktop"),
    node("server:github", "server", "github"),
    node("pkg:form-data", "package", "form-data@4.0.0", "critical", 9.6),
    node("cve:form-data", "vulnerability", "CVE-2025-7783", "critical", 9.8),
    node("cred:gh-token", "credential", "GITHUB_PERSONAL_ACCESS_TOKEN", "high", 7.5),
  ];
  const edges: GraphEdge[] = [
    edge("agent:desktop", "server:github", "uses"),
    edge("server:github", "pkg:form-data", "depends_on"),
    edge("pkg:form-data", "cve:form-data", "vulnerable_to", 1.5),
    edge("server:github", "cred:gh-token", "exposes_cred"),
  ];

  return {
    scan_id: scanId,
    tenant_id: "default",
    created_at: createdAt,
    nodes,
    edges,
    attack_paths: [
      {
        source: "agent:desktop",
        target: "cve:form-data",
        hops: ["agent:desktop", "server:github", "pkg:form-data", "cve:form-data"],
        edges: [
          "agent:desktop->server:github:uses",
          "server:github->pkg:form-data:depends_on",
          "pkg:form-data->cve:form-data:vulnerable_to",
        ],
        composite_risk: 9.8,
        summary: "claude-desktop reaches a critical vulnerable package through the github MCP server.",
        credential_exposure: ["GITHUB_PERSONAL_ACCESS_TOKEN"],
        tool_exposure: ["create_pull_request"],
        vuln_ids: ["CVE-2025-7783"],
      },
    ],
    interaction_risks: [],
    stats: {
      total_nodes: nodes.length,
      total_edges: edges.length,
      node_types: { agent: 1, server: 1, package: 1, vulnerability: 1, credential: 1 },
      severity_counts: { critical: 2, high: 1, medium: 0 },
      relationship_types: { uses: 1, depends_on: 1, vulnerable_to: 1, exposes_cred: 1 },
      attack_path_count: 1,
      interaction_risk_count: 0,
      max_attack_path_risk: 9.8,
      highest_interaction_risk: 0,
    },
    pagination: { total: nodes.length, offset: 0, limit: 250, has_more: false },
  };
}

async function routeCockpit(page: Page, snapshotNodeCount?: number) {
  const graph = buildCockpitGraph();

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
        request_id: "req-cockpit-e2e",
        trace_id: "trace-cockpit-e2e",
        span_id: "span-cockpit-e2e",
      }),
    });
  });
  await page.route("**/v1/posture/counts", async (route) => {
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ critical: 2, high: 1, medium: 0, low: 0, total: 3, kev: 1, compound_issues: 1 }),
    });
  });
  await page.route("**/v1/graph/snapshots?**", async (route) => {
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify([
        {
          scan_id: scanId,
          created_at: createdAt,
          node_count: snapshotNodeCount ?? graph.nodes.length,
          edge_count: graph.edges.length,
          risk_summary: graph.stats.severity_counts,
        },
      ]),
    });
  });
  await page.route("**/v1/graph/views/fix-first?**", async (route) => {
    const attackPath = graph.attack_paths[0]!;
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        scan_id: scanId,
        tenant_id: "default",
        created_at: createdAt,
        cards: [
          {
            id: "card-cockpit-fixture",
            rank: 1,
            title: "Critical package reachable from MCP server",
            summary: attackPath.summary,
            attack_path: attackPath,
            nodes: graph.nodes,
            sequence_labels: ["claude-desktop", "github", "form-data@4.0.0", "CVE-2025-7783"],
            risk_reasons: [
              {
                kind: "critical_vulnerability",
                label: "Critical reachable CVE",
                detail: "A critical vulnerability is reachable from an agent-connected MCP server.",
              },
            ],
            next_actions: [
              {
                title: "Upgrade vulnerable package",
                detail: "Prioritize the package dependency before granting more tool access.",
                href: "/findings?scan=scan-cockpit-fixture",
              },
            ],
            affected: {
              agents: ["claude-desktop"],
              servers: ["github"],
              packages: ["form-data@4.0.0"],
              findings: ["CVE-2025-7783"],
              credentials: ["GITHUB_PERSONAL_ACCESS_TOKEN"],
              tools: ["create_pull_request"],
            },
          },
        ],
        summary: {
          total_paths: 1,
          matched_paths: 1,
          returned_paths: 1,
          highest_risk: 9.8,
          covered_findings: 1,
          node_count: graph.nodes.length,
          edge_count: graph.edges.length,
        },
        focus: { cve: "", package: "", agent: "" },
      }),
    });
  });
  await page.route("**/v1/graph/attack-paths?**", async (route) => {
    await route.fulfill({ contentType: "application/json", body: JSON.stringify(graph) });
  });
  await page.route("**/v1/graph/diff?**", async (route) => {
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ nodes_added: [], nodes_removed: [], nodes_changed: [], edges_added: [], edges_removed: [] }),
    });
  });
  await page.route("**/v1/graph?**", async (route) => {
    await route.fulfill({ contentType: "application/json", body: JSON.stringify(graph) });
  });
}

async function expectCockpitVisible(page: Page) {
  await expect(page.getByRole("heading", { name: "Investigation" })).toBeVisible();
  await expect(
    page.getByRole("heading", { name: /Claude Desktop.*form-data.*CVE-2025-7783/ }),
  ).toBeVisible();
  // Progressive disclosure summary — avoid /Evidence/ which also matches "Evidence drawer".
  await expect(page.getByText("Evidence & relationships")).toBeVisible();
  await expect(page.getByText("Path risk", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("Hops", { exact: true }).first()).toBeVisible();
}

for (const theme of ["dark", "light"] as const) {
  test(`security-graph cockpit ${theme} renders exposure command center on a non-empty graph`, async ({ page }, testInfo: TestInfo) => {
    await routeCockpit(page);
    await page.addInitScript((selectedTheme) => {
      window.localStorage.setItem("agent-bom-theme", selectedTheme);
    }, theme);

    await page.goto("/security-graph");
    await page.waitForLoadState("networkidle");
    await expectCockpitVisible(page);

    await page.screenshot({ path: testInfo.outputPath(`security-graph-cockpit-${theme}.png`), fullPage: true });
  });
}

test("security-graph cockpit stays usable on a mobile viewport", async ({ page }, testInfo: TestInfo) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await routeCockpit(page);

  await page.goto("/security-graph");
  await page.waitForLoadState("networkidle");
  await expectCockpitVisible(page);
  const overflows = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth);
  expect(overflows).toBe(false);

  await page.screenshot({ path: testInfo.outputPath("security-graph-cockpit-mobile.png"), fullPage: true });
});

test("large estates lead with clusters and keep raw topology as drill-down", async ({ page }, testInfo: TestInfo) => {
  await routeCockpit(page, 1_241);

  await page.goto("/security-graph");
  await page.waitForLoadState("networkidle");

  await expect(page.getByText("Large estate · 1,241 nodes")).toBeVisible();
  await expect(page.getByRole("link", { name: "Explore clusters" })).toHaveAttribute(
    "href",
    "/graph?scan=scan-cockpit-fixture&rollup=1",
  );
  await expect(page.getByRole("link", { name: "Open raw topology" })).toHaveAttribute(
    "href",
    "/graph?scan=scan-cockpit-fixture&rollup=0",
  );
  await page.screenshot({ path: testInfo.outputPath("investigation-large-estate.png"), fullPage: true });
});
