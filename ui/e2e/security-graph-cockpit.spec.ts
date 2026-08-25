import { expect, test, type Page, type TestInfo } from "@playwright/test";

// Non-empty fixture with two observed paths so the security graph page can
// prove that queue selection updates the in-place graph and evidence panel.
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

function buildCockpitGraph(nodeCount = 5) {
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
  for (let index = nodes.length; index < nodeCount; index += 1) {
    nodes.push(node(`resource:${index}`, "cloud_resource", `production-resource-${index}`, index % 17 === 0 ? "high" : "none", index % 17 === 0 ? 7.1 : 0));
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
      {
        source: "agent:desktop",
        target: "cred:gh-token",
        hops: ["agent:desktop", "server:github", "cred:gh-token"],
        edges: [
          "agent:desktop->server:github:uses",
          "server:github->cred:gh-token:exposes_cred",
        ],
        composite_risk: 7.5,
        summary: "claude-desktop reaches an exposed credential through the github MCP server.",
        credential_exposure: ["GITHUB_PERSONAL_ACCESS_TOKEN"],
        tool_exposure: [],
        vuln_ids: [],
      },
    ],
    interaction_risks: [],
    stats: {
      total_nodes: nodes.length,
      total_edges: edges.length,
      node_types: { agent: 1, server: 1, package: 1, vulnerability: 1, credential: 1 },
      severity_counts: { critical: 2, high: 1, medium: 0 },
      relationship_types: { uses: 1, depends_on: 1, vulnerable_to: 1, exposes_cred: 1 },
      attack_path_count: 2,
      interaction_risk_count: 0,
      max_attack_path_risk: 9.8,
      highest_interaction_risk: 0,
    },
    pagination: { total: nodes.length, offset: 0, limit: 250, has_more: false },
  };
}

async function routeCockpit(
  page: Page,
  snapshotNodeCount?: number,
  options: {
    emptyFocusResults?: boolean;
    emptyRollup?: boolean;
    rollupDelayMs?: number;
    fixFirstDelayMs?: number;
    rollupItemCount?: number;
  } = {},
) {
  const graph = buildCockpitGraph(snapshotNodeCount);
  const baseRollupItems = [
    {
      id: "account:production",
      label: "Production account",
      entity_type: "cloud_account",
      severity: "critical",
      is_container: true,
      has_children: true,
      direct_child_count: 900,
      aggregate: {
        descendant_count: 900,
        by_type: { cloud_resource: 900 },
        severity_counts: { critical: 1, high: 53, none: 846 },
        worst_severity: "critical",
        worst_severity_rank: 4,
        internet_exposed: true,
        toxic_combo: true,
        exposed_count: 8,
        toxic_count: 1,
      },
    },
    {
      id: "account:development",
      label: "Development account",
      entity_type: "cloud_account",
      severity: "high",
      is_container: true,
      has_children: true,
      direct_child_count: 341,
      aggregate: {
        descendant_count: 341,
        by_type: { cloud_resource: 341 },
        severity_counts: { high: 20, none: 321 },
        worst_severity: "high",
        worst_severity_rank: 3,
        internet_exposed: false,
        toxic_combo: false,
        exposed_count: 0,
        toxic_count: 0,
      },
    },
  ];
  const requestedRollupItems = Math.max(2, options.rollupItemCount ?? 2);
  const rollupItems = options.emptyRollup
    ? []
    : Array.from({ length: requestedRollupItems }, (_, index) => {
        if (index < baseRollupItems.length) return baseRollupItems[index]!;
        return {
          ...baseRollupItems[1]!,
          id: `account:team-${index}`,
          label: `Team account ${index}`,
          severity: "none",
          direct_child_count: 1,
          aggregate: {
            ...baseRollupItems[1]!.aggregate,
            descendant_count: 1,
            severity_counts: { none: 1 },
            worst_severity: "none",
            worst_severity_rank: 0,
          },
        };
      });

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
  await page.route("**/v1/graph/scenarios", async (route) => {
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        schema: "graph.scenarios.v1",
        count: 1,
        scenarios: [
          {
            scenario_id: "scenario-private-endpoint",
            tenant_id: "default",
            name: "Private service endpoint",
            description: "Replace public database access with a private endpoint.",
            base_scan_id: scanId,
            assumptions: ["The endpoint policy is deployed with least privilege."],
            changes: [],
            revision: 2,
            created_by: "analyst@example.com",
            created_at: createdAt,
            updated_at: createdAt,
          },
        ],
      }),
    });
  });
  await page.route("**/v1/graph/scenarios/scenario-private-endpoint/comparison?**", async (route) => {
    const proposedNode = node(
      "proposal:scenario-private-endpoint:private-endpoint",
      "cloud_resource",
      "Private service endpoint",
    );
    proposedNode.status = "proposed";
    proposedNode.attributes = {
      evidence_state: "proposed",
      observed: false,
      deployed: false,
      scenario_id: "scenario-private-endpoint",
      scenario_revision: 2,
      assumption: "The endpoint policy is deployed with least privilege.",
    };
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        schema: "graph.scenario-comparison.v1",
        scenario: {
          scenario_id: "scenario-private-endpoint",
          tenant_id: "default",
          name: "Private service endpoint",
          description: "Replace public database access with a private endpoint.",
          base_scan_id: scanId,
          assumptions: ["The endpoint policy is deployed with least privilege."],
          changes: [],
          revision: 2,
          created_by: "analyst@example.com",
          created_at: createdAt,
          updated_at: createdAt,
        },
        current: { scan_id: scanId, node_count: graph.nodes.length, edge_count: graph.edges.length },
        proposed: {
          node_count: graph.nodes.length + 1,
          edge_count: graph.edges.length,
          modeled: true,
          nodes: [...graph.nodes, proposedNode],
          edges: graph.edges,
          completeness: { status: "complete", complete: true, sampled: false, truncated: false, returned: graph.nodes.length + 1, total: graph.nodes.length + 1 },
        },
        difference: {
          nodes_added: [proposedNode.id],
          nodes_removed: [],
          nodes_changed: ["server:github"],
          edges_added: [],
          edges_removed: ["server:github->cred:gh-token:exposes_cred"],
          touched_observed_path_count: 1,
          touched_observed_path_ids: ["agent:desktop->cred:gh-token"],
        },
        available: true,
        stale: false,
      }),
    });
  });
  await page.route("**/v1/graph/views/fix-first?**", async (route) => {
    if (options.fixFirstDelayMs) {
      await new Promise((resolve) => setTimeout(resolve, options.fixFirstDelayMs));
    }
    const attackPath = graph.attack_paths[0]!;
    const cards = options.emptyFocusResults
      ? []
      : [
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
        ];
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        scan_id: scanId,
        tenant_id: "default",
        created_at: createdAt,
        cards,
        summary: {
          total_paths: 1,
          matched_paths: cards.length,
          returned_paths: cards.length,
          highest_risk: cards.length ? 9.8 : 0,
          covered_findings: cards.length,
          node_count: graph.nodes.length,
          edge_count: graph.edges.length,
        },
        focus: { cve: "", package: "", agent: "" },
      }),
    });
  });
  await page.route("**/v1/graph/attack-paths?**", async (route) => {
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        ...graph,
        pagination: { total: graph.attack_paths.length, offset: 0, limit: 100, has_more: false },
        completeness: { returned: graph.attack_paths.length, total: graph.attack_paths.length, truncated: false, reason: "" },
        count_metadata: {
          source: "persisted_graph_paths",
          snapshot_total: graph.attack_paths.length,
          materialized_paths: graph.attack_paths.length,
          derived_paths: 0,
          returned_rows: graph.attack_paths.length,
        },
      }),
    });
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
  await page.route("**/v1/graph/rollup?**", async (route) => {
    if (options.rollupDelayMs) {
      await new Promise((resolve) => setTimeout(resolve, options.rollupDelayMs));
    }
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        scan_id: scanId,
        tenant_id: "default",
        created_at: createdAt,
        mode: "rollup",
        filters: {},
        top_level: rollupItems,
        // The server aggregates every non-containment edge onto the containers
        // its endpoints roll up into, so a collapsed estate arrives as a
        // topology. This fixture used to omit the key entirely, which made the
        // canvas draw a grid of disconnected cards and let an "edge-free
        // roll-up" assertion look like a deliberate decision rather than a
        // fixture that could not have shown an edge either way.
        edges: options.emptyRollup ? [] : [
          {
            source: "account:development",
            target: "account:production",
            count: 35,
            relationships: ["can_access", "uses"],
          },
        ],
        completeness: {
          returned: rollupItems.length,
          total: rollupItems.length,
          truncated: false,
          reason: "",
        },
        edge_count_metadata: {
          definition: "aggregated non-containment relationship rows between returned containers",
          source_total: options.emptyRollup ? 0 : 1,
          returned: options.emptyRollup ? 0 : 1,
          truncated: false,
          source_truncated: false,
          reason: "",
        },
        summary: {
          total_nodes: snapshotNodeCount ?? 1241,
          total_edges: graph.edges.length,
          top_level_count: rollupItems.length,
          container_count: rollupItems.length,
        },
      }),
    });
  });
}

for (const proof of [
  { theme: "dark", width: 1512, height: 811 },
  { theme: "light", width: 1568, height: 780 },
] as const) {
  test(`scenario comparison stays truthful at ${proof.width}x${proof.height} ${proof.theme}`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width: proof.width, height: proof.height });
    await routeCockpit(page, 36);
    await page.addInitScript((selectedTheme) => {
      window.localStorage.setItem("agent-bom-theme", selectedTheme);
    }, proof.theme);

    await page.goto(`/security-graph?lens=estate&rollup=0&scenario=scenario-private-endpoint&state=proposed`);
    await page.waitForLoadState("networkidle");
    await expect(page.getByRole("status")).toContainText(
      "Proposed scenario — not observed or deployed",
    );
    await expect(page.getByText("Current · observed")).toBeVisible();
    await expect(page.getByText("Proposed · modeled")).toBeVisible();
    await page.getByRole("tab", { name: "Difference" }).click();
    await expect(page).toHaveURL(/state=difference/);
    await expect(page.getByTestId("graph-scenario-difference")).toContainText(
      "1 touched observed paths",
    );
    const overflows = await page.evaluate(
      () => document.documentElement.scrollWidth > document.documentElement.clientWidth,
    );
    expect(overflows).toBe(false);
    await page.screenshot({
      path: testInfo.outputPath(`graph-scenario-${proof.width}x${proof.height}-${proof.theme}.png`),
      fullPage: true,
    });
  });
}

test("Attack Paths keeps scenario state observed-only", async ({ page }) => {
  await routeCockpit(page);
  await page.goto(`/security-graph?lens=attack-path&scenario=scenario-private-endpoint&state=proposed`);
  await page.waitForLoadState("networkidle");

  await expect(page.getByText(/Attack Paths remains observed-only/)).toBeVisible();
  await expect(page.getByText(/Proposed scenario — not observed or deployed/)).toHaveCount(0);
  await expect(page).toHaveURL(/state=current/);
});

async function expectCockpitVisible(page: Page) {
  await expect(page.getByRole("heading", { name: "Investigation" })).toBeVisible();
  await expect(
    page.getByRole("heading", { name: /Claude Desktop.*form-data.*CVE-2025-7783/ }),
  ).toBeVisible();
  // Progressive disclosure summary — avoid /Evidence/ which also matches "Evidence drawer".
  await expect(page.getByText("Evidence & relationships")).toBeVisible();
  await expect(page.getByText("Path risk", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("Path span", { exact: true }).first()).toBeVisible();
}

for (const theme of ["dark", "light"] as const) {
  test(`security-graph cockpit ${theme} renders exposure command center on a non-empty graph`, async ({ page }, testInfo: TestInfo) => {
    await routeCockpit(page);
    await page.addInitScript((selectedTheme) => {
      window.localStorage.setItem("agent-bom-theme", selectedTheme);
    }, theme);

    await page.goto("/security-graph?lens=attack-path");
    await page.waitForLoadState("networkidle");
    await expectCockpitVisible(page);

    await page.screenshot({ path: testInfo.outputPath(`security-graph-cockpit-${theme}.png`), fullPage: true });
  });
}

test("security-graph cockpit stays usable on a mobile viewport", async ({ page }, testInfo: TestInfo) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await routeCockpit(page);

  await page.goto("/security-graph?lens=attack-path");
  await page.waitForLoadState("networkidle");
  await expectCockpitVisible(page);
  const overflows = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth);
  expect(overflows).toBe(false);

  await page.screenshot({ path: testInfo.outputPath("security-graph-cockpit-mobile.png"), fullPage: true });
});

test("requested scan without a graph snapshot never falls back to another scan", async ({ page }) => {
  await routeCockpit(page);

  await page.goto("/security-graph?scan=scan-without-graph&cve=CVE-2099-MISSING");
  await page.waitForLoadState("networkidle");

  await expect(page.getByText("Snapshot unavailable for requested scan")).toBeVisible();
  await expect(page.getByText(/did not substitute evidence from a different scan/i)).toBeVisible();
  await expect(page.getByText("Critical package reachable from MCP server")).toHaveCount(0);
});

test("focused investigation never shows an unrelated global path", async ({ page }) => {
  await routeCockpit(page, undefined, { emptyFocusResults: true });

  await page.goto(`/security-graph?scan=${scanId}&cve=CVE-2099-NOT-IN-SNAPSHOT`);
  await page.waitForLoadState("networkidle");

  await expect(page.getByText("No attack paths matched the current focus")).toBeVisible();
  await expect(page.getByText("Critical package reachable from MCP server")).toHaveCount(0);
});

test("ranked persisted paths render before slower fix guidance", async ({ page }) => {
  await routeCockpit(page, undefined, { fixFirstDelayMs: 2_000 });

  await page.goto("/security-graph?lens=attack-path");
  await expect(page.getByText("#1 fix first")).toBeVisible();
  await expect(page.getByText(/Ranked paths are ready; fix guidance is still loading/)).toBeVisible();
  await expect(page.getByText("agent → server → package → finding")).toBeVisible();

  await expect(page.getByText("Critical package reachable from MCP server")).toBeVisible();
});

test("ranked path selection focuses the in-place interactive graph and announces the change", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 1000 });
  await routeCockpit(page);

  await page.goto("/security-graph?lens=attack-path");
  await page.waitForLoadState("networkidle");

  const workspace = page.getByRole("region", { name: "Investigation workspace" });
  const queue = workspace.getByLabel("Attack path queue");
  const detail = workspace.getByRole("region", { name: "Selected path detail" });
  const [queueBox, detailBox] = await Promise.all([queue.boundingBox(), detail.boundingBox()]);
  expect(queueBox).not.toBeNull();
  expect(detailBox).not.toBeNull();
  expect(Math.abs(queueBox!.y - detailBox!.y)).toBeLessThan(200);

  await queue.getByRole("button", { name: /#2/ }).click();
  await expect(detail.getByTestId("security-graph-investigation")).toBeVisible();
  await expect(page.getByRole("status")).toContainText("Focused path 2");
  const [selectedRowBox, focusedDetailBox] = await Promise.all([
    queue.getByRole("button", { name: /#2/ }).boundingBox(),
    detail.boundingBox(),
  ]);
  expect(selectedRowBox).not.toBeNull();
  expect(focusedDetailBox).not.toBeNull();
  expect(selectedRowBox!.y).toBeLessThan(1000);
  expect(focusedDetailBox!.y).toBeLessThan(1000);
});

test("mobile ranked path selection moves the selected graph into view", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await routeCockpit(page);

  await page.goto("/security-graph?lens=attack-path");
  await page.waitForLoadState("networkidle");

  const queue = page.getByLabel("Attack path queue");
  await queue.getByRole("button", { name: /#2/ }).click();
  const detail = page.getByRole("region", { name: "Selected path detail" });
  await expect(detail.getByTestId("security-graph-investigation")).toBeVisible();
  await expect.poll(async () => (await detail.boundingBox())?.y ?? Number.POSITIVE_INFINITY).toBeLessThan(120);
});

for (const theme of ["dark", "light"] as const) {
test(`large estates lead with non-overlapping clusters in ${theme}`, async ({ page }, testInfo: TestInfo) => {
  await routeCockpit(page, 1_241);
  await page.addInitScript((selectedTheme) => {
    window.localStorage.setItem("agent-bom-theme", selectedTheme);
  }, theme);

  await page.goto("/security-graph?lens=attack-path");
  await page.waitForLoadState("networkidle");

  const evidenceScope = page.getByRole("button", { name: /Evidence scope/ });
  await expect(evidenceScope).toHaveAttribute("aria-expanded", "false");
  await evidenceScope.click();
  await expect(
    page.getByText("1,241 nodes. Use a focused lens before opening the full topology."),
  ).toBeVisible();
  await expect(page.getByRole("link", { name: "Explore clusters" })).toHaveAttribute(
    "href",
    "/security-graph?scan=scan-cockpit-fixture&lens=lineage&rollup=1",
  );
  await expect(page.getByRole("link", { name: "Open raw topology" })).toHaveAttribute(
    "href",
    "/security-graph?scan=scan-cockpit-fixture&lens=lineage&rollup=0",
  );
  await page.screenshot({ path: testInfo.outputPath(`investigation-large-estate-${theme}.png`), fullPage: true });

  const rollupRequest = page.waitForRequest((request) => request.url().includes("/v1/graph/rollup"));
  await page.getByRole("link", { name: "Explore clusters" }).click();
  await expect(page).toHaveURL(/scan=scan-cockpit-fixture/);
  await expect(page).toHaveURL(/rollup=1/);
  await rollupRequest;
  await expect(page.getByText("Scope navigation", { exact: true })).toBeVisible();
  // The roll-up used to emit no edges, so this banner had to disclaim that the
  // cards were "not rendered relationship evidence". It now draws the real
  // aggregated relationships between containers, so the banner says so and the
  // old disclaimer must NOT come back.
  await expect(page.getByText(/real relationships, aggregated/i)).toBeVisible();
  await expect(page.getByText(/not rendered relationship evidence/i)).toHaveCount(0);
  // The banner claims aggregated relationships; the canvas has to hold one, or
  // the claim is the disclaimer it replaced with the word "not" removed.
  await expect(page.locator(".react-flow__edge")).toHaveCount(1);
  await expect(page.getByTestId("graph-compression-summary")).toHaveCount(0);
  await expect(page.getByText(/2 containers at this level.*1241 nodes in snapshot/)).toBeVisible();
  const cards = page.locator('[data-rollup-container="true"]');
  await expect(cards).toHaveCount(2);
  const [firstBox, secondBox] = await Promise.all([cards.nth(0).boundingBox(), cards.nth(1).boundingBox()]);
  expect(firstBox).not.toBeNull();
  expect(secondBox).not.toBeNull();
  expect(firstBox!.x + firstBox!.width).toBeLessThanOrEqual(secondBox!.x);
  await page.screenshot({ path: testInfo.outputPath(`investigation-large-estate-clustered-${theme}.png`), fullPage: true });

  await page.getByRole("button", { name: "Open node view" }).click();
  await expect(page).toHaveURL(/rollup=0/);
});
}

test("36-node snapshots default to real topology and forced roll-up still draws relationships", async ({ page }) => {
  await routeCockpit(page, 36);

  await page.goto(`/graph?scan=${scanId}`);
  await page.waitForLoadState("networkidle");
  await expect(page.getByText("Scope navigation", { exact: true })).toHaveCount(0);
  expect(await page.locator(".react-flow__edge").count()).toBeGreaterThan(0);

  await page.goto(`/graph?scan=${scanId}&rollup=1`);
  await page.waitForLoadState("networkidle");
  await expect(page.getByText("Scope navigation", { exact: true })).toBeVisible();
  await expect(page.locator('[data-rollup-container="true"]')).toHaveCount(2);
  // Collapsing the estate changes what a relationship is drawn *between*, never
  // whether one is drawn. A roll-up with no edges is the grid of disconnected
  // cards this view was built to stop being.
  await expect(page.locator(".react-flow__edge")).toHaveCount(1);
  await expect(page.getByTestId("graph-compression-summary")).toHaveCount(0);
});

test("200-node snapshots default to roll-up and explicit raw topology persists", async ({ page }) => {
  await routeCockpit(page, 200);

  await page.goto(`/graph?scan=${scanId}`);
  await page.waitForLoadState("networkidle");
  await expect(page.getByText("Scope navigation", { exact: true })).toBeVisible();
  await expect(page.getByText(/200 nodes in snapshot/i)).toBeVisible();

  await page.goto(`/graph?scan=${scanId}&rollup=0`);
  await page.waitForLoadState("networkidle");
  await expect(page).toHaveURL(/rollup=0/);
  await expect(page.getByText("Scope navigation", { exact: true })).toHaveCount(0);
  expect(await page.locator(".react-flow__edge").count()).toBeGreaterThan(0);
});

test("empty forced roll-up preserves operator preference and falls back to real topology", async ({ page }) => {
  await routeCockpit(page, 36, { emptyRollup: true });

  await page.goto(`/graph?scan=${scanId}&rollup=1`);
  await page.waitForLoadState("networkidle");
  await expect(page).toHaveURL(/rollup=1/);
  await expect(page.getByText(/Roll-up unavailable/i)).toBeVisible();
  expect(await page.locator(".react-flow__edge").count()).toBeGreaterThan(0);
});

test("eligible roll-up shows a loading surface without raw-topology counts", async ({ page }) => {
  await routeCockpit(page, 200, { rollupDelayMs: 750 });

  await page.goto(`/graph?scan=${scanId}`);
  await expect(page.getByText("Loading scope navigation")).toBeVisible();
  await expect(page.getByTestId("graph-compression-summary")).toHaveCount(0);
  await expect(page.locator(".react-flow__edge")).toHaveCount(0);
  await expect(page.getByText("Scope navigation", { exact: true })).toBeVisible();
});

test("ranked paths reach the first viewport instead of sitting under a tower of bands", async ({ page }) => {
  // The investigation page stacked eight full-width bands above the content:
  // title, lens row, investigation loop, deploy gate, exposure paths, snapshot,
  // large-estate notice, metric tiles. The graph and the ranked paths — the
  // reason the page exists — began below the fold on a 900px-tall viewport.
  //
  // Controls recede, content is the hero. This pins that the paths panel starts
  // within the first viewport at a standard desktop height.
  await page.setViewportSize({ width: 1440, height: 900 });
  await routeCockpit(page);

  await page.goto("/security-graph?lens=attack-path");
  await page.waitForLoadState("networkidle");

  const paths = page.getByText(/rendered · .* returned · .* snapshot paths/).first();
  await expect(paths).toBeVisible();
  const box = await paths.boundingBox();
  expect(box).not.toBeNull();
  expect(box!.y).toBeLessThan(900);
});

for (const proof of [
  { width: 1512, height: 811, theme: "light" },
  { width: 1568, height: 780, theme: "dark" },
] as const) {
  test(`estate canvas is the truthful first view at ${proof.width}x${proof.height}`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width: proof.width, height: proof.height });
    await routeCockpit(page, 1_241, { rollupItemCount: 30 });
    await page.addInitScript((theme) => {
      window.localStorage.setItem("agent-bom-theme", theme);
    }, proof.theme);

    await page.goto("/security-graph");
    await page.waitForLoadState("networkidle");

    await expect(page.getByRole("heading", { name: "Investigation Canvas" })).toBeVisible();
    await expect(page.getByRole("button", { name: /Estate/ })).toHaveAttribute("aria-pressed", "true");
    await expect(page.getByTestId("graph-rollup-decision-surface")).toBeVisible();
    await expect(page.getByTestId("graph-rollup-relationship-completeness")).toHaveText(
      "1 aggregated relationship rows · complete for this scope",
    );
    await expect(page.getByText("Agent Mesh")).toBeHidden();
    await expect(page.getByText("Context", { exact: true })).toBeHidden();

    const proofState = await page.evaluate(() => ({
      horizontalOverflow: document.documentElement.scrollWidth > document.documentElement.clientWidth,
      viewport: { width: window.innerWidth, height: window.innerHeight },
    }));
    expect(proofState.horizontalOverflow).toBe(false);
    expect(proofState.viewport).toEqual({ width: proof.width, height: proof.height });

    await page.screenshot({
      path: testInfo.outputPath(`investigation-canvas-estate-${proof.width}x${proof.height}.png`),
      fullPage: false,
    });
  });
}

for (const viewport of [
  { width: 1512, height: 811 },
  { width: 1568, height: 780 },
] as const) {
  test(`investigation canvas preserves evidence and saved viewport at ${viewport.width}x${viewport.height}`, async ({ page }, testInfo) => {
    await page.setViewportSize(viewport);
    await routeCockpit(page);

    await page.goto("/security-graph?lens=attack-path");
    await page.waitForLoadState("networkidle");
    await page.getByLabel("Attack path queue").getByRole("button", { name: /#1/ }).click();
    const detail = page.getByRole("region", { name: "Selected path detail" });
    const canvas = detail.getByTestId("security-graph-investigation");
    const legendBand = detail.getByTestId("security-graph-legend-band");
    const interactionBand = detail.getByTestId("security-graph-interaction-band");
    const nodeBand = canvas.locator(".react-flow");
    await expect(canvas).toBeVisible();
    await expect(legendBand).toBeVisible();
    await expect(interactionBand).toBeVisible();
    await expect(canvas.locator(".react-flow__node")).not.toHaveCount(0);

    const [legendBox, canvasBox, interactionBox, nodeBandBox] = await Promise.all([
      legendBand.boundingBox(),
      canvas.boundingBox(),
      interactionBand.boundingBox(),
      nodeBand.boundingBox(),
    ]);
    expect(legendBox).not.toBeNull();
    expect(canvasBox).not.toBeNull();
    expect(interactionBox).not.toBeNull();
    expect(nodeBandBox).not.toBeNull();
    expect(legendBox!.y + legendBox!.height).toBeLessThanOrEqual(canvasBox!.y + 1);
    expect(interactionBox!.y + interactionBox!.height).toBeLessThanOrEqual(nodeBandBox!.y + 1);

    const fitButton = interactionBand.getByRole("button", { name: /fit visible/i });
    await fitButton.click();
    await expect.poll(() => page.evaluate(() =>
      Object.keys(window.localStorage).some((key) => key.startsWith("agent-bom:graph-presentation:v1:")),
    )).toBe(true);
    await page.waitForTimeout(350);
    const savedTransform = await canvas.locator(".react-flow__viewport").getAttribute("style");
    await page.reload();
    await page.waitForLoadState("networkidle");
    await page.getByLabel("Attack path queue").getByRole("button", { name: /#1/ }).click();
    await expect(detail.getByTestId("security-graph-investigation")).toBeVisible();
    await expect.poll(async () =>
      detail.getByTestId("security-graph-investigation").locator(".react-flow__viewport").getAttribute("style"),
    ).toBe(savedTransform);

    await page.screenshot({
      path: testInfo.outputPath(`security-graph-${viewport.width}x${viewport.height}.png`),
      fullPage: true,
    });
  });
}

test("the deploy gate is disclosure-gated rather than always expanded", async ({ page }) => {
  // "Should I deploy?" is a deliberate, occasional action — not something that
  // should cost a full band of vertical space on every visit.
  await routeCockpit(page);

  await page.goto("/security-graph?lens=attack-path");
  await page.waitForLoadState("networkidle");

  await expect(page.getByPlaceholder(/agent:claude-desktop/)).toBeHidden();
});
