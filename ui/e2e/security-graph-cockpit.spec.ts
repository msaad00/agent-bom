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
    qualifiedEvidence?: boolean;
    longPathNodeCount?: number;
  } = {},
) {
  const graph = buildCockpitGraph(snapshotNodeCount);
  if (options.longPathNodeCount) {
    const intermediates = Array.from({ length: options.longPathNodeCount - 3 }, (_, index) =>
      node(`server:hop-${index}`, "server", `Recorded service ${index + 1}`));
    graph.nodes = [graph.nodes[0]!, ...intermediates, graph.nodes[2]!, graph.nodes[3]!];
    graph.edges = graph.nodes.slice(1).map((item, index) => edge(graph.nodes[index]!.id, item.id, "depends_on"));
    graph.attack_paths = [{ ...graph.attack_paths[0]!, hops: graph.nodes.map(item => item.id), edges: graph.edges.map(item => item.id) }];
    graph.stats.total_nodes = graph.nodes.length;
    graph.stats.total_edges = graph.edges.length;
  }
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
          edge_count: graph.edges.length - 1,
          modeled: true,
          nodes: [...graph.nodes, proposedNode],
          edges: graph.edges.filter((item) => item.id !== "server:github->cred:gh-token:exposes_cred"),
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
            exposure_path: options.qualifiedEvidence ? {
              id: "qualified-path-fixture", label: "Recorded package path", summary: "Recorded relationships do not establish effective permission, exploitation or successful data access.",
              riskScore: 9.8, severity: "critical", source: { id: "agent:desktop", label: "claude-desktop", role: "agent" },
              target: { id: "cve:form-data", label: "CVE-2025-7783", role: "finding" },
              hops: attackPath.hops.map(id => graph.nodes.find(item => item.id === id)!).map(item => ({ id: item.id, label: item.label, role: item.entity_type === "vulnerability" ? "finding" : item.entity_type })),
              relationships: graph.edges.slice(0, 3), nodeIds: attackPath.hops, edgeIds: attackPath.edges,
              findings: attackPath.vuln_ids, affectedAgents: ["claude-desktop"], affectedServers: ["github"], reachableTools: [], exposedCredentials: [],
              evidenceDimensions: { reachability: { status: "unavailable", verdict: "unknown" }, exploitability: { status: "unavailable", verdict: "not_assessed" },
                impact: { status: "unavailable" }, actionability: { status: "unavailable" }, completeness: { status: "partial" } },
              provenance: { source: "fixture", scanId },
            } : undefined,
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
                href: "/remediation",
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
  for (const capture of [false, true]) {
  test(`scenario comparison stays truthful at ${proof.width}x${proof.height} ${proof.theme} capture=${capture}`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width: proof.width, height: proof.height });
    await routeCockpit(page, 36);
    await page.addInitScript((selectedTheme) => {
      window.localStorage.setItem("agent-bom-theme", selectedTheme);
    }, proof.theme);

    await page.goto(`/security-graph?lens=estate&rollup=0&scenario=scenario-private-endpoint&state=proposed${capture ? "&capture=1" : ""}`);
    await page.waitForLoadState("networkidle");
    await expect(page.getByRole("status")).toContainText(
      "Proposed scenario — not observed or deployed",
    );
    await expect(page.getByRole("group", { name: "Investigation view" })).toBeHidden();
    await expect(page.getByText("Current · observed")).toBeVisible();
    await expect(page.getByText("Proposed · modeled")).toBeVisible();
    const canvas = page.locator(".react-flow");
    await expect(canvas.locator('[data-id="proposal:scenario-private-endpoint:private-endpoint"]')).toBeAttached();
    await expect(canvas.locator('.react-flow__edge[data-id="server:github->cred:gh-token:exposes_cred"]')).toHaveCount(0);
    await expect.poll(() => canvas.locator(".react-flow__viewport").evaluate(
      (element) => new DOMMatrixReadOnly(getComputedStyle(element).transform).a,
    )).toBeGreaterThanOrEqual(0.9);
    const canvasBox = await canvas.boundingBox();
    expect(canvasBox).not.toBeNull();
    expect(canvasBox!.height).toBeGreaterThanOrEqual(400);
    expect(canvasBox!.y + canvasBox!.height).toBeLessThanOrEqual(proof.height + 16);
    const proposedBox = await canvas.locator('[data-id="proposal:scenario-private-endpoint:private-endpoint"]').boundingBox();
    expect(proposedBox).not.toBeNull();
    expect(proposedBox!.x).toBeGreaterThanOrEqual(canvasBox!.x);
    expect(proposedBox!.y).toBeGreaterThanOrEqual(canvasBox!.y);
    expect(proposedBox!.x + proposedBox!.width).toBeLessThanOrEqual(canvasBox!.x + canvasBox!.width);
    expect(proposedBox!.y + proposedBox!.height).toBeLessThanOrEqual(canvasBox!.y + canvasBox!.height);
    await page.screenshot({ path: testInfo.outputPath(`scenario-first-view-${proof.theme}-${capture}.png`) });
    await expect.poll(() => canvas.locator(".react-flow__node").evaluateAll((nodes) => {
      const frame = nodes[0]?.closest(".react-flow")?.getBoundingClientRect();
      if (!frame) return 0;
      return nodes.filter((node) => {
        const box = node.getBoundingClientRect();
        return box.left >= frame.left && box.right <= frame.right && box.top >= frame.top && box.bottom <= frame.bottom;
      }).length;
    })).toBeGreaterThanOrEqual(3);
    await expect(page.getByTestId("scenario-impact-summary")).toContainText("Observed paths touched");
    await expect(page.getByTestId("graph-viewport-scope")).toContainText("Fit all");
    await expect(page.getByTestId("graph-viewport-scope")).toContainText("Changes and neighbors");
    await page.getByRole("button", { name: "Show full graph" }).click();
    await expect(page.getByRole("button", { name: "Focus changes" })).toBeVisible();
    await expect(page.getByTestId("graph-viewport-scope")).not.toContainText("Changes and neighbors");
    await page.getByRole("button", { name: "Focus changes" }).click();
    await expect(page.getByTestId("graph-viewport-scope")).toContainText("Changes and neighbors");
    await page.getByRole("button", { name: "Review modeled changes" }).click();
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
    page.getByRole("heading", { name: "Claude Desktop → CVE-2025-7783" }),
  ).toBeVisible();
  // Progressive disclosure summary — avoid /Evidence/ which also matches "Evidence drawer".
  await expect(page.getByText("Evidence & relationships")).toBeVisible();
  await expect(page.getByText("Path priority", { exact: true }).first()).toBeVisible();
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
  await expect(page.getByRole("heading", { name: "Claude Desktop → CVE-2025-7783" })).toHaveCount(0);
});

test("focused investigation never shows an unrelated global path", async ({ page }) => {
  await routeCockpit(page, undefined, { emptyFocusResults: true });

  await page.goto(`/security-graph?scan=${scanId}&cve=CVE-2099-NOT-IN-SNAPSHOT`);
  await page.waitForLoadState("networkidle");

  await expect(page.getByText("No attack paths matched the current focus")).toBeVisible();
  await expect(page.getByText(/This does not establish whether the vulnerability is exploitable/)).toBeVisible();
  await expect(page.getByRole("heading", { name: "Claude Desktop → CVE-2025-7783" })).toHaveCount(0);
});

test("unlinked finding records require an explicit move to related package paths", async ({ page }) => {
  await routeCockpit(page);
  await page.goto(`/security-graph?lens=attack-path&scan=${scanId}&node=pkg%3Aform-data&cve=CVE-2025-7783&package=form-data&finding=unlinked-record`);
  await expect(page.getByText("No path is linked to this finding record")).toBeVisible();
  await page.getByRole("link", { name: "Show related package and advisory paths" }).click();
  await expect(page.getByRole("note", { name: "Finding association" })).toContainText("does not establish a link to the selected finding record");
  await expect(page.getByRole("heading", { name: "Claude Desktop → CVE-2025-7783" })).toBeVisible();
  expect(new URL(page.url()).searchParams.get("scan")).toBe(scanId);
  expect(new URL(page.url()).searchParams.get("node")).toBe("pkg:form-data");
  expect(new URL(page.url()).searchParams.has("finding")).toBe(false);
});

test("snapshot loading never claims that an empty graph loaded successfully", async ({ page }) => {
  await routeCockpit(page);
  let release!: () => void;
  const pending = new Promise<void>(resolve => { release = resolve; });
  await page.route("**/v1/graph/snapshots?**", async route => { await pending; await route.fallback(); });
  try {
    await page.goto(`/security-graph?lens=attack-path&scan=${scanId}&cve=CVE-2025-7783`);
    await expect(page.getByRole("heading", { name: "Loading security graph" })).toBeVisible();
    await expect(page.getByText(/The persisted graph loaded successfully/)).toHaveCount(0);
  } finally {
    release();
  }
});

test("ranked persisted paths render before slower fix guidance", async ({ page }) => {
  await routeCockpit(page, undefined, { fixFirstDelayMs: 2_000 });

  await page.goto("/security-graph?lens=attack-path");
  await expect(page.getByText("#1 fix first")).toBeVisible();
  await expect(page.getByText(/Ranked paths are ready; fix guidance is still loading/)).toBeVisible();
  await expect(page.getByText("agent → server → package → finding")).toBeVisible();

  await expect(page.getByRole("heading", { name: "Claude Desktop → CVE-2025-7783" })).toBeVisible();
});

test("top-path deep links settle and keep subsequent queue selection interactive", async ({ page }) => {
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  page.on("console", (message) => {
    if (message.type() === "error" && /Maximum update depth/.test(message.text())) errors.push(message.text());
  });
  await routeCockpit(page);
  await page.goto(`/security-graph?lens=attack-path&scan=${scanId}&path=top`);
  const detail = page.getByTestId("selected-exposure-path");
  await expect(detail.getByRole("heading", { name: "Claude Desktop → CVE-2025-7783" })).toBeVisible();
  await expect(detail.getByTestId("exposure-path-primary-action")).toHaveAttribute(
    "href", `/remediation?scan=${scanId}&cve=CVE-2025-7783&package=form-data%404.0.0`,
  );
  await page.getByLabel("Attack path queue").getByRole("button", { name: /#2/ }).click();
  await expect(page.getByRole("status")).toContainText("Focused path 2");
  // Let post-selection effects settle before checking that focus stays put.
  await page.waitForTimeout(500);
  await expect(page.getByRole("status")).toContainText("Focused path 2");
  await expect(detail).toBeVisible();
  expect(errors).toEqual([]);
});

test("ranked path selection opens the ordered path and can expand the interactive graph", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 1000 });
  await routeCockpit(page);

  await page.goto("/security-graph?lens=attack-path");
  await page.waitForLoadState("networkidle");

  const workspace = page.getByRole("region", { name: "Investigation workspace" });
  const queue = workspace.getByLabel("Attack path queue");
  const detail = workspace.getByRole("region", { name: "Selected path detail" });
  const [queueBox, detailBox] = await Promise.all([workspace.locator(".investigation-queue").boundingBox(), detail.boundingBox()]);
  expect(queueBox).not.toBeNull();
  expect(detailBox).not.toBeNull();
  expect(Math.abs(queueBox!.y - detailBox!.y)).toBeLessThan(200);

  await queue.getByRole("button", { name: /#2/ }).click();
  await expect(detail.getByRole("button", { name: "Path", exact: true })).toHaveAttribute("aria-pressed", "true");
  await detail.getByRole("button", { name: "Graph", exact: true }).click();
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

test("mobile ranked path selection moves the ordered path into view", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await routeCockpit(page);

  await page.goto("/security-graph?lens=attack-path");
  await page.waitForLoadState("networkidle");

  await page.getByRole("button", { name: /Paths & filters/ }).click();
  const queue = page.getByLabel("Attack path queue");
  await queue.getByRole("button", { name: /#2/ }).click();
  const detail = page.getByRole("region", { name: "Selected path detail" });
  await expect(detail.getByRole("button", { name: "Path", exact: true })).toHaveAttribute("aria-pressed", "true");
  await expect.poll(async () => (await detail.boundingBox())?.y ?? Number.POSITIVE_INFINITY).toBeLessThan(120);
});

for (const theme of ["light", "dark"] as const) {
for (const width of [1440, 390]) {
test(`a priority path outside the queue page loads its exact graph in ${theme} at ${width}px`, async ({ page }, testInfo) => {
  await page.setViewportSize({ width, height: width < 640 ? 844 : 960 });
  await page.addInitScript((value) => window.localStorage.setItem("agent-bom-theme", value), theme === "light" ? "dark" : "light");
  await routeCockpit(page);
  const source = node("repo:isolated", "directory", "Isolated repository");
  const target = node("ci:isolated", "ci_job", "Isolated build");
  const path = { ...buildCockpitGraph().attack_paths[0]!, source: source.id, target: target.id,
    hops: [source.id, target.id], edges: ["contains"], vuln_ids: [] };
  await page.route("**/v1/graph/views/fix-first?**", route => route.fulfill({ json: {
    scan_id: scanId, tenant_id: "default", created_at: createdAt, attack_campaigns: [],
    summary: { total_paths: 3, matched_paths: 3, returned_paths: 1, highest_risk: 9.8, covered_findings: 0, node_count: 7, edge_count: 5 },
    focus: { cve: "", package: "", agent: "" },
    cards: [{ id: "isolated", rank: 1, title: "Isolated build path", summary: "Recorded build relationship",
      attack_path: path, nodes: [source, target], sequence_labels: [], risk_reasons: [], next_actions: [],
      affected: { agents: [], servers: [], packages: [], findings: [], credentials: [], tools: [] } }],
  } }));
  const queries: Record<string, unknown>[] = [];
  await page.route("**/v1/graph/query", (route) => {
    queries.push(route.request().postDataJSON());
    return route.fulfill({ json: { ...buildCockpitGraph(), nodes: [source, target],
      edges: [edge(source.id, target.id, "contains")], attack_paths: [], truncated: width < 640, missing_roots: [] } });
  });
  await page.goto("/security-graph?lens=attack-path");
  await page.getByRole("button", { name: `Switch to ${theme} theme`, exact: true }).click();
  await expect(page.locator("html")).toHaveAttribute("data-theme", theme);
  if (width < 1024) await page.getByRole("button", { name: /Paths & filters/ }).click();
  await page.getByLabel("Attack path queue").getByRole("button", { name: /#1 FIX FIRST/i }).click();
  const detail = page.getByRole("region", { name: "Selected path detail" });
  await detail.getByRole("button", { name: "Graph", exact: true }).click();
  const canvas = detail.getByTestId("security-graph-investigation");
  await expect(canvas.locator(".react-flow__node")).toHaveCount(2);
  await expect(canvas.locator(".react-flow__edge")).toHaveCount(1);
  await expect(canvas.getByText("Isolated repository", { exact: true })).toBeVisible();
  await expect(canvas.getByText("Isolated build", { exact: true })).toBeVisible();
  await expect(canvas.getByText("claude-desktop", { exact: true })).toHaveCount(0);
  if (width < 640) {
    await expect(detail).toContainText("Selected path loaded. Broader context was limited by the graph query budget.");
    const inViewport = (id: string) => canvas.locator(`.react-flow__node[data-id="${id}"]`).evaluate(element => {
      const box = element.getBoundingClientRect();
      return box.width >= 180 && box.left >= 0 && box.right <= innerWidth && box.top >= 0 && box.bottom <= innerHeight;
    });
    await expect.poll(() => inViewport(source.id)).toBe(true);
    for (let attempt = 0; attempt < 3; attempt++) {
      await canvas.getByRole("button", { name: "Next graph node" }).click();
      await expect(canvas.getByText("Focused view · 2 of 2")).toBeVisible();
      await expect.poll(() => inViewport(target.id)).toBe(true);
      await canvas.getByRole("button", { name: "Previous graph node" }).click();
      await expect(canvas.getByText("Focused view · 1 of 2")).toBeVisible();
      await expect.poll(() => inViewport(source.id)).toBe(true);
    }
  }
  // Narrow panels start with readable node focus; the explicit overview still
  // has to frame every hydrated hop without loading unrelated topology.
  await canvas.locator(".react-flow__controls-fitview").click();
  await expect.poll(async () => {
    const bounds = await canvas.boundingBox();
    if (!bounds) return false;
    const boxes = await Promise.all((await canvas.locator(".react-flow__node").all()).map((node) => node.boundingBox()));
    return boxes.every((box) => box && box.x >= bounds.x && box.x + box.width <= bounds.x + bounds.width);
  }).toBe(true);
  expect(queries).toHaveLength(1);
  expect(queries[0]).toMatchObject({ roots: [source.id, target.id], scan_id: scanId, max_nodes: 2, max_depth: 1, include_attack_paths: false });
  await page.screenshot({ path: testInfo.outputPath(`selected-path-${theme}-${width}.png`), fullPage: true });
});
}
}

async function openEvidenceControls(page: Page) {
  const controls = page.getByTestId("graph-evidence-controls");
  await expect(controls).toBeVisible();
  if ((await controls.getAttribute("open")) === null) {
    await controls.locator(":scope > summary").click();
  }
  await expect(controls).toHaveAttribute("open", "");
  return controls;
}

for (const theme of ["dark", "light"] as const) {
test(`large estates lead with non-overlapping clusters in ${theme}`, async ({ page }, testInfo: TestInfo) => {
  await routeCockpit(page, 1_241);
  await page.addInitScript((selectedTheme) => {
    window.localStorage.setItem("agent-bom-theme", selectedTheme);
  }, theme);

  await page.goto("/security-graph?lens=attack-path");
  await page.waitForLoadState("networkidle");

  await page.getByText("Investigation tools · snapshots, correlation & checks", { exact: true }).click();
  await expect(page.getByRole("button", { name: "Evidence scope" })).toHaveAttribute("aria-pressed", "true");
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
  await openEvidenceControls(page);
  await expect(page.getByText("Scope navigation", { exact: true })).toBeVisible();
  // Aggregated scope navigation must retain the actual relationship edge.
  await expect(page.locator(".react-flow__edge")).toHaveCount(1);
  await expect(page.getByTestId("graph-compression-summary")).toHaveCount(0);
  await expect(page.getByText(/2 nodes and scopes at this level.*1241 nodes in snapshot/)).toBeVisible();
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
  await openEvidenceControls(page);
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
  await openEvidenceControls(page);
  await expect(page.getByText("Scope navigation", { exact: true })).toBeVisible();
  await expect(page.getByText("2 nodes and scopes at this level · 200 nodes in snapshot", { exact: true })).toBeVisible();

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
  await openEvidenceControls(page);
  await expect(page.getByText(/Roll-up unavailable/i)).toBeVisible();
  expect(await page.locator(".react-flow__edge").count()).toBeGreaterThan(0);
});

test("eligible roll-up shows a loading surface without raw-topology counts", async ({ page }) => {
  await routeCockpit(page, 200, { rollupDelayMs: 3_000 });

  await page.goto(`/graph?scan=${scanId}`);
  await openEvidenceControls(page);
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

  const paths = page.getByText(/\d+ shown · \d+ loaded paths/).first();
  await expect(paths).toBeVisible();
  await expect(page.getByText(/from the path queue \+ \d+ additional priority paths/)).toBeVisible();
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
    const evidenceControls = page.getByTestId("graph-evidence-controls");
    await expect(evidenceControls).toBeVisible();
    await expect(evidenceControls).not.toHaveAttribute("open", "");
    await expect(evidenceControls.getByRole("button", { name: /Estate/ })).toBeHidden();
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
    await detail.getByRole("button", { name: "Graph", exact: true }).click();
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
    expect(legendBox!.y).toBeGreaterThanOrEqual(canvasBox!.y);
    expect(legendBox!.y + legendBox!.height).toBeLessThanOrEqual(nodeBandBox!.y + 1);
    expect(interactionBox!.y + interactionBox!.height).toBeLessThanOrEqual(nodeBandBox!.y + 1);

    await interactionBand.getByText("Layout", { exact: true }).click();
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
    await detail.getByRole("button", { name: "Graph", exact: true }).click();
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


test("selected paths 13 and 25 retain hydrated anchors beyond fix-first enrichment", async ({ page }) => {
  await routeCockpit(page);
  const graph = buildCockpitGraph();
  const paths = Array.from({ length: 25 }, (_, index) => {
    const ordinal = index + 1;
    const source = `container:occurrence-${ordinal}`;
    const target = `finding:occurrence-${ordinal}`;
    graph.nodes.push(node(source, "container", `runtime-anchor-${ordinal}`));
    graph.nodes.push(node(target, "vulnerability", `finding-anchor-${ordinal}`, "high", 7));
    graph.edges.push(edge(source, target, "vulnerable_to"));
    return {
      ...graph.attack_paths[0]!, source, target,
      hops: [source, target], edges: ["vulnerable_to"],
      composite_risk: 10 - ordinal / 100,
      summary: `Occurrence ${ordinal} exposure`, vuln_ids: [`finding-${ordinal}`],
    };
  });
  await page.route("**/v1/graph/views/fix-first?**", route => route.fulfill({
    json: { scan_id: scanId, tenant_id: "default", created_at: createdAt, cards: [], attack_campaigns: [],
      summary: { total_paths: 25, matched_paths: 25, returned_paths: 0, highest_risk: 9.99, covered_findings: 25, node_count: graph.nodes.length, edge_count: graph.edges.length } },
  }));
  await page.route("**/v1/graph/attack-paths?**", route => {
    const offset = Number(new URL(route.request().url()).searchParams.get("offset") ?? 0);
    const selected = offset === 0 ? paths.slice(0, 12) : paths.slice(12);
    return route.fulfill({ json: {
      ...graph, attack_paths: selected,
      pagination: { total: 25, offset, limit: offset === 0 ? 12 : 100, has_more: offset === 0 },
    } });
  });
  await page.goto("/security-graph?lens=attack-path");
  const queue = page.getByLabel("Attack path queue");
  await expect(queue.getByRole("button", { name: /#12\b/ })).toBeVisible();
  await page.getByRole("button", { name: "Show 12 more", exact: true }).click();
  await queue.getByRole("button", { name: /#13\b/ }).click();
  const proof = page.getByTestId("attack-path-correlation-proof");
  await proof.locator("summary").filter({ hasText: /^Exact anchors/ }).click();
  await expect(proof.getByText("runtime-anchor-13", { exact: true })).toBeVisible();
  await expect(proof.getByText("finding-anchor-13", { exact: true })).toBeVisible();
  await expect(proof.getByText(/path nodes unavailable/)).toHaveCount(0);
  await page.getByRole("button", { name: "Show 1 more", exact: true }).click();
  await queue.getByRole("button", { name: /#25\b/ }).click();
  await expect(proof.getByText("runtime-anchor-25", { exact: true })).toBeVisible();
  await expect(proof.getByText("finding-anchor-25", { exact: true })).toBeVisible();
  await expect(proof.getByText(/path nodes unavailable/)).toHaveCount(0);
});


test("URL-selected path returns to summary without reopening the path", async ({ page }) => {
  await routeCockpit(page, 200, { rollupItemCount: 30 });
  await page.goto(`/security-graph?lens=estate&scan=${scanId}&path=top`);
  const views = page.getByRole("group", { name: "Investigation view" });
  await views.getByRole("button", { name: "Summary", exact: true }).click();
  await expect(page.getByTestId("graph-rollup-decision-surface")).toBeVisible();
  await expect(page).not.toHaveURL(/[?&]path=/);
  await views.getByRole("button", { name: "Graph", exact: true }).click();
  await views.getByRole("button", { name: "Summary", exact: true }).click();
  await expect(page.getByTestId("graph-rollup-decision-surface")).toBeVisible();
  await expect(page).not.toHaveURL(/[?&]path=/);
});

for (const theme of ["light", "dark"] as const) {
  test(`estate topology starts readable and fits all on request with compact controls in ${theme}`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await routeCockpit(page, 200, { rollupItemCount: 30 });
    await page.addInitScript((value) => localStorage.setItem("agent-bom-theme", value), theme);
    await page.goto("/security-graph");
    await expect(page.getByTestId("graph-rollup-decision-surface")).toBeVisible();
    const views = page.getByRole("group", { name: "Investigation view" });
    await views.getByRole("button", { name: "Graph", exact: true }).click();
    const canvas = page.locator(".react-flow").first();
    await expect(canvas.locator(".react-flow__node")).toHaveCount(30);
    await expect(page.getByTestId("graph-viewport-scope")).toContainText("Focused view");
    await expect.poll(() => canvas.locator(".react-flow__viewport").evaluate(element =>
      new DOMMatrixReadOnly(getComputedStyle(element).transform).a,
    )).toBeGreaterThanOrEqual(1);
    await page.screenshot({ path: testInfo.outputPath(`estate-readable-${theme}.png`), fullPage: false });
    await page.getByRole("button", { name: "Fit all", exact: true }).click();
    await expect.poll(() => canvas.evaluate((element) => {
      const frame = element.getBoundingClientRect();
      return [...element.querySelectorAll(".react-flow__node")].every((node) => {
        const box = node.getBoundingClientRect();
        return box.left >= frame.left && box.top >= frame.top && box.right <= frame.right && box.bottom <= frame.bottom;
      });
    })).toBe(true);
    const frame = await canvas.boundingBox();
    expect(frame!.y).toBeLessThan(330);
    expect(frame!.height).toBeGreaterThan(500);
    await expect(canvas.locator(".react-flow__minimap")).toBeHidden();
    await expect(views.getByRole("button")).toHaveCount(2);
    await page.screenshot({ path: testInfo.outputPath(`estate-topology-${theme}.png`), fullPage: false });
    await views.getByRole("button", { name: "Summary", exact: true }).click();
    await expect(page.getByTestId("graph-rollup-decision-surface")).toBeVisible();
    await expect(page.getByTestId("graph-viewport-scope")).toBeHidden();
  });
}

for (const theme of ["light", "dark"] as const) {
  test(`nonstandard path hops expand with retry and reconciled queue counts in ${theme}`, async ({ page }, testInfo) => {
    await routeCockpit(page);
    await page.setViewportSize({ width: 1568, height: 1000 });
    await page.addInitScript((value) => localStorage.setItem("agent-bom-theme", value), theme);
    const graph = buildCockpitGraph();
    const repo = node("repo:billing", "directory", "Billing repository");
    const job = node("ci:billing", "ci_job", "Build billing");
    graph.nodes.push(repo, job);
    const extra = { ...graph.attack_paths[0]!, source: repo.id, hops: [repo.id, job.id, "pkg:form-data", "cve:form-data"] };
    await page.route("**/v1/graph/views/fix-first?**", route => route.fulfill({ json: {
      scan_id: scanId, tenant_id: "default", created_at: createdAt, attack_campaigns: [],
      summary: { total_paths: 3, matched_paths: 3, returned_paths: 1, highest_risk: 9.8, covered_findings: 1, node_count: graph.nodes.length, edge_count: graph.edges.length },
      focus: { cve: "", package: "", agent: "" },
      cards: [{ id: "priority-repo", rank: 1, title: "Billing dependency exposure", summary: "Build uses a vulnerable dependency", attack_path: extra,
        nodes: graph.nodes, sequence_labels: [], risk_reasons: [], next_actions: [],
        affected: { agents: [], servers: [], packages: [], findings: [], credentials: [], tools: [] } }],
    } }));
    let attempts = 0;
    await page.route("**/v1/graph/node/*/neighbors?**", route => {
      attempts += 1;
      if (attempts === 1) return route.fulfill({ status: 503, json: { detail: "Unavailable" } });
      return route.fulfill({ json: { node_id: repo.id, scan_id: scanId, found: true, direction: "both", limit: 12,
        total_neighbors: 1, truncated: false, neighbors: [job], edges: [edge(repo.id, job.id, "contains")] } });
    });
    await page.goto("/security-graph?lens=attack-path");
    await expect(page.getByRole("heading", { name: "3 shown · 3 loaded paths" })).toBeVisible();
    await expect(page.getByText(/2 from the path queue \+ 1 additional priority paths/)).toBeVisible();
    await page.getByLabel("Attack path queue").getByRole("button", { name: /#1 fix first/ }).click();
    await page.getByRole("button", { name: "List", exact: true }).click();
    const explorer = page.getByRole("region", { name: "Expand path neighbors" });
    await explorer.getByRole("button", { name: "Expand neighbors of Billing repository" }).click();
    await explorer.getByRole("button", { name: "Retry neighbor lookup" }).click();
    await expect(explorer.getByText("Outgoing relationships", { exact: true })).toBeVisible();
    await expect(explorer.getByText("Contains", { exact: true })).toBeVisible();
    await expect(explorer.getByRole("button", { name: "Expand neighbors of Build billing" })).toBeVisible();
    await expect(explorer.getByText("leaf", { exact: true })).toHaveCount(0);
    await expect(explorer.getByRole("link", { name: "Traverse from Billing repository" })).toHaveAttribute("href", /root=repo%3Abilling/);
    await explorer.scrollIntoViewIfNeeded();
    await page.screenshot({ path: testInfo.outputPath(`path-neighbors-${theme}.png`) });
  });
}

for (const proof of [
  { theme: "light", width: 1440, height: 1000 },
  { theme: "dark", width: 1440, height: 1000 },
  { theme: "light", width: 390, height: 844 },
  { theme: "dark", width: 390, height: 844 },
] as const) {
  test(`exposure evidence pagination remains readable ${proof.theme} ${proof.width}`, async ({ page }, testInfo) => {
    await page.setViewportSize(proof);
    await page.addInitScript(theme => localStorage.setItem("agent-bom-theme", theme), proof.theme);
    await routeCockpit(page);
    const requests: URL[] = [];
    await page.route("**/v1/graph/exposure-paths?**", async route => {
      const url = new URL(route.request().url());
      requests.push(url);
      const second = url.searchParams.has("cursor");
      const source = { id: "agent:desktop", label: "A long assistant name with deployment context and an extended readable source label", role: "agent" };
      const target = { id: second ? "data:second" : "data:first", label: second ? "Second page asset" : "First page asset", role: "data" };
      const unavailable = { status: "unavailable", verdict: null };
      await route.fulfill({ contentType: "application/json", body: JSON.stringify({
        schema_version: "v1", tool: "exposure_paths", scan_id: scanId, count: 1, total: 2,
        pagination: { offset: second ? 1 : 0, limit: 25, returned: 1, has_more: !second, next_cursor: second ? null : "next-page" },
        paths: [{
          id: target.id, label: target.label, summary: "Static evidence; execution is unverified.", riskScore: 30, severity: "high",
          source, target, hops: [source, target], nodeIds: [source.id, target.id], edgeIds: ["context"], findings: [],
          relationships: [{ id: "context", source: source.id, target: target.id, relationship: "accessed", direction: "directed", traversable: false }],
          reachableTools: [], exposedCredentials: [], reachability: "unknown",
          hopEvidence: [{source_node_id: source.id, target_node_id: target.id, relationship: "accessed", source_snapshot_ids: ["synthetic-runtime:blocked"], relationship_provenance: "recorded", evidence_tier: "runtime_observed", freshness: "fresh", runtime_observed_state: "blocked", runtime_outcome: "blocked", direction: "directed", traversable: false, complete: false, truncated: false, correlation_identity_status: "current", authority: {
            status: "recorded", derivation: null, reason_codes: [], native_grants: ["SELECT", "INSERT"].map(privilege => ({
              source: "snowflake-objects", privilege, account: "synthetic-account", role: "ANALYST", object_fqn: "DB.PUBLIC.ORDERS", object_type: "table",
            })), decisions: Array.from({length: 8}, (_, index) => ({
              source: "authorization-evidence", provider: "gcp", decision: "allow", action: `storage.objects.read:${index}`,
              principal_id: source.id, resource: "projects/_/buckets/synthetic-example", binding_ids: [`source-grant:${index}`], observed_at: null,
            })),
          }}],
          evidenceDimensions: { reachability: unavailable, exploitability: unavailable, impact: unavailable, actionability: unavailable, completeness: { status: "partial" } },
          provenance: { source: "fixture", scanId },
        }],
      }) });
    });
    await page.goto(`/security-graph?lens=attack-path&scan=${scanId}`);
    await page.getByText("Investigation tools · snapshots, correlation & checks", { exact: true }).click();
    await page.getByRole("button", { name: /Exposure paths/ }).click();
    const lens = page.getByTestId("exposure-path-lens");
    await expect(lens.getByRole("region", { name: "Path evidence assessment" })).toContainText("Unknown");
    await lens.getByText("Evidence & relationships", { exact: true }).click();
    await expect(lens.getByRole("region", { name: "Relationship proof" })).toContainText("Context only; not traversable");
    await lens.getByText("Inspect 1 hop receipts", { exact: true }).click();
    const inspector = lens.getByRole("region", { name: "Hop evidence inspector" });
    const hopButton = inspector.getByRole("button", { name: /1\. A long assistant/ });
    await hopButton.focus();
    await page.keyboard.press("Enter");
    await expect(hopButton).toHaveAttribute("aria-expanded", "true");
    await expect(inspector).toContainText("Blocked attempt");
    await expect(inspector).toContainText("synthetic-runtime:blocked");
    await expect(inspector).toContainText("This receipt cannot establish a successful downstream action");
    const authority = inspector.getByRole("region", { name: "Recorded authority" });
    await expect(authority).toContainText("Snapshot evidence, not a current permission check");
    await expect(authority.getByText("storage.objects.read:0 · allow", {exact: true})).toBeVisible();
    await authority.getByRole("button", {name: "Next receipts"}).click();
    await expect(authority.getByText("storage.objects.read:4 · allow", {exact: true})).toBeVisible();
    const bindings = authority.getByText("Source bindings (1)", {exact: true}).first();
    await bindings.click();
    await expect(authority.getByText("source-grant:4", {exact: true})).toBeVisible();
    await authority.getByRole("button", {name: "Next receipts"}).click();
    await expect(authority.getByText("SELECT · Native grant", {exact: true})).toBeVisible();
    await authority.getByText("INSERT · Native grant", {exact: true}).scrollIntoViewIfNeeded();
    await expect(authority.getByText("INSERT · Native grant", {exact: true})).toBeVisible();
    await expect(authority).toContainText("Session authorization and policy effects require separate evidence");
    await authority.getByRole("list", {name: "Authority receipts"}).evaluate(element => { element.scrollTop = 0; });
    expect(await authority.evaluate(element => element.scrollWidth <= element.clientWidth + 1)).toBe(true);
    await authority.evaluate(element => element.scrollIntoView({block: "start"}));
    await authority.screenshot({path: testInfo.outputPath(`hop-authority-${proof.theme}-${proof.width}.png`)});
    await hopButton.focus();
    expect(await inspector.evaluate(element => element.scrollWidth <= element.clientWidth + 1)).toBe(true);
    await inspector.screenshot({path: testInfo.outputPath(`hop-evidence-${proof.theme}-${proof.width}.png`)});
    await page.keyboard.press("Enter");
    await expect(hopButton).toHaveAttribute("aria-expanded", "false");
    await lens.getByRole("button", { name: "Next paths" }).click();
    await expect(lens.getByRole("status")).toContainText("Page 2");
    await expect(lens.getByRole("button", { name: "Next paths" })).toBeDisabled();
    await expect(lens.getByRole("list", { name: "Exposure path queue" })).toContainText(/Second Page Asset/i);
    await lens.getByRole("button", { name: "Previous paths" }).click();
    await expect(lens.getByRole("status")).toContainText("Page 1");
    // The initial request can resolve latest before the parent loads its scope;
    // both continuation and backward navigation must retain the resolved scan.
    expect(requests.slice(-2).every(url => url.searchParams.get("scan_id") === scanId)).toBe(true);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
  });
}

for (const theme of ["light", "dark"] as const) {
  test(`focused path and qualifications fit the first desktop viewport ${theme}`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.addInitScript(value => localStorage.setItem("agent-bom-theme", value), theme);
    await routeCockpit(page, undefined, { qualifiedEvidence: true });
    await page.goto(`/security-graph?lens=attack-path&scan=${scanId}&node=pkg%3Aform-data&cve=CVE-2025-7783&package=form-data`);
    const detail = page.getByTestId("selected-exposure-path");
    await expect(detail).toBeVisible();
    const diagram = detail.getByRole("img", { name: /Selected exposure path graph/ });
    await expect(diagram).toBeVisible();
    // Resolving the parent scan scope can briefly remount this diagram. Read
    // one box per attempt and retry missing geometry without accepting it.
    await expect.poll(async () => {
      const bounds = await diagram.boundingBox();
      return bounds ? bounds.y + bounds.height : Number.POSITIVE_INFINITY;
    }).toBeLessThanOrEqual(900);
    await expect(detail.getByRole("region", { name: "Path evidence assessment" })).toContainText("Reachability");
    await expect(detail.getByRole("region", { name: "Path evidence assessment" })).toContainText("Exploitability");
    await expect(detail.getByRole("region", { name: "Path evidence assessment" })).toContainText("Assessment completeness");
    await expect(detail.getByTestId("exposure-path-primary-action")).toBeVisible();
    await expect(detail.getByText("Evidence & relationships", { exact: true })).toBeVisible();
    await page.screenshot({ path: testInfo.outputPath(`focused-path-${theme}.png`) });
  });
}

for (const theme of ["light", "dark"] as const) {
  for (const width of [1568, 390]) {
    test(`investigation workspace keeps graph primary with usable pane navigation ${theme} ${width}`, async ({ page }, testInfo) => {
      await page.setViewportSize({ width, height: 1000 });
      await page.addInitScript(value => localStorage.setItem("agent-bom-theme", value), theme);
      await routeCockpit(page, undefined, { qualifiedEvidence: true });
      await page.goto(`/security-graph?lens=attack-path&scan=${scanId}`);
      const workspace = page.getByRole("region", { name: "Investigation workspace" });
      const detail = workspace.getByRole("region", { name: "Selected path detail" });
      await expect(detail).toBeVisible();
      await expect(detail.getByRole("region", { name: "Path evidence assessment" })).toContainText(/unknown/i);
      await expect(detail.getByRole("heading", { level: 2 })).not.toContainText(/reachable|exploitable/i);
      const queue = page.getByLabel("Attack path queue");
      await expect(queue).not.toContainText(/Critical package reachable/);
      if (width < 1024) {
        await expect(queue).toBeHidden();
        await page.getByRole("button", { name: /Paths & filters/ }).click();
        await expect(queue).toBeVisible();
        await expect(detail).toBeHidden();
        await queue.getByRole("button", { name: /#2/ }).click();
        await expect(queue).toBeHidden();
        await expect(detail).toBeVisible();
        await expect(detail.getByRole("heading", { level: 2 })).toContainText("GITHUB PERSONAL ACCESS TOKEN");
        const steps = detail.getByTestId("exposure-path-sequence");
        expect((await steps.boundingBox())!.height).toBeLessThan(280);
        await detail.getByRole("button", { name: "Next path steps" }).click();
        await expect.poll(() => steps.evaluate(element => element.scrollLeft)).toBeGreaterThan(0);
        await expect(detail.getByRole("button", { name: "Previous path steps" })).toBeEnabled();
        await detail.getByRole("button", { name: "Previous path steps" }).click();
        await expect.poll(() => steps.evaluate(element => element.scrollLeft)).toBe(0);
      } else {
        const [queueBox, detailBox] = await Promise.all([queue.boundingBox(), detail.boundingBox()]);
        expect(queueBox!.x + queueBox!.width).toBeLessThan(detailBox!.x);
        expect(queueBox!.height).toBeLessThanOrEqual(650);
        const graph = detail.getByRole("region", { name: "Selected exposure path graph", exact: true });
        const proof = detail.getByRole("complementary", { name: "Selected path evidence" });
        const [graphBox, proofBox] = await Promise.all([graph.boundingBox(), proof.boundingBox()]);
        expect(proofBox!.x).toBeGreaterThan(graphBox!.x);
        expect(Math.abs(proofBox!.y - graphBox!.y)).toBeLessThan(80);
        expect(graphBox!.y + graphBox!.height).toBeLessThan(1000);
      }
      await expect(page.getByRole("button", { name: "Should I deploy?" })).toBeHidden();
      await page.getByText("Investigation tools · snapshots, correlation & checks", { exact: true }).click();
      await page.getByRole("button", { name: "Should I deploy?" }).click();
      await expect(page.getByPlaceholder(/agent:claude-desktop/)).toBeVisible();
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
      await page.getByText("Investigation tools · snapshots, correlation & checks", { exact: true }).click();
      await page.evaluate(() => window.scrollTo(0, 0));
      await page.screenshot({ path: testInfo.outputPath(`workspace-${theme}-${width}.png`), fullPage: true });
    });
  }
}

for (const theme of ["light", "dark"] as const) {
 for (const height of [800, 1000]) {
  test(`selected Graph keeps its nodes in the first desktop viewport ${theme} ${height}`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width: 1568, height });
    await page.addInitScript(value => localStorage.setItem("agent-bom-theme", value), theme);
    await routeCockpit(page, undefined, { qualifiedEvidence: true });
    await page.goto(`/security-graph?lens=attack-path&scan=${scanId}&node=pkg%3Aform-data&cve=CVE-2025-7783&package=form-data`);
    const detail = page.getByTestId("selected-exposure-path");
    await detail.getByRole("button", { name: "Graph", exact: true }).click();
    const canvas = page.getByTestId("security-graph-investigation");
    await expect(canvas.locator(".react-flow__node")).toHaveCount(4);
    await expect(canvas.locator(".react-flow__edge")).toHaveCount(3);
    await page.evaluate(() => window.scrollTo(0, 0));
    let previousTransform = "";
    let unchangedSince = Date.now();
    await expect.poll(async () => {
      const transform = await canvas.locator(".react-flow__viewport").getAttribute("style");
      if (transform !== previousTransform) {
        previousTransform = transform ?? "";
        unchangedSince = Date.now();
      }
      return Date.now() - unchangedSince >= 350;
    }, { intervals: [100] }).toBe(true);
    await expect.poll(() => canvas.locator(".react-flow__node").evaluateAll(elements =>
      elements.every(element => {
        const box = element.getBoundingClientRect();
        const flow = element.closest(".react-flow")!;
        const frame = flow.getBoundingClientRect();
        const controls = flow.querySelector(".react-flow__controls")!.getBoundingClientRect();
        const overlapsControls = box.left < controls.right && box.right > controls.left && box.top < controls.bottom && box.bottom > controls.top;
        return box.top >= 0 && box.bottom <= innerHeight && box.left >= frame.left && box.right <= frame.right && !overlapsControls;
      }),
    )).toBe(true);
    await expect(detail.getByRole("region", { name: "Path evidence assessment" })).toContainText(/unknown/i);
    await expect(detail.getByRole("complementary", { name: "Selected path evidence" })).toBeVisible();
    await page.screenshot({ path: testInfo.outputPath(`selected-graph-${theme}-${height}.png`), fullPage: true });
  });
}
}

for (const theme of ["light", "dark"] as const) {
 for (const width of [390, 1568]) {
  test(`node impact qualifies bounded upstream connections in ${theme} at ${width}px`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width, height: 900 });
    await page.addInitScript(value => localStorage.setItem("agent-bom-theme", value), theme);
    await routeCockpit(page, undefined, { qualifiedEvidence: true });
    const graph = buildCockpitGraph();
    const selectedNode = graph.nodes.find(item => item.id === "pkg:form-data")!;
    await page.route("**/v1/graph/node/*?**", route => route.fulfill({ json: {
      node: selectedNode, edges_in: [], edges_out: [], neighbors: [], sources: ["scan"],
      impact: { node_id: selectedNode.id, affected_nodes: ["agent:desktop", "server:github"], affected_count: 2,
        affected_by_type: { agent: 1, server: 1 }, max_depth_reached: 2,
        completeness: { status: "truncated", complete: false, truncated: true, sampled: false, returned: 2, reason: "depth_limit" } },
    } }));
    await page.goto(`/security-graph?lens=attack-path&scan=${scanId}&node=pkg%3Aform-data&cve=CVE-2025-7783&package=form-data`);
    await page.getByTestId("selected-exposure-path").getByRole("button", { name: "Graph", exact: true }).click();
    await page.locator('.react-flow__node[data-id="pkg:form-data"]').click();
    const drawer = page.getByTestId("graph-entity-drawer");
    await drawer.getByTestId("graph-drawer-tab-impact").click();
    const panel = drawer.getByTestId("graph-drawer-panel-impact");
    await expect(panel).toContainText("Upstream connected entities");
    await expect(panel).toContainText("Partial traversal · 2 entities returned");
    await expect(panel).toContainText("additional upstream connections may exist");
    await expect(panel).toContainText("do not establish exploitability, successful actions or observed damage");
    await expect(panel).toContainText("Agent: 1");
    await expect(panel).toContainText("Server: 1");
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await panel.screenshot({ path: testInfo.outputPath(`impact-scope-${theme}-${width}.png`) });
  });
 }
}

for (const theme of ["light", "dark"] as const) {
  test(`mobile selected Graph navigates a long path at readable zoom in ${theme}`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await page.addInitScript(value => localStorage.setItem("agent-bom-theme", value), theme === "light" ? "dark" : "light");
    await routeCockpit(page, undefined, { qualifiedEvidence: true, longPathNodeCount: 10 });
    await page.goto(`/security-graph?lens=attack-path&scan=${scanId}&node=pkg%3Aform-data&cve=CVE-2025-7783&package=form-data`);
    await page.getByRole("button", { name: `Switch to ${theme} theme`, exact: true }).click();
    await expect(page.locator("html")).toHaveAttribute("data-theme", theme);
    const detail = page.getByTestId("selected-exposure-path");
    const sequence = detail.getByTestId("exposure-path-sequence");
    await expect(sequence.locator("li")).toHaveCount(10);
    await expect(sequence.locator("li").filter({ visible: true }).first()).toBeVisible();
    expect((await sequence.locator("li").filter({ visible: true }).first().boundingBox())!.width).toBeGreaterThanOrEqual(180);
    await detail.getByRole("button", { name: "Graph", exact: true }).click();
    const canvas = page.getByTestId("security-graph-investigation");
    await expect(canvas.locator(".react-flow__node")).toHaveCount(10);
    await expect.poll(() => canvas.locator('.react-flow__node[data-id="agent:desktop"]').evaluate(element => {
      const width = element.getBoundingClientRect().width;
      const label = element.querySelector("p")!;
      const zoom = new DOMMatrixReadOnly(getComputedStyle(element.closest(".react-flow")!.querySelector(".react-flow__viewport")!).transform).a;
      return width >= 180 && parseFloat(getComputedStyle(label).fontSize) * zoom >= 12 && element.getBoundingClientRect().top >= 0 && element.getBoundingClientRect().bottom <= innerHeight;
    })).toBe(true);
    await expect(canvas.getByText("Focused view · 1 of 10")).toBeVisible();
    await expect.poll(() => canvas.evaluate(element => element.getBoundingClientRect().top)).toBeLessThan(250);
    await page.screenshot({ path: testInfo.outputPath(`mobile-readable-initial-${theme}.png`), fullPage: false });
    await expect(canvas.getByRole("button", { name: "Previous graph node" })).toBeDisabled();
    for (let step = 2; step <= 10; step++) {
      await canvas.getByRole("button", { name: "Next graph node" }).click();
      await expect(canvas.getByText(`Focused view · ${step} of 10`)).toBeVisible();
      const expectedId = step === 10 ? "cve:form-data" : step === 9 ? "pkg:form-data" : `server:hop-${step - 2}`;
      await expect.poll(() => canvas.locator(`.react-flow__node[data-id="${expectedId}"]`).evaluate(element => {
        const box = element.getBoundingClientRect();
        return box.width >= 180 && box.left >= 0 && box.right <= innerWidth && box.top >= 0 && box.bottom <= innerHeight;
      })).toBe(true);
    }
    await expect(canvas.getByRole("button", { name: "Next graph node" })).toBeDisabled();
    const last = canvas.locator('.react-flow__node[data-id="cve:form-data"]');
    await expect.poll(() => last.evaluate(element => {
      const box = element.getBoundingClientRect();
      const frame = element.closest(".react-flow")!.getBoundingClientRect();
      return box.width >= 180 && box.left >= frame.left && box.right <= frame.right && box.top >= frame.top && box.bottom <= frame.bottom;
    })).toBe(true);
    await canvas.getByLabel("Graph options", { exact: true }).click();
    await canvas.getByRole("button", { name: "Fit visible graph", exact: true }).click();
    await expect(canvas.getByText("Overview · 10 nodes")).toBeVisible();
    await canvas.getByLabel("Graph options", { exact: true }).click();
    await canvas.getByRole("button", { name: "Previous graph node" }).click();
    await expect(canvas.getByText("Focused view · 9 of 10")).toBeVisible();
    await expect.poll(() => canvas.locator('.react-flow__node[data-id="pkg:form-data"]').evaluate(element => {
      const box = element.getBoundingClientRect();
      const frame = element.closest(".react-flow")!.getBoundingClientRect();
      return box.width >= 180 && box.left >= frame.left && box.right <= frame.right;
    })).toBe(true);
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await canvas.screenshot({ path: testInfo.outputPath(`mobile-readable-graph-${theme}.png`) });
  });
}

for (const proof of [{ theme: "light", width: 1440 }, { theme: "dark", width: 1440 }, { theme: "dark", width: 390 }]) {
  test(`agent investigation questions retain honest scope ${proof.theme} ${proof.width}`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width: proof.width, height: 1000 });
    await page.addInitScript(value => localStorage.setItem("agent-bom-theme", value), proof.theme);
    await routeCockpit(page, undefined, { qualifiedEvidence: true });
    await page.route("**/v1/runtime/trace-explorer?**", route => route.fulfill({ json: { sessions: [], session_count: 0, blocked_count: 0 } }));
    await page.goto(`/security-graph?lens=attack-path&scan=${scanId}&agent=claude-desktop`);
    const questions = page.getByRole("region", { name: "Agent investigation questions", exact: true });
    await expect(questions).toBeVisible();
    await questions.getByText("Investigate this path", { exact: true }).click();
    await questions.getByRole("button", { name: "CVE conditions" }).click();
    await expect(questions).toContainText("Local exploitability: not assessed");
    await expect(questions.getByText("Not recorded", { exact: true })).toHaveCount(4);
    await questions.scrollIntoViewIfNeeded();
    await page.screenshot({ path: testInfo.outputPath(`agent-investigation-${proof.theme}-${proof.width}.png`) });
    await questions.getByRole("button", { name: "Assume compromise" }).click();
    await questions.getByRole("checkbox").check();
    await expect(questions).toContainText("Scenario assumption only");
    await questions.getByRole("button", { name: "Potential impact" }).click();
    await expect(questions).toContainText("No downstream data asset");
    await questions.getByRole("button", { name: "Recorded activity" }).click();
    await questions.getByRole("link", { name: "Recorded activity for claude-desktop" }).click();
    await expect(page).toHaveURL(new RegExp(`agent=claude-desktop&scan=${scanId}`));
    await expect(page.getByText(/No activity matched this agent/)).toBeVisible();
    await expect(page.getByText(/not.*scan|scan.*not/i).first()).toBeVisible();
  });
}

for (const theme of ["light", "dark"] as const) {
  for (const width of [390, 1440]) {
    test(`environment scope filters and evidence remain readable ${theme} ${width}`, async ({ page }, testInfo) => {
      await page.setViewportSize({ width, height: 900 });
      await page.addInitScript((value) => localStorage.setItem("agent-bom-theme", value), theme);
      await routeCockpit(page, 200, { rollupItemCount: 30 });
      await page.goto(`/graph?scan=${scanId}&rollup=1`);
      const surface = page.getByTestId("graph-rollup-decision-surface");
      await expect(surface).toBeVisible();
      await surface.getByText("Filter nodes and scopes", { exact: true }).click();
      await surface.getByRole("button", { name: "All 30", exact: true }).click();
      await surface.getByLabel("Search this scope").fill("production");
      await expect(surface.locator("article")).toHaveCount(1);
      await surface.getByText("Recorded relationships (1 row)", { exact: true }).click();
      await expect(surface.getByText(/do not establish runtime execution/)).toBeVisible();
      expect(await surface.evaluate((element) => element.scrollWidth <= element.clientWidth + 1)).toBe(true);
      await page.screenshot({ path: testInfo.outputPath(`environment-focus-${theme}-${width}.png`), fullPage: true });
    });
  }
}

test("environment scope filtering stays bounded with 3000 returned scopes", async ({ page }, testInfo) => {
  await routeCockpit(page, 3000, { rollupItemCount: 3000 });
  await page.goto(`/graph?scan=${scanId}&rollup=1`);
  const surface = page.getByTestId("graph-rollup-decision-surface");
  await expect(surface).toBeVisible();
  await surface.getByRole("button", { name: "All 3000", exact: true }).click();
  await expect(surface.locator("article")).toHaveCount(12);
  await surface.getByText("Filter nodes and scopes", { exact: true }).click();
  const durations: number[] = [];
  for (let index = 0; index < 10; index += 1) {
    const start = performance.now();
    await surface.getByLabel("Search this scope").fill(index % 2 ? "production" : "development");
    await expect(surface.locator("article")).toHaveCount(1);
    durations.push(performance.now() - start);
  }
  console.info("Scope filter fixture max milliseconds:", Math.max(...durations).toFixed(1));
  await testInfo.attach("filter-timing-fixture", { body: JSON.stringify({ scopes: 3000, samples_ms: durations, max_ms: Math.max(...durations), note: "Local browser automation with mocked API; excludes production backend latency." }), contentType: "application/json" });
});
