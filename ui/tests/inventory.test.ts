import { describe, expect, it } from "vitest";

import type { UnifiedGraphResponse } from "@/lib/api";
import {
  ASSET_KINDS,
  assetKindForEntityType,
  buildInventory,
  dataSourceOptions,
  filterAssetRows,
  sortAssetRows,
  summarizeRows,
  type AssetRow,
} from "@/lib/inventory";

function node(
  id: string,
  entityType: string,
  overrides: Partial<UnifiedGraphResponse["nodes"][number]> = {},
): UnifiedGraphResponse["nodes"][number] {
  return {
    id,
    entity_type: entityType,
    label: id,
    category_uid: 0,
    class_uid: 0,
    type_uid: 0,
    status: "active",
    risk_score: 0,
    severity: "none",
    severity_id: 0,
    first_seen: "2026-07-01T00:00:00Z",
    last_seen: "2026-07-10T00:00:00Z",
    attributes: {},
    compliance_tags: [],
    data_sources: [],
    dimensions: {},
    ...overrides,
  } as UnifiedGraphResponse["nodes"][number];
}

function edge(source: string, target: string): UnifiedGraphResponse["edges"][number] {
  return {
    id: `${source}->${target}`,
    source,
    target,
    relationship: "vulnerable_to",
    direction: "directed",
    weight: 1,
    traversable: true,
    first_seen: "2026-07-01T00:00:00Z",
    last_seen: "2026-07-10T00:00:00Z",
    evidence: {},
    activity_id: 0,
  } as UnifiedGraphResponse["edges"][number];
}

function graph(
  nodes: UnifiedGraphResponse["nodes"],
  edges: UnifiedGraphResponse["edges"],
  nodeTypes: Record<string, number> = {},
): UnifiedGraphResponse {
  return {
    scan_id: "scan-1",
    tenant_id: "t1",
    created_at: "2026-07-10T00:00:00Z",
    nodes,
    edges,
    attack_paths: [],
    interaction_risks: [],
    stats: {
      total_nodes: nodes.length,
      total_edges: edges.length,
      node_types: nodeTypes,
      severity_counts: {},
      relationship_types: {},
      attack_path_count: 0,
      interaction_risk_count: 0,
      max_attack_path_risk: 0,
      highest_interaction_risk: 0,
    },
    pagination: { total: nodes.length, offset: 0, limit: 500, has_more: false },
  } as unknown as UnifiedGraphResponse;
}

describe("assetKindForEntityType", () => {
  it("maps canonical entity types to asset kinds", () => {
    expect(assetKindForEntityType("package")).toBe("packages");
    expect(assetKindForEntityType("server")).toBe("servers");
    expect(assetKindForEntityType("agent")).toBe("agents");
    expect(assetKindForEntityType("cloud_resource")).toBe("cloud");
    expect(assetKindForEntityType("data_store")).toBe("cloud");
    expect(assetKindForEntityType("credential")).toBe("identities");
    expect(assetKindForEntityType("service_account")).toBe("identities");
    expect(assetKindForEntityType("container")).toBe("containers");
    expect(assetKindForEntityType("source_file")).toBe("code");
  });

  it("is case-insensitive and returns null for findings + unknowns", () => {
    expect(assetKindForEntityType("PACKAGE")).toBe("packages");
    expect(assetKindForEntityType("vulnerability")).toBeNull();
    expect(assetKindForEntityType("misconfiguration")).toBeNull();
    expect(assetKindForEntityType("nonsense")).toBeNull();
    expect(assetKindForEntityType(undefined)).toBeNull();
  });

  it("covers every entity type declared in ASSET_KINDS", () => {
    for (const kind of ASSET_KINDS) {
      for (const entityType of kind.entityTypes) {
        expect(assetKindForEntityType(entityType)).toBe(kind.id);
      }
    }
  });
});

describe("buildInventory", () => {
  it("buckets nodes by kind and excludes finding nodes", () => {
    const model = buildInventory(
      graph(
        [
          node("pkg-1", "package"),
          node("srv-1", "server"),
          node("cve-1", "vulnerability", { severity: "critical" }),
        ],
        [],
      ),
    );
    expect(model.rowsByKind.packages).toHaveLength(1);
    expect(model.rowsByKind.servers).toHaveLength(1);
    // Findings are never listed as assets.
    const allRows = Object.values(model.rowsByKind).flat();
    expect(allRows.some((r) => r.entityType === "vulnerability")).toBe(false);
  });

  it("correlates direct finding neighbors and rolls up severity", () => {
    const model = buildInventory(
      graph(
        [
          node("pkg-1", "package", { severity: "high" }),
          node("cve-1", "vulnerability", { severity: "critical" }),
          node("cve-2", "vulnerability", { severity: "medium" }),
          node("misc-1", "misconfiguration", { severity: "high" }),
        ],
        [
          edge("cve-1", "pkg-1"),
          edge("pkg-1", "cve-2"), // direction should not matter
          edge("misc-1", "pkg-1"),
        ],
      ),
    );
    const pkg = model.rowsByKind.packages[0]!;
    expect(pkg.findingCount).toBe(3);
    expect(pkg.criticalCount).toBe(1);
    expect(pkg.highCount).toBe(1);
    expect(pkg.topFindingSeverity).toBe("critical");
    expect(pkg.severity).toBe("high"); // node's own posture, not the finding
    expect(pkg.findingIds).toHaveLength(3);
  });

  it("does not double-count duplicate finding edges", () => {
    const model = buildInventory(
      graph(
        [node("pkg-1", "package"), node("cve-1", "vulnerability", { severity: "high" })],
        [edge("cve-1", "pkg-1"), edge("pkg-1", "cve-1")],
      ),
    );
    expect(model.rowsByKind.packages[0]!.findingCount).toBe(1);
  });

  it("ignores edges between two assets or two findings", () => {
    const model = buildInventory(
      graph(
        [node("agent-1", "agent"), node("srv-1", "server")],
        [edge("agent-1", "srv-1")],
      ),
    );
    expect(model.rowsByKind.agents[0]!.findingCount).toBe(0);
    expect(model.rowsByKind.servers[0]!.findingCount).toBe(0);
  });

  it("uses graph stats for true totals but never under-reports loaded rows", () => {
    const model = buildInventory(
      graph([node("pkg-1", "package"), node("pkg-2", "package")], [], {
        package: 500,
        server: 3,
      }),
    );
    expect(model.totalsByKind.packages).toBe(500);
    expect(model.loadedByKind.packages).toBe(2);
    // No server nodes loaded, but stats claim 3 — total reflects stats.
    expect(model.totalsByKind.servers).toBe(3);
    expect(model.loadedByKind.servers).toBe(0);
  });

  it("pulls ecosystem/provider from dimensions and attributes", () => {
    const model = buildInventory(
      graph(
        [
          node("pkg-1", "package", { dimensions: { ecosystem: "pypi" }, attributes: { version: "1.2.3" } }),
          node("res-1", "cloud_resource", { dimensions: { cloud_provider: "aws" } }),
        ],
        [],
      ),
    );
    expect(model.rowsByKind.packages[0]!.ecosystem).toBe("pypi");
    expect(model.rowsByKind.packages[0]!.version).toBe("1.2.3");
    expect(model.rowsByKind.cloud[0]!.provider).toBe("aws");
  });
});

describe("filterAssetRows / sort / summary", () => {
  const rows: AssetRow[] = [
    baseRow({ id: "a", label: "requests", severity: "critical", severityRank: 4, findingCount: 3, criticalCount: 2, dataSources: ["sbom"] }),
    baseRow({ id: "b", label: "flask", severity: "low", severityRank: 1, findingCount: 0, dataSources: ["image-scan"] }),
    baseRow({ id: "c", label: "boto3", severity: "high", severityRank: 3, findingCount: 1, highCount: 1, dataSources: ["sbom"] }),
  ];

  it("filters by query across label and data source", () => {
    expect(filterAssetRows(rows, { query: "requ" }).map((r) => r.id)).toEqual(["a"]);
    expect(filterAssetRows(rows, { query: "image-scan" }).map((r) => r.id)).toEqual(["b"]);
  });

  it("filters by minimum severity", () => {
    expect(filterAssetRows(rows, { severity: "high" }).map((r) => r.id).sort()).toEqual(["a", "c"]);
  });

  it("filters by data source and findings-only", () => {
    expect(filterAssetRows(rows, { dataSource: "sbom" }).map((r) => r.id).sort()).toEqual(["a", "c"]);
    expect(filterAssetRows(rows, { withFindingsOnly: true }).map((r) => r.id).sort()).toEqual(["a", "c"]);
  });

  it("sorts by severity and findings", () => {
    expect(sortAssetRows(rows, "severity", "desc").map((r) => r.id)).toEqual(["a", "c", "b"]);
    expect(sortAssetRows(rows, "findings", "desc")[0]!.id).toBe("a");
    expect(sortAssetRows(rows, "label", "asc").map((r) => r.id)).toEqual(["c", "b", "a"]);
  });

  it("lists distinct data sources sorted", () => {
    expect(dataSourceOptions(rows)).toEqual(["image-scan", "sbom"]);
  });

  it("summarizes KPI numbers", () => {
    const summary = summarizeRows(rows);
    expect(summary.criticalAssets).toBe(1);
    expect(summary.highAssets).toBe(1);
    expect(summary.withFindings).toBe(2);
    expect(summary.totalFindings).toBe(4);
  });
});

function baseRow(overrides: Partial<AssetRow>): AssetRow {
  return {
    id: "x",
    kind: "packages",
    entityType: "package",
    label: "x",
    severity: "none",
    severityRank: 0,
    riskScore: 0,
    status: "active",
    ecosystem: undefined,
    provider: undefined,
    environment: undefined,
    version: undefined,
    dataSources: [],
    findingCount: 0,
    criticalCount: 0,
    highCount: 0,
    topFindingSeverity: "none",
    firstSeen: undefined,
    lastSeen: undefined,
    attributes: {},
    complianceTags: [],
    findingIds: [],
    ...overrides,
  };
}
