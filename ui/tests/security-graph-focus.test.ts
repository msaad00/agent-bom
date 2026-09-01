import { describe, expect, it } from "vitest";

import {
  buildFocusedGraphData,
  latestCompletedCorrelation,
  selectInitialGraphSnapshot,
} from "@/lib/security-graph-focus";
import type { GraphCorrelationRun, GraphSnapshot } from "@/lib/api-types";
import type { AttackPath, UnifiedGraphData } from "@/lib/graph-schema";

function graphFixture(): UnifiedGraphData {
  return {
    scan_id: "scan-1",
    tenant_id: "default",
    created_at: "2026-05-27T16:00:00Z",
    nodes: [
      {
        id: "agent:desktop",
        entity_type: "agent",
        label: "claude-desktop",
        category_uid: 0,
        class_uid: 0,
        type_uid: 0,
        status: "active",
        risk_score: 5,
        severity: "medium",
        severity_id: 2,
        first_seen: "2026-05-27T16:00:00Z",
        last_seen: "2026-05-27T16:00:00Z",
        attributes: {},
        compliance_tags: [],
        data_sources: ["scan"],
        dimensions: {},
      },
      {
        id: "server:github",
        entity_type: "server",
        label: "github",
        category_uid: 0,
        class_uid: 0,
        type_uid: 0,
        status: "active",
        risk_score: 4,
        severity: "low",
        severity_id: 1,
        first_seen: "2026-05-27T16:00:00Z",
        last_seen: "2026-05-27T16:00:00Z",
        attributes: {},
        compliance_tags: [],
        data_sources: ["scan"],
        dimensions: {},
      },
      {
        id: "pkg:form-data",
        entity_type: "package",
        label: "form-data@4.0.0",
        category_uid: 0,
        class_uid: 0,
        type_uid: 0,
        status: "active",
        risk_score: 9,
        severity: "critical",
        severity_id: 4,
        first_seen: "2026-05-27T16:00:00Z",
        last_seen: "2026-05-27T16:00:00Z",
        attributes: {},
        compliance_tags: [],
        data_sources: ["scan"],
        dimensions: {},
      },
      {
        id: "cve:form-data",
        entity_type: "vulnerability",
        label: "CVE-2025-7783",
        category_uid: 0,
        class_uid: 0,
        type_uid: 0,
        status: "active",
        risk_score: 9.8,
        severity: "critical",
        severity_id: 4,
        first_seen: "2026-05-27T16:00:00Z",
        last_seen: "2026-05-27T16:00:00Z",
        attributes: {},
        compliance_tags: [],
        data_sources: ["scan"],
        dimensions: {},
      },
    ],
    edges: [
      {
        id: "agent:desktop->server:github:uses",
        source: "agent:desktop",
        target: "server:github",
        relationship: "uses",
        direction: "directed",
        weight: 1,
        traversable: true,
        first_seen: "2026-05-27T16:00:00Z",
        last_seen: "2026-05-27T16:00:00Z",
        evidence: {},
        activity_id: 1,
      },
      {
        id: "server:github->pkg:form-data:depends_on",
        source: "server:github",
        target: "pkg:form-data",
        relationship: "depends_on",
        direction: "directed",
        weight: 1,
        traversable: true,
        first_seen: "2026-05-27T16:00:00Z",
        last_seen: "2026-05-27T16:00:00Z",
        evidence: {},
        activity_id: 1,
      },
      {
        id: "pkg:form-data->cve:form-data:vulnerable_to",
        source: "pkg:form-data",
        target: "cve:form-data",
        relationship: "vulnerable_to",
        direction: "directed",
        weight: 1,
        traversable: true,
        first_seen: "2026-05-27T16:00:00Z",
        last_seen: "2026-05-27T16:00:00Z",
        evidence: {},
        activity_id: 1,
      },
    ],
    attack_paths: [],
    interaction_risks: [],
    stats: {
      total_nodes: 4,
      total_edges: 3,
      node_types: {},
      severity_counts: {},
      relationship_types: {},
      attack_path_count: 0,
      interaction_risk_count: 0,
      max_attack_path_risk: 0,
      highest_interaction_risk: 0,
    },
  };
}

const attackPath: AttackPath = {
  source: "agent:desktop",
  target: "cve:form-data",
  hops: ["agent:desktop", "server:github", "pkg:form-data", "cve:form-data"],
  edges: [
    "agent:desktop->server:github:uses",
    "server:github->pkg:form-data:depends_on",
    "pkg:form-data->cve:form-data:vulnerable_to",
  ],
  composite_risk: 9.8,
  summary: "Reachable critical CVE",
  credential_exposure: [],
  tool_exposure: [],
  vuln_ids: ["CVE-2025-7783"],
};

describe("buildFocusedGraphData", () => {
  it("keeps only nodes and edges on the selected attack path", () => {
    const focused = buildFocusedGraphData(graphFixture(), attackPath);
    expect(focused?.nodes.map((node) => node.id)).toEqual(attackPath.hops);
    expect(focused?.edges).toHaveLength(3);
    expect(focused?.stats.total_nodes).toBe(4);
    expect(focused?.attack_paths).toEqual([attackPath]);
  });

  it("returns null when the path has no resolvable nodes", () => {
    expect(
      buildFocusedGraphData(graphFixture(), {
        ...attackPath,
        hops: ["missing:node"],
        edges: [],
      }),
    ).toBeNull();
  });
});

describe("initial Investigation snapshot", () => {
  const snapshots = [
    { scan_id: "newer-scan", node_count: 2, edge_count: 1 },
    { scan_id: "corr-output", node_count: 8, edge_count: 7, snapshot_kind: "correlation" },
  ] as GraphSnapshot[];
  const correlation = {
    correlation_id: "corr-output",
    output_scan_id: "corr-output",
    status: "complete",
  } as GraphCorrelationRun;

  it("prefers an explicit deep link over automatic correlation selection", () => {
    expect(selectInitialGraphSnapshot(snapshots, "newer-scan", correlation)).toBe("newer-scan");
  });

  it("selects the latest completed correlation output when no scan is requested", () => {
    expect(selectInitialGraphSnapshot(snapshots, "", correlation)).toBe("corr-output");
  });

  it("finds the latest completed correlation even when API items are unordered", () => {
    const latest = latestCompletedCorrelation([
      { ...correlation, correlation_id: "older", created_at: "2026-08-29T00:00:00Z" },
      { ...correlation, correlation_id: "newest", created_at: "2026-08-31T00:00:00Z" },
      { ...correlation, correlation_id: "middle", created_at: "2026-08-30T00:00:00Z" },
    ]);

    expect(latest?.correlation_id).toBe("newest");
  });

  it("falls back to the first retained snapshot when the output was removed", () => {
    expect(selectInitialGraphSnapshot(snapshots, "", { ...correlation, output_scan_id: "removed" })).toBe("newer-scan");
  });

  it("ignores pending and failed correlation runs", () => {
    expect(latestCompletedCorrelation([
      { ...correlation, status: "pending" },
      { ...correlation, status: "failed" },
    ])).toBeNull();
  });
});
