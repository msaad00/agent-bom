import { describe, expect, it } from "vitest";

import type { GraphScenarioComparisonResponse } from "@/lib/api-types";
import type { UnifiedGraphResponse } from "@/lib/api";
import { proposedGraphFromComparison } from "@/lib/graph-scenario";
import type { UnifiedNode } from "@/lib/graph-schema";

const node = (id: string): UnifiedNode => ({
  id,
  entity_type: "cloud_resource",
  label: id,
  category_uid: 0,
  class_uid: 0,
  type_uid: 0,
  status: "active",
  risk_score: 0,
  severity: "none",
  severity_id: 0,
  first_seen: "2026-08-25T00:00:00Z",
  last_seen: "2026-08-25T00:00:00Z",
  attributes: {},
  compliance_tags: [],
  data_sources: ["scan"],
  dimensions: {},
});

const observed: UnifiedGraphResponse = {
  scan_id: "scan-1",
  tenant_id: "tenant-1",
  created_at: "2026-08-25T00:00:00Z",
  nodes: [node("observed")],
  edges: [],
  attack_paths: [],
  interaction_risks: [],
  stats: {
    total_nodes: 1,
    total_edges: 0,
    node_types: { cloud_resource: 1 },
    severity_counts: { none: 1 },
    relationship_types: {},
    attack_path_count: 0,
    interaction_risk_count: 0,
    max_attack_path_risk: 0,
    highest_interaction_risk: 0,
    analysis_status: {},
  },
  pagination: { total: 1, offset: 0, limit: 1, has_more: false },
};

const comparison: GraphScenarioComparisonResponse = {
  schema: "graph.scenario-comparison.v1",
  scenario: {
    scenario_id: "scenario-1",
    tenant_id: "tenant-1",
    name: "Private service endpoint",
    description: "",
    base_scan_id: "scan-1",
    assumptions: [],
    changes: [],
    revision: 1,
    created_by: "analyst@example.com",
    created_at: "2026-08-25T00:00:00Z",
    updated_at: "2026-08-25T00:00:00Z",
  },
  current: { scan_id: "scan-1", node_count: 1, edge_count: 0 },
  proposed: {
    modeled: true,
    node_count: 2,
    edge_count: 0,
    nodes: [node("z-proposed"), node("a-observed")],
    edges: [],
  },
  difference: {
    nodes_added: ["z-proposed"],
    nodes_removed: [],
    nodes_changed: [],
    edges_added: [],
    edges_removed: [],
    touched_observed_path_count: 0,
    touched_observed_path_ids: [],
  },
  available: true,
};

describe("proposedGraphFromComparison", () => {
  it("uses the full server-authored overlay deterministically without mutating observed truth", () => {
    const result = proposedGraphFromComparison(observed, comparison);

    expect(result?.nodes.map((item) => item.id)).toEqual([
      "a-observed",
      "z-proposed",
    ]);
    expect(result?.stats.total_nodes).toBe(2);
    expect(observed.nodes.map((item) => item.id)).toEqual(["observed"]);
    expect(comparison.proposed.nodes.map((item) => item.id)).toEqual([
      "z-proposed",
      "a-observed",
    ]);
  });

  it("refuses to invent a modeled graph when comparison is unavailable", () => {
    expect(
      proposedGraphFromComparison(observed, {
        ...comparison,
        available: false,
        unavailable_reason: "base snapshot mismatch",
      }),
    ).toBeNull();
  });
});
