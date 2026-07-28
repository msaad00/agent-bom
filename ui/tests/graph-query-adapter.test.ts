import { describe, expect, it } from "vitest";

import {
  knownGraphTotal,
  queryResponseToGraphResponse,
} from "@/app/graph/graph-page-client";
import type { GraphQueryResponse } from "@/lib/api-types";

describe("graph query response adapter", () => {
  it("preserves traversal completeness without inventing an exhaustive total", () => {
    const response: GraphQueryResponse = {
      scan_id: "scan-query",
      tenant_id: "default",
      created_at: "2026-07-28T00:00:00Z",
      nodes: [],
      edges: [],
      attack_paths: [],
      interaction_risks: [],
      stats: {
        total_nodes: 0,
        total_edges: 0,
        node_types: {},
        severity_counts: {},
        relationship_types: {},
        attack_path_count: 0,
        interaction_risk_count: 0,
        max_attack_path_risk: 0,
        highest_interaction_risk: 0,
      },
      roots: ["agent:root"],
      direction: "both",
      max_depth: 2,
      max_nodes: 2,
      max_edges: 10,
      timeout_ms: 2500,
      budget: { max_nodes: 2 },
      truncated: true,
      missing_roots: [],
      depth_by_node: {},
      filters: {},
      completeness: {
        status: "truncated",
        complete: false,
        sampled: false,
        truncated: true,
        returned: 2,
        reason: "traversal_budget",
      },
    };

    const adapted = queryResponseToGraphResponse(response);

    expect(adapted.completeness).toEqual(response.completeness);
    expect(adapted.completeness?.total).toBeUndefined();
    expect(adapted.pagination.has_more).toBe(true);
    expect(knownGraphTotal(adapted)).toBeNull();
  });
});
