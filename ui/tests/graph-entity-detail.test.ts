import { describe, expect, it } from "vitest";

import type { LineageNodeData } from "@/components/lineage-nodes";
import {
  evidenceTierLabel,
  mergeGraphNodeDetail,
  resolveInvestigationNextAction,
  semanticLayerForNodeType,
} from "@/lib/graph-entity-detail";
import type { GraphNodeDetailResponse } from "@/lib/api-types";

function baseNode(overrides: Partial<LineageNodeData> = {}): LineageNodeData {
  return {
    label: "CVE-2024-1234",
    nodeType: "vulnerability",
    attributes: { node_id: "vuln::cve-2024-1234" },
    ...overrides,
  };
}

describe("graph-entity-detail", () => {
  it("maps node types to semantic layers", () => {
    expect(semanticLayerForNodeType("agent").key).toBe("orchestration");
    expect(semanticLayerForNodeType("server").key).toBe("mcp_server");
    expect(semanticLayerForNodeType("vulnerability").key).toBe("finding");
  });

  it("merges API node detail into lineage drawer fields", () => {
    const detail = {
      node: {
        id: "vuln::cve-2024-1234",
        entity_type: "vulnerability",
        label: "CVE-2024-1234",
        status: "open",
        severity: "critical",
        risk_score: 9.1,
        first_seen: "2026-01-01T00:00:00Z",
        last_seen: "2026-01-02T00:00:00Z",
        data_sources: ["scan"],
        compliance_tags: [],
        attributes: { evidence_tier: "static_scan" },
      },
      edges_out: [{ id: "e1" }],
      edges_in: [{ id: "e2" }, { id: "e3" }],
      neighbors: ["a", "b"],
      sources: ["scan"],
      impact: {
        node_id: "vuln::cve-2024-1234",
        affected_nodes: ["a", "b", "c"],
        affected_by_type: { agent: 1 },
        affected_count: 3,
        max_depth_reached: 2,
      },
    } as unknown as GraphNodeDetailResponse;

    const merged = mergeGraphNodeDetail(baseNode(), detail);
    expect(merged.incomingEdgeCount).toBe(2);
    expect(merged.outgoingEdgeCount).toBe(1);
    expect(merged.neighborCount).toBe(2);
    expect(merged.impactCount).toBe(3);
    expect(merged.attributes?.node_id).toBe("vuln::cve-2024-1234");
    expect(evidenceTierLabel(merged)).toBe("static scan");
  });

  it("resolves next actions for findings and packages", () => {
    expect(resolveInvestigationNextAction(baseNode(), { scanId: "scan-1" }).href).toContain(
      "/vulnerabilities",
    );
    expect(
      resolveInvestigationNextAction(baseNode({ nodeType: "package", label: "lodash" }), {
        scanId: "scan-1",
      }).label,
    ).toMatch(/package/i);
    expect(
      resolveInvestigationNextAction(baseNode({ nodeType: "agent", label: "cursor" }), {
        remediationHref: "/remediation?id=1",
      }).href,
    ).toBe("/remediation?id=1");
  });
});
