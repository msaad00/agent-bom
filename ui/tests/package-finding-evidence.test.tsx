import { render, screen, cleanup } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { LineageDetailPanel } from "@/components/lineage-detail";
import { mergeGraphNodeDetail } from "@/lib/graph-entity-detail";
import type { GraphNodeDetailResponse } from "@/lib/api-types";
import type { LineageNodeData } from "@/components/lineage-nodes";

const base: LineageNodeData = { label: "pyyaml@5.3", nodeType: "package", attributes: { node_id: "package:pypi:pyyaml@5.3" } };
const id = String(base.attributes?.node_id);
function context(withFinding = true): GraphNodeDetailResponse {
  return {
    node: { id, entity_type: "package", risk_score: 0, attributes: {} },
    edges_out: withFinding ? [{ source: id, target: "vuln:CVE-2020-14343", relationship: "vulnerable_to" }] : [],
    edges_in: withFinding ? [{ source: "vuln:CVE-2020-14343", target: id, relationship: "affects" }] : [],
    neighbors: withFinding ? ["vuln:CVE-2020-14343"] : [], sources: [],
    impact: { affected_count: 0, affected_by_type: {}, max_depth_reached: 0 },
  } as unknown as GraphNodeDetailResponse;
}
afterEach(cleanup);
describe("package finding evidence after summary traversal", () => {
  it("counts distinct linked findings despite reciprocal edges and stale zero counts", () => {
    const merged = mergeGraphNodeDetail({ ...base, vulnCount: 0 }, context());
    expect(merged.vulnCount).toBe(1);
    render(<LineageDetailPanel data={merged} onClose={() => {}} />);
    expect(screen.getByText("Findings")).toBeInTheDocument();
    expect(screen.queryByText(/No known findings/)).not.toBeInTheDocument();
    expect(screen.getByText("Node risk score")).toBeInTheDocument();
  });
  it("does not treat unavailable evidence as zero findings", () => {
    render(<LineageDetailPanel data={base} onClose={() => {}} />);
    expect(screen.getByText("Finding count unavailable")).toBeInTheDocument();
    expect(screen.queryByText(/No known findings/)).not.toBeInTheDocument();
  });
  it("scopes an empty graph context to recorded relationships", () => {
    render(<LineageDetailPanel data={mergeGraphNodeDetail(base, context(false))} onClose={() => {}} />);
    expect(screen.getByText("No findings linked in this snapshot")).toBeInTheDocument();
  });
});
