import { describe, expect, it } from "vitest";
import type { ScanResult } from "@/lib/api";
import { domainFindingsForScan } from "@/lib/scan-domain-findings";

function result(secrets?: Record<string, unknown>): ScanResult {
  return { ai_inventory: secrets ? { secrets } : {} } as ScanResult;
}

describe("secret and PII scanner evidence", () => {
  it("counts PII-only repository findings without calling them credentials", () => {
    const view = domainFindingsForScan({ result: result({ total: 2, complete: true, by_category: { pii: 2 } }) });
    expect(view.lanes.secrets.ran).toBe(true);
    expect(view.lanes.secrets.findings).toBe(2);
    expect(view.lanes.secrets.detail).toBe("2 PII");
    expect(view.reconciled.total).toBe(2);
  });
  it("distinguishes a completed zero-result scan from an absent scan", () => {
    expect(domainFindingsForScan({ result: result({ total: 0, complete: true }) }).lanes.secrets.detail).toBe("0 findings");
    expect(domainFindingsForScan({ result: result() }).lanes.secrets.ran).toBe(false);
  });
  it("does not call incomplete zero-result evidence clean", () => {
    const lane = domainFindingsForScan({ result: result({ total: 0, complete: false, warnings: ["file limit"] }) }).lanes.secrets;
    expect(lane.ran).toBe(true);
    expect(lane.detail).toBe("incomplete · 0 findings");
  });
  it("keeps mixed categories and their total", () => {
    const view = domainFindingsForScan({ result: result({ total: 4, complete: true, by_category: { credential: 1, secret: 1, pii: 2 } }) });
    expect(view.lanes.secrets.detail).toBe("2 secrets · 2 PII");
    expect(view.reconciled.total).toBe(4);
  });
  it("does not infer a completed scan from legacy findings alone", () => {
    const lane = domainFindingsForScan({ result: result({ total: 1 }) }).lanes.secrets;
    expect(lane.detail).toBe("coverage unknown · 1 finding");
  });
});

it("keeps discovery-time secret evidence visible when CVE scanning was skipped", async () => {
  const { buildPipelineGraph } = await import("@/lib/scan-pipeline-graph");
  const { lanes } = domainFindingsForScan({ result: result({ total: 2, complete: true, by_category: { pii: 2 } }) });
  const graph = buildPipelineGraph({
    lanes,
    steps: new Map([["scanning", { type: "step", step_id: "scanning", status: "skipped", message: "Skipped by request" }]]),
  });
  expect(graph.nodes.find((node) => node.id === "secrets")?.data.status).toBe("done");
});
