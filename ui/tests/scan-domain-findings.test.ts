import { describe, expect, it } from "vitest";
import type { ScanResult } from "@/lib/api";
import { cisSummaryFromResult, domainFindingsForScan } from "@/lib/scan-domain-findings";

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


describe("CIS benchmark evidence", () => {
  it("keeps a reported one percent pass rate at one percent", () => {
    expect(cisSummaryFromResult({ cis_benchmark: { pass_rate: 1 } } as ScanResult)?.passRate).toBe(1);
  });
  it("does not omit a benchmark with unknown counts from aggregate results", () => {
    const scan = { cis_benchmark: { passed: 10, failed: 0, total: 10 }, azure_cis_benchmark: { pass_rate: 20 } } as ScanResult;
    expect(cisSummaryFromResult(scan)?.failed).toBeNull();
    expect(cisSummaryFromResult(scan)?.passRate).toBeNull();
  });
  it("does not use one provider's rate as a multi-provider aggregate", () => {
    const scan = { cis_benchmark: { pass_rate: 20 }, azure_cis_benchmark: { pass_rate: 80 } } as ScanResult;
    expect(cisSummaryFromResult(scan)?.passRate).toBeNull();
  });
  it("keeps errors and inapplicable checks out of the failed count", () => {
    const scan = { cis_benchmark: { passed: 2, failed: 1, errored: 3, not_applicable: 4, total: 10 } } as ScanResult;
    expect(cisSummaryFromResult(scan)?.failed).toBe(1);
    expect(cisSummaryFromResult(scan)?.passRate).toBeCloseTo(200 / 3);
    expect(domainFindingsForScan({ result: scan }).lanes.cis.findings).toBe(1);
  });
  it("does not turn missing failure counts into zero or total minus passed", () => {
    const summary = cisSummaryFromResult({ cis_benchmark: { passed: 2, total: 10 } } as ScanResult);
    expect(summary?.failed).toBeNull();
    expect(summary?.passRate).toBeNull();
  });
  it("treats a check error as unavailable assessment, not a failed control", () => {
    const scan = { cis_benchmark: { checks: [{ status: "pass" }, { status: "error" }, { status: "not_applicable" }, { status: "fail" }] } } as ScanResult;
    expect(cisSummaryFromResult(scan)?.failed).toBe(1);
  });
});

it("shows recorded cloud inventory without claiming an exposure assessment", () => {
  const scan = { cloud_inventory: { resource_count: 12, identity_count: 3 } } as ScanResult;
  const view = domainFindingsForScan({ result: scan });
  expect(view.lanes.cloud.ran).toBe(true);
  expect(view.lanes.cloud.findings).toBeNull();
  expect(view.lanes.cloud.detail).toBe("12 resources · 3 identities");
  expect(view.reconciled.byDomain.cloud).toBeNull();
});
