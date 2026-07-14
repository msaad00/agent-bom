import { describe, expect, it } from "vitest";

import type { StepEvent } from "@/lib/api";
import {
  PIPELINE_GRAPH,
  SCANNER_DOMAINS,
  backendStepForNode,
  buildPipelineGraph,
  cisFailedCount,
  deriveDomainLanes,
  laneStatus,
  reconcileFindings,
} from "@/lib/scan-pipeline-graph";

function step(partial: Partial<StepEvent> & { step_id: string; status: StepEvent["status"] }): StepEvent {
  return { type: "step", message: "", ...partial };
}

function stepsMap(events: StepEvent[]): Map<string, StepEvent> {
  return new Map(events.map((e) => [e.step_id, e]));
}

describe("scan-pipeline-graph topology", () => {
  it("fans extraction out to five scanner lanes that converge into enrichment", () => {
    const scannerIds = PIPELINE_GRAPH.filter((n) => n.kind === "scanner").map((n) => n.id);
    expect(scannerIds).toEqual([...SCANNER_DOMAINS]);

    for (const id of scannerIds) {
      const node = PIPELINE_GRAPH.find((n) => n.id === id)!;
      expect(node.dependsOn).toEqual(["extraction"]);
      expect(backendStepForNode(id)).toBe("scanning");
    }

    const enrichment = PIPELINE_GRAPH.find((n) => n.id === "enrichment")!;
    expect(enrichment.dependsOn).toEqual([...SCANNER_DOMAINS]);
  });

  it("builds a branching (not linear) edge set", () => {
    const { nodes, edges } = buildPipelineGraph({ steps: new Map() });
    expect(nodes).toHaveLength(PIPELINE_GRAPH.length);

    // extraction fans out to all five lanes
    const fanOut = edges.filter((e) => e.source === "extraction");
    expect(fanOut.map((e) => e.target).sort()).toEqual([...SCANNER_DOMAINS].sort());

    // all five lanes fan in to enrichment
    const fanIn = edges.filter((e) => e.target === "enrichment");
    expect(fanIn.map((e) => e.source).sort()).toEqual([...SCANNER_DOMAINS].sort());

    // it is genuinely a fork: more than one node shares extraction as a source
    expect(fanOut.length).toBeGreaterThan(1);
  });

  it("carries backend stepId + node id so scanner lanes drill into scanning", () => {
    const { nodes } = buildPipelineGraph({ steps: new Map() });
    const sca = nodes.find((n) => n.id === "sca")!;
    expect(sca.data.stepId).toBe("scanning");
    expect(sca.data.kind).toBe("scanner");
    expect(sca.data.domain).toBe("sca");
  });
});

describe("scan-pipeline-graph lane status", () => {
  it("collapses lanes with no domain data to skipped once scanning is terminal", () => {
    expect(laneStatus("done", false)).toBe("skipped");
    expect(laneStatus("done", true)).toBe("done");
    expect(laneStatus("running", false)).toBe("running");
    expect(laneStatus("pending", false)).toBe("pending");
  });

  it("marks scanner nodes without data as skipped after a completed scan", () => {
    const steps = stepsMap([
      step({ step_id: "scanning", status: "done", message: "Found 3 vulnerabilities" }),
    ]);
    const lanes = deriveDomainLanes({ vulnerabilities: 3 });
    const { nodes } = buildPipelineGraph({ steps, lanes });
    const byId = new Map(nodes.map((n) => [n.id, n.data.status]));
    expect(byId.get("sca")).toBe("done");
    expect(byId.get("secrets")).toBe("skipped");
    expect(byId.get("cis")).toBe("skipped");
  });
});

describe("scan-pipeline-graph honesty reconciliation", () => {
  it("counts CIS failures as findings (0 vulns / 32% pass is 68 findings, not 0)", () => {
    const cis = { passed: 32, failed: null, total: 100, passRate: 0.32 };
    expect(cisFailedCount(cis)).toBe(68);

    const lanes = deriveDomainLanes({ vulnerabilities: 0, cis });
    const reconciled = reconcileFindings(lanes);
    expect(reconciled.total).toBe(68);
    expect(reconciled.byDomain.sca).toBe(0);
    expect(reconciled.byDomain.cis).toBe(68);
    expect(lanes.cis.detail).toBe("68 fail · 100 checks");
  });

  it("derives CIS failures from an explicit failed count or a pass rate", () => {
    expect(cisFailedCount({ passed: null, failed: 12, total: 50, passRate: null })).toBe(12);
    expect(cisFailedCount({ passed: null, failed: null, total: 200, passRate: 90 })).toBe(20);
    expect(cisFailedCount(null)).toBeNull();
  });

  it("leaves untouched domains out of the total and marks them not-run", () => {
    const lanes = deriveDomainLanes({ vulnerabilities: 5 });
    const reconciled = reconcileFindings(lanes);
    expect(reconciled.total).toBe(5);
    expect(reconciled.domainsRun).toBe(1);
    expect(reconciled.byDomain.secrets).toBeNull();
    expect(lanes.secrets.ran).toBe(false);
    expect(lanes.sca.detail).toBe("5 CVEs");
  });

  it("labels a clean scanned domain as clean, not absent", () => {
    const lanes = deriveDomainLanes({ vulnerabilities: 0 });
    expect(lanes.sca.ran).toBe(true);
    expect(lanes.sca.findings).toBe(0);
    expect(lanes.sca.detail).toBe("clean");
  });
});
