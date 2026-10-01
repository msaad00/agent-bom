import { describe, expect, it } from "vitest";
import { selectAttackPathQueue } from "@/lib/attack-path-queue";
import type { AttackPath } from "@/lib/graph-schema";

const path = (source: string, risk: number): AttackPath => ({
  source, target: "data", hops: [source, "data"], edges: ["can_access"],
  composite_risk: risk, summary: "", credential_exposure: [], tool_exposure: [], vuln_ids: [],
});

describe("canonical investigation queue", () => {
  it("preserves evidence-first server order despite higher-risk enrichment cards", () => {
    const witnessed = path("witnessed", 30), conditional = path("conditional", 95), extra = path("other", 99);
    expect(selectAttackPathQueue([witnessed, conditional], [extra, conditional], new Map(), {})).toEqual([witnessed, conditional]);
  });
  it("does not refill an authoritative empty page with out-of-scope cards", () => {
    expect(selectAttackPathQueue([], [path("other", 99)], new Map(), {})).toEqual([]);
  });
  it("keeps campaign filtering in the same authoritative order", () => {
    const first = path("first", 30), second = path("second", 95);
    expect(selectAttackPathQueue([first, second], [], new Map(), {}, ["second->data", "first->data"])).toEqual([first, second]);
  });
});
