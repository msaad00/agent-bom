import { describe, expect, it } from "vitest";

import {
  EVIDENCE_BASES,
  EVIDENCE_STATUSES,
  EXPLOITABILITY_VERDICTS,
  FRESHNESS_STATUSES,
  REACHABILITY_VERDICTS,
} from "@/lib/evidence-semantics";

describe("canonical evidence semantics", () => {
  it("keeps orthogonal vocabularies explicit and closed", () => {
    expect(EVIDENCE_BASES).toEqual(["observed", "runtime_observed", "inferred", "modeled"]);
    expect(EVIDENCE_STATUSES).toEqual(["complete", "partial", "unavailable", "failed"]);
    expect(FRESHNESS_STATUSES).toEqual(["fresh", "stale", "unknown"]);
    expect(REACHABILITY_VERDICTS).toEqual(["confirmed", "likely", "unknown", "unlikely"]);
    expect(EXPLOITABILITY_VERDICTS).toEqual(["exploitable", "not_exploitable", "unknown"]);
  });
});
