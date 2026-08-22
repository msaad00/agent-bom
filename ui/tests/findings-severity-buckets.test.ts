import { describe, expect, it } from "vitest";

import type { FindingFacets } from "@/lib/api-types";
import { SEVERITY_FILTER_KEYS } from "@/lib/findings-view";

describe("findings severity filters", () => {
  it("offers a filter for every severity bucket the API reports", () => {
    // The facet contract is the authority on which buckets exist. A chip list
    // that omits one silently strands those findings: they are counted in the
    // total but reachable by no filter, which is the exact "unknown is never a
    // silent drop" rule the findings view is meant to uphold.
    const buckets: Array<keyof FindingFacets["severity"]> = [
      "critical",
      "high",
      "medium",
      "low",
      "info",
      "unknown",
    ];
    for (const bucket of buckets) {
      expect(SEVERITY_FILTER_KEYS).toContain(bucket === "unknown" ? "unrated" : bucket);
    }
  });
});
