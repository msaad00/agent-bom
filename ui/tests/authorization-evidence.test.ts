import { describe, expect, it } from "vitest";

import { authorizationEvidenceCopy } from "@/lib/authorization-evidence";

describe("authorizationEvidenceCopy", () => {
  it("describes complete evidence without overstating its scope", () => {
    expect(authorizationEvidenceCopy({ status: "complete", required_source_count: 2, complete_source_count: 2,
      partial_source_count: 0, indeterminate_source_count: 0 })).toEqual({
      label: "Complete",
      detail: "2 of 2 required evidence sources are complete for this scan.",
    });
  });

  it("describes partial evidence as unsuitable for conclusive authorization decisions", () => {
    expect(authorizationEvidenceCopy({ status: "partial", required_source_count: 3, complete_source_count: 2,
      partial_source_count: 1, indeterminate_source_count: 0 })).toEqual({
      label: "Partial",
      detail: "2 of 3 required evidence sources are complete. Authorization decisions may remain indeterminate.",
    });
  });

  it("does not imply an authorization result when evidence is indeterminate", () => {
    expect(authorizationEvidenceCopy({ status: "indeterminate", required_source_count: 3, complete_source_count: 1,
      partial_source_count: 0, indeterminate_source_count: 2 })).toEqual({
      label: "Indeterminate",
      detail: "Authorization evidence is not conclusive for this scan. No allow or deny should be inferred.",
    });
  });
});
