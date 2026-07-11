import { describe, expect, it } from "vitest";

import { isNotEvaluated, postureLabel } from "@/components/compliance-status";

describe("compliance status honesty", () => {
  it("treats no-evidence statuses as not evaluated", () => {
    expect(isNotEvaluated("no_data")).toBe(true);
    expect(isNotEvaluated("not_evaluated")).toBe(true);
    expect(isNotEvaluated("pass")).toBe(false);
    expect(isNotEvaluated("fail")).toBe(false);
  });

  it("labels no-evidence statuses as 'Not evaluated', never Compliant/Non-compliant", () => {
    expect(postureLabel("no_data")).toBe("Not evaluated");
    expect(postureLabel("not_evaluated")).toBe("Not evaluated");
    expect(postureLabel("pass")).toBe("Compliant");
    expect(postureLabel("fail")).toBe("Non-compliant");
  });
});
