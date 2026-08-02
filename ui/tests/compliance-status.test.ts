import { describe, expect, it } from "vitest";

import {
  controlStatusLabel,
  controlStatusTone,
  isNotEvaluated,
  postureLabel,
} from "@/components/compliance-status";

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

  // The per-control vocabulary the backend actually emits (compliance.py:526-553)
  // is wider than pass/warning/fail. A control nothing was measured for must
  // never read as a failure the estate owns.
  it("counts every no-evidence per-control status as not evaluated", () => {
    expect(isNotEvaluated("not_assessed")).toBe(true);
    expect(isNotEvaluated("not_applicable")).toBe(true);
  });

  it("never labels an unmeasured control 'Fail'", () => {
    expect(controlStatusLabel("not_assessed")).toBe("Not assessed");
    expect(controlStatusLabel("not_evaluated")).toBe("Not evaluated");
    expect(controlStatusLabel("not_applicable")).toBe("Not applicable");
    expect(controlStatusLabel("applicable")).toBe("Applicable");
    expect(controlStatusLabel("pass")).toBe("Pass");
    expect(controlStatusLabel("warning")).toBe("Needs attention");
    expect(controlStatusLabel("fail")).toBe("Fail");
    // An unknown future status is neutral, never a fabricated failure.
    expect(controlStatusLabel("something_new")).toBe("Not evaluated");
  });

  it("tones an unmeasured control neutral, not critical", () => {
    expect(controlStatusTone("not_assessed")).toBe("neutral");
    expect(controlStatusTone("not_applicable")).toBe("neutral");
    expect(controlStatusTone("not_evaluated")).toBe("neutral");
    expect(controlStatusTone("pass")).toBe("pass");
    expect(controlStatusTone("warning")).toBe("warning");
    expect(controlStatusTone("fail")).toBe("fail");
  });
});
