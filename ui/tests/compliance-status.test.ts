import { describe, expect, it } from "vitest";

import {
  controlStatusLabel,
  evidenceReasonCta,
  evidenceReasonLabel,
  isControlUnscored,
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
});

describe("compliance control provenance", () => {
  it("treats anything other than graded pass/warn/fail as unscored", () => {
    for (const s of ["pass", "warning", "fail"]) {
      expect(isControlUnscored(s)).toBe(false);
    }
    for (const s of ["not_evaluated", "not_assessed", "not_applicable", "applicable"]) {
      expect(isControlUnscored(s)).toBe(true);
    }
  });

  it("gives every control status a human label, never a raw code", () => {
    expect(controlStatusLabel("pass")).toBe("Pass");
    expect(controlStatusLabel("not_assessed")).toBe("Not assessed");
    expect(controlStatusLabel("not_applicable")).toBe("Not applicable");
    expect(controlStatusLabel("applicable")).toBe("Applicable");
    expect(controlStatusLabel("not_evaluated")).toBe("Not evaluated");
    // An unknown status still reads honestly, never as a raw code.
    expect(controlStatusLabel("something_new")).toBe("Not evaluated");
  });

  it("maps every backend evidence_reason code to a concise label", () => {
    expect(evidenceReasonLabel("no_completed_scan")).toBe("No completed scan");
    expect(evidenceReasonLabel("no_mapped_finding")).toBe("No mapped finding");
    expect(evidenceReasonLabel("unrated_severity_finding")).toBe("Unrated-severity finding");
    expect(evidenceReasonLabel("no_observed_signal")).toBe("No observed signal");
    expect(evidenceReasonLabel("scan_evidence_age_unknown")).toBe("Scan age unknown");
    expect(evidenceReasonLabel(undefined)).toBeNull();
    expect(evidenceReasonLabel("mystery_code")).toBeNull();
  });

  it("offers a next-step CTA only where a missing input is implied", () => {
    expect(evidenceReasonCta("no_completed_scan")).toEqual({ label: "New Scan", href: "/scan" });
    expect(evidenceReasonCta("scan_evidence_age_unknown")).toEqual({ label: "New Scan", href: "/scan" });
    expect(evidenceReasonCta("no_observed_signal")).toEqual({
      label: "Connect a source",
      href: "/connections",
    });
    // A scan ran but nothing graded the control — no honest single action.
    expect(evidenceReasonCta("no_mapped_finding")).toBeNull();
    expect(evidenceReasonCta("unrated_severity_finding")).toBeNull();
    expect(evidenceReasonCta("open_finding")).toBeNull();
    expect(evidenceReasonCta(undefined)).toBeNull();
  });
});
