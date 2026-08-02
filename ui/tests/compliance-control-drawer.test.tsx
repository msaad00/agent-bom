import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { ComplianceControlDrawer } from "@/components/compliance-control-drawer";
import type { ComplianceControl } from "@/lib/api";

function control(status: ComplianceControl["status"]): ComplianceControl {
  return {
    code: "LLM01",
    name: "Prompt Injection",
    findings: 0,
    status,
    severity_breakdown: {},
    affected_packages: [],
    affected_agents: [],
  };
}

describe("compliance control drawer status honesty", () => {
  // The backend emits not_assessed / not_evaluated / not_applicable for
  // controls it never measured. Reading those as "Fail" asserts a control
  // failure the estate does not own — the inverse of the false-pass bug.
  it.each([
    ["not_assessed", "Not assessed"],
    ["not_evaluated", "Not evaluated"],
    ["not_applicable", "Not applicable"],
  ])("labels %s as %s, never Fail", (status, expected) => {
    render(
      <ComplianceControlDrawer
        control={control(status as ComplianceControl["status"])}
        frameworkLabel="OWASP LLM"
        onClose={() => {}}
      />,
    );

    expect(screen.getByText(expected)).toBeInTheDocument();
    expect(screen.queryByText("Fail")).not.toBeInTheDocument();
  });

  it("still labels a measured failure as Fail", () => {
    render(
      <ComplianceControlDrawer control={control("fail")} frameworkLabel="OWASP LLM" onClose={() => {}} />,
    );

    expect(screen.getByText("Fail")).toBeInTheDocument();
  });
});
