import { describe, expect, it } from "vitest";
import { nodeRiskAssessment, nodeRiskLabel } from "@/lib/node-risk-assessment";

const assessed = { status: "assessed", basis: "cvss", scope: "node" } as const;

describe("node risk assessment", () => {
  it.each([undefined, 0, 9.5])("does not infer assessment from a legacy score %s", score => {
    expect(nodeRiskLabel(score, undefined)).toBe("Not assessed");
  });
  it("distinguishes assessed zero from unassessed zero", () => {
    expect(nodeRiskLabel(0, assessed)).toBe("0.0");
    expect(nodeRiskLabel(9.5, assessed)).toBe("9.5");
    expect(nodeRiskLabel(0, { status: "not_assessed" })).toBe("Not assessed");
    expect(nodeRiskLabel(Number.NaN, assessed)).toBe("Unavailable");
  });
  it("normalizes missing and invalid assessment metadata conservatively", () => {
    expect(nodeRiskAssessment({ status: "unknown", basis: 7 })).toEqual({ status: "not_assessed", basis: null, scope: null });
    expect(nodeRiskAssessment(assessed)).toEqual(assessed);
    expect(nodeRiskLabel(0, { status: "assessed", basis: null, scope: null })).toBe("Not assessed");
    expect(nodeRiskLabel(0, { status: "assessed", basis: " ", scope: "node" })).toBe("Not assessed");
  });
});
