import { describe, expect, it } from "vitest";

import { openIssueSeverity } from "@/lib/open-issue-counts";

const issues = {
  critical: 325,
  high: 814,
  medium: 10,
  low: 2,
  unrated: 1,
  total: 1152,
  approximate: false,
  basis: "issue_groups" as const,
};

describe("openIssueSeverity", () => {
  it("prefers the issue-group counts the findings page shows over occurrence totals", () => {
    const result = openIssueSeverity({ critical: 428, high: 1265, medium: 20, low: 4, total: 1717, issues });
    expect(result).toMatchObject({ critical: 325, high: 814, medium: 10, low: 2, total: 1152 });
  });

  it("falls back to legacy occurrence counts when the server predates issue counts", () => {
    const result = openIssueSeverity({ critical: 3, high: 1, medium: 0, low: 0, total: 4 });
    expect(result).toEqual({ critical: 3, high: 1, medium: 0, low: 0, total: 4 });
  });

  it("returns null for missing input", () => {
    expect(openIssueSeverity(null)).toBeNull();
    expect(openIssueSeverity(undefined)).toBeNull();
  });
});
