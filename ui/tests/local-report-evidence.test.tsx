import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { LocalReportEvidence } from "@/components/local-report-evidence";
import type { ScanResult } from "@/lib/api";

function show(scan_run: unknown) {
  return render(<LocalReportEvidence report={{ agents: [], blast_radius: [], scan_run } as unknown as ScanResult} />);
}

describe("local collection evidence", () => {
  it("keeps complete collection scoped and unverified", () => {
    show({ outcome: "complete", requested_scope_count: 1, complete_scope_count: 1, incomplete_scope_count: 0 });
    expect(screen.getByText("Collection complete")).toBeVisible();
    expect(screen.getByText(/1 of 1 requested scopes complete/)).toBeVisible();
    expect(screen.getByText(/provenance and freshness have not been verified/)).toBeVisible();
  });
  it.each([null, "untrusted", [], undefined])("accepts legacy or unknown metadata without a clean verdict", (run) => {
    show(run);
    expect(screen.getByText("Collection coverage unknown")).toBeVisible();
  });
  it.each([
    { outcome: "complete", scopes: "invalid" },
    { outcome: "complete", scopes: [null] },
    { outcome: "complete", issues: { message: "invalid" } },
    { outcome: "complete", requested_scope_count: -1 },
    { outcome: "complete", requested_scope_count: 1, complete_scope_count: 4, incomplete_scope_count: 0 },
    { outcome: "complete", scopes: [{ name: "advisories", status: "unavailable", requested: true }] },
  ])("flags contradictory or malformed coverage metadata", (run) => {
    show(run);
    expect(screen.getByText("Collection metadata inconsistent")).toBeVisible();
  });
  it("bounds rendered details while disclosing omitted records", () => {
    show({ outcome: "partial", scopes: Array.from({ length: 21 }, (_, i) => ({ name: `scope-${i}`, status: "unavailable" })),
      issues: Array.from({ length: 6 }, (_, i) => ({ code: `issue-${i}`, message: "Collection unavailable" })) });
    fireEvent.click(screen.getByText(/Collection details/));
    expect(screen.getByText(/Showing 20 of 21 scope records/)).toBeVisible();
    expect(screen.getByText(/Showing 5 of 6 issues/)).toBeVisible();
    expect(screen.queryByText(/scope-20:/)).not.toBeInTheDocument();
    expect(screen.queryByText(/issue-5:/)).not.toBeInTheDocument();
  });
});
