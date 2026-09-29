import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { FindingInvestigationContext } from "@/components/finding-investigation-context";
let params = new URLSearchParams();
vi.mock("next/navigation", () => ({ useSearchParams: () => params }));

describe("finding return context", () => {
  it("keeps a changed snapshot visibly separate from the original finding", () => {
    params = new URLSearchParams({ finding: "f-1", finding_scan: "original", scan: "other" });
    render(<FindingInvestigationContext />);
    expect(screen.getByText(/Viewing a different graph snapshot/)).toBeVisible();
    expect(screen.getByRole("link", { name: "Return to finding" })).toHaveAttribute("href", "/findings?finding=f-1&scan=original&window=0");
  });
  it("retains the explicit evidence boundary for related graph exploration", () => {
    params = new URLSearchParams({ related_finding: "f-1", finding_scan: "original" });
    render(<FindingInvestigationContext />);
    expect(screen.getByText(/Graph relationships require their own evidence/)).toBeVisible();
    expect(screen.getByRole("link", { name: "Return to finding" })).toHaveAttribute("href", "/findings?finding=f-1&scan=original&window=0");
  });
  it("adds no finding context to an ordinary graph", () => {
    params = new URLSearchParams({ scan: "s-1" });
    render(<FindingInvestigationContext />);
    expect(screen.queryByRole("complementary")).not.toBeInTheDocument();
  });
});
