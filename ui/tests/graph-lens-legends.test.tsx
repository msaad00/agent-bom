import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { GraphDriftLegend } from "@/components/graph-drift-legend";
import { GraphEvidenceLegend } from "@/components/graph-evidence-legend";

describe("graph lens legends", () => {
  it("preserves drift counts, switch semantics and source context", () => {
    const toggle = vi.fn();
    const filter = vi.fn();
    const props = { active: true, onToggleActive: toggle, filter: "all" as const, onFilterChange: filter,
      counts: { new: 2, changed: 3, removed: 4, unchanged: 5 }, criticalCount: 1,
      comparedLabel: "prior-snapshot", attributeSummaries: ["Role changed"] };
    const { rerender } = render(<GraphDriftLegend {...props} />);
    expect(screen.getByRole("switch").getAttribute("aria-checked")).toBe("true");
    expect(screen.getByTestId("graph-drift-chip-all").textContent).toBe("All14");
    expect(screen.getByTestId("graph-drift-chip-critical").textContent).toBe("Critical change1");
    expect(screen.getByText("Role changed")).toBeTruthy();
    fireEvent.click(screen.getByTestId("graph-drift-chip-critical"));
    expect(filter).toHaveBeenCalledWith("critical");
    fireEvent.click(screen.getByRole("switch"));
    expect(toggle).toHaveBeenCalledWith(false);
    rerender(<GraphDriftLegend {...props} active={false} />);
    expect(screen.getByText("prior-snapshot")).toBeTruthy();
    expect(screen.queryByTestId("graph-drift-chips")).toBeNull();
  });
  it("preserves evidence categories and pressed-button semantics", () => {
    const toggle = vi.fn();
    const filter = vi.fn();
    render(<GraphEvidenceLegend active onToggleActive={toggle} filter="runtime_blocked"
      onFilterChange={filter} counts={{ all: 9, runtime_observed: 2, runtime_blocked: 3, static_scan: 4 }} />);
    expect(screen.getByTestId("graph-evidence-toggle").getAttribute("aria-pressed")).toBe("true");
    expect(screen.getByTestId("graph-evidence-chip-runtime_blocked").getAttribute("aria-pressed")).toBe("true");
    expect(screen.getByTestId("graph-evidence-chip-static_scan").textContent).toBe("Static scan4");
    fireEvent.click(screen.getByTestId("graph-evidence-chip-static_scan"));
    expect(filter).toHaveBeenCalledWith("static_scan");
    fireEvent.click(screen.getByTestId("graph-evidence-toggle"));
    expect(toggle).toHaveBeenCalledWith(false);
  });
});
