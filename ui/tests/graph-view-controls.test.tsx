import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { GraphViewControls } from "@/components/graph-view-controls";
import { createExpandedGraphFilters } from "@/components/lineage-filter";

describe("graph view controls", () => {
  it("labels estate summary without claiming inactive topology layers apply", () => {
    render(<GraphViewControls filters={createExpandedGraphFilters()} onChange={vi.fn()} agentNames={[]} estateSummary />);
    const summary = screen.getByLabelText("Active graph filters");
    expect(summary.textContent).toContain("Estate summary");
    expect(summary.textContent).toContain("open filtered topology");
    expect(summary.textContent).not.toContain("layers");
  });
  it("exposes filters directly and changes layers without discarding other scope", () => {
    const filters = { ...createExpandedGraphFilters("Alice"), severity: "high", pageSize: 150 };
    const onChange = vi.fn();
    const onReset = vi.fn();
    render(<GraphViewControls filters={filters} onChange={onChange} onReset={onReset} agentNames={["Alice"]} />);
    expect(screen.getByLabelText("Active graph filters").textContent).toContain("high+ severity");
    const toggle = screen.getByRole("button", { name: "View & layers" });
    expect(toggle.getAttribute("aria-expanded")).toBe("false");
    fireEvent.click(toggle);
    expect(toggle.getAttribute("aria-expanded")).toBe("true");
    fireEvent.change(screen.getByRole("searchbox", { name: "Filter graph layers" }), { target: { value: "Packages" } });
    fireEvent.click(screen.getByRole("checkbox", { name: "Packages" }));
    expect(onChange).toHaveBeenLastCalledWith({ ...filters, layers: { ...filters.layers, package: false } });
    fireEvent.click(screen.getByRole("button", { name: "Reset graph view" }));
    expect(onReset).toHaveBeenCalledOnce();
  });
});
