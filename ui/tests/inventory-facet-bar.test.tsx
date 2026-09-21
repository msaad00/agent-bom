import { fireEvent, render, screen, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { InventoryFacetBar } from "@/components/inventory/inventory-facet-bar";
import type { InventoryFacets } from "@/lib/api";

const inventory = vi.hoisted(() => ({
  filters: { search: "", type: "agent", environment: "production", source: "cloud:aws", provider: "aws", severity: "high", minSeverity: "" },
  facets: {} as InventoryFacets,
  setFilter: vi.fn(),
  clearFilters: vi.fn(),
}));
vi.mock("@/lib/inventory-context", () => ({
  useInventory: () => ({ model: { facets: inventory.facets }, summary: null, filters: inventory.filters,
    fixedEntityTypes: [], setFilter: inventory.setFilter, clearFilters: inventory.clearFilters }),
}));

beforeEach(() => {
  vi.clearAllMocks();
  inventory.filters = { search: "", type: "agent", environment: "production", source: "cloud:aws", provider: "aws", severity: "high", minSeverity: "" };
  inventory.facets = { type: { buckets: [] }, environment: { buckets: [] }, source: { buckets: [] }, provider: { buckets: [] }, severity: { buckets: [] } };
});

describe("active inventory facet values", () => {
  it.each([
    ["type", "Type", "agent"], ["environment", "Environment", "production"],
    ["source", "Source", "cloud:aws"], ["provider", "Provider", "aws"],
    ["severity", "Finding severity", "high"],
  ] as const)("retains %s scope when its active value is absent from returned facets", (key, title, value) => {
    render(<InventoryFacetBar />);
    const select = screen.getByLabelText(`Filter by ${title.toLowerCase()}`);
    expect(select).toHaveValue(value);
    expect(within(select).getByRole("option", { selected: true })).toHaveTextContent("selected · count unavailable");
    expect(inventory.setFilter).not.toHaveBeenCalled();
    fireEvent.change(select, { target: { value: "" } });
    expect(inventory.setFilter).toHaveBeenCalledWith(key, "");
  });

  it("keeps an explicit multi-type scope intact rather than selecting a single bucket", () => {
    inventory.filters.type = "agent,package";
    inventory.facets.type.buckets = [{ value: "agent", count: 2 }, { value: "package", count: 3 }];
    render(<InventoryFacetBar />);
    expect(screen.getByLabelText("Filter by type")).toHaveValue("agent,package");
    expect(inventory.setFilter).not.toHaveBeenCalled();
  });

  it("shows a returned active bucket count once without an unavailable placeholder", () => {
    inventory.facets.type.buckets = [{ value: "agent", count: 0 }];
    render(<InventoryFacetBar />);
    const select = screen.getByLabelText("Filter by type");
    expect(within(select).getAllByRole("option")).toHaveLength(2);
    expect(within(select).getByRole("option", { selected: true })).toHaveTextContent("Agent (0)");
  });

  it("honors the route-owned severity when its facet is absent and clears through the route callback", () => {
    const onSeverityFilterChange = vi.fn();
    render(<InventoryFacetBar severityFilter="critical" onSeverityFilterChange={onSeverityFilterChange} />);
    const select = screen.getByLabelText("Filter by finding severity");
    expect(select).toHaveValue("critical");
    fireEvent.change(select, { target: { value: "" } });
    expect(inventory.setFilter).toHaveBeenCalledWith("severity", "");
    expect(onSeverityFilterChange).toHaveBeenCalledWith("all");
  });
});
