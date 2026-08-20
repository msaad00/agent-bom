import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import InventoryKindClient from "@/app/inventory/[kind]/InventoryKindClient";

const { navState, replaceMock } = vi.hoisted(() => ({
  navState: { search: "severity=high&tab=assets" },
  replaceMock: vi.fn(),
}));

vi.mock("next/navigation", () => ({
  useParams: () => ({ kind: "packages" }),
  usePathname: () => "/inventory/packages",
  useRouter: () => ({ replace: replaceMock }),
  useSearchParams: () => new URLSearchParams(navState.search),
}));

vi.mock("@/lib/inventory-context", () => ({
  InventoryProvider: ({
    children,
    minSeverity,
  }: {
    children: React.ReactNode;
    minSeverity?: string;
  }) => (
    <div data-testid="inventory-provider" data-min-severity={minSeverity ?? "all"}>
      {children}
    </div>
  ),
}));

vi.mock("@/components/inventory/asset-inventory-view", () => ({
  AssetInventoryView: ({
    severityFilter,
    onSeverityFilterChange,
  }: {
    severityFilter?: string;
    onSeverityFilterChange?: (severity: string) => void;
  }) => (
    <div>
      <span>severity:{severityFilter}</span>
      <button type="button" onClick={() => onSeverityFilterChange?.("critical")}>
        Critical
      </button>
      <button type="button" onClick={() => onSeverityFilterChange?.("all")}>
        All
      </button>
    </div>
  ),
}));

beforeEach(() => {
  navState.search = "severity=high&tab=assets";
  replaceMock.mockReset();
});

describe("Inventory server filter URL contract", () => {
  it("restores severity into the server request and preserves unrelated query state", () => {
    render(<InventoryKindClient />);

    expect(screen.getByTestId("inventory-provider")).toHaveAttribute("data-min-severity", "high");
    expect(screen.getByText("severity:high")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Critical" }));
    expect(replaceMock).toHaveBeenCalledWith(
      "/inventory/packages?severity=critical&tab=assets",
      { scroll: false },
    );

    fireEvent.click(screen.getByRole("button", { name: "All" }));
    expect(replaceMock).toHaveBeenCalledWith("/inventory/packages?tab=assets", { scroll: false });
  });

  it("drops unsupported severity values before they reach the server", () => {
    navState.search = "severity=unknown";
    render(<InventoryKindClient />);

    expect(screen.getByTestId("inventory-provider")).toHaveAttribute("data-min-severity", "all");
    expect(screen.getByText("severity:all")).toBeInTheDocument();
  });
});
