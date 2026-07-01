import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { GraphLensSwitcher } from "@/components/graph-lens-switcher";

const push = vi.fn();
let pathname = "/graph";

vi.mock("next/navigation", () => ({
  usePathname: () => pathname,
  useRouter: () => ({ push }),
}));

describe("GraphLensSwitcher", () => {
  beforeEach(() => {
    pathname = "/graph";
    push.mockClear();
  });

  it("renders the floating lens bar for full-canvas graph pages", () => {
    render(<GraphLensSwitcher variant="floating" />);

    expect(screen.getByTestId("graph-lens-floating-bar")).toBeInTheDocument();
    expect(screen.getByText("Security Graph Lens")).toBeInTheDocument();
    expect(screen.getByText("Attack Paths")).toBeInTheDocument();
    expect(screen.getByText("Lineage")).toBeInTheDocument();
    expect(screen.getByText("Agent Mesh")).toBeInTheDocument();
    expect(screen.getByText("Context")).toBeInTheDocument();
  });

  it("routes to another graph lens without shifting the canvas route shell", () => {
    render(<GraphLensSwitcher variant="floating" />);

    fireEvent.click(screen.getByRole("button", { name: /agent mesh/i }));

    expect(push).toHaveBeenCalledWith("/mesh");
  });

  it("does not reroute when the active lens is selected", () => {
    pathname = "/mesh";
    render(<GraphLensSwitcher variant="floating" />);

    fireEvent.click(screen.getByRole("button", { name: /agent mesh/i }));

    expect(push).not.toHaveBeenCalled();
  });
});
