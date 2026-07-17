import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { GraphLensSwitcher } from "@/components/graph-lens-switcher";

const push = vi.fn();
let pathname = "/graph";
let scope: string | null = null;
let params = new URLSearchParams();

vi.mock("next/navigation", () => ({
  usePathname: () => pathname,
  useRouter: () => ({ push }),
  useSearchParams: () => ({
    get: (key: string) => (key === "scope" ? scope : params.get(key)),
  }),
}));

describe("GraphLensSwitcher", () => {
  beforeEach(() => {
    pathname = "/graph";
    scope = null;
    params = new URLSearchParams();
    push.mockClear();
  });

  it("renders the compact lens bar without overlay marketing copy", () => {
    render(<GraphLensSwitcher variant="compact" />);

    expect(screen.queryByTestId("graph-lens-floating-bar")).not.toBeInTheDocument();
    expect(screen.queryByText("Security Graph Lens")).not.toBeInTheDocument();
    expect(screen.getByText("Lens")).toBeInTheDocument();
    expect(screen.getByText("Lineage")).toBeInTheDocument();
  });

  it("renders the floating lens bar for full-canvas graph pages", () => {
    render(<GraphLensSwitcher variant="floating" />);

    expect(screen.getByTestId("graph-lens-floating-bar")).toBeInTheDocument();
    expect(screen.getByText("Security Graph Lens")).toBeInTheDocument();
    expect(screen.getByText("Attack Paths")).toBeInTheDocument();
    expect(screen.getByText("Lineage")).toBeInTheDocument();
    expect(screen.getByText("Asset Drift")).toBeInTheDocument();
    expect(screen.getByText("Agent Mesh")).toBeInTheDocument();
    expect(screen.getByText("Context")).toBeInTheDocument();
  });

  it("routes to another graph lens without shifting the canvas route shell", () => {
    render(<GraphLensSwitcher variant="floating" />);

    fireEvent.click(screen.getByRole("button", { name: /agent mesh/i }));

    expect(push).toHaveBeenCalledWith("/mesh");
  });

  it("preserves investigation focus when switching route-backed lenses", () => {
    pathname = "/security-graph";
    params = new URLSearchParams({
      scan: "scan-123",
      agent: "payments-agent",
      cve: "CVE-2026-0042",
      package: "werkzeug",
      root: "agent:payments",
      root_label: "Payments agent",
      investigate: "1",
      q: "Payments agent",
      rollup: "1",
      unrelated: "drop-me",
    });
    render(<GraphLensSwitcher variant="floating" />);

    fireEvent.click(screen.getByRole("button", { name: /agent mesh/i }));

    expect(push).toHaveBeenCalledWith(
      "/mesh?scan=scan-123&agent=payments-agent&cve=CVE-2026-0042&package=werkzeug&root=agent%3Apayments&root_label=Payments+agent&investigate=1&q=Payments+agent&rollup=1",
    );
  });

  it("keeps the target lens scope authoritative while preserving shared context", () => {
    params = new URLSearchParams({ scan: "scan-123", scope: "something-else" });
    render(<GraphLensSwitcher variant="floating" />);

    fireEvent.click(screen.getByRole("button", { name: /asset drift/i }));

    expect(push).toHaveBeenCalledWith("/graph?scan=scan-123&scope=asset-drift");
  });

  it("routes to the asset drift lens on the lineage graph", () => {
    render(<GraphLensSwitcher variant="floating" />);

    fireEvent.click(screen.getByRole("button", { name: /asset drift/i }));

    expect(push).toHaveBeenCalledWith("/graph?scope=asset-drift");
  });

  it("does not reroute when the active lens is selected", () => {
    pathname = "/mesh";
    render(<GraphLensSwitcher variant="floating" />);

    fireEvent.click(screen.getByRole("button", { name: /agent mesh/i }));

    expect(push).not.toHaveBeenCalled();
  });

  it("renders a collapsible legend dock under the lens bar", () => {
    render(
      <GraphLensSwitcher
        variant="compact"
        legendItems={[
          { label: "AI Agent", color: "#10b981", layer: "orchestration", kind: "node", shape: "dot" },
          { label: "MCP Server", color: "#3b82f6", layer: "mcp_server", kind: "node", shape: "square" },
          { label: "Uses", color: "#10b981", kind: "edge", lineStyle: "solid" },
        ]}
      />,
    );

    expect(screen.getByText("Legend")).toBeInTheDocument();
    expect(screen.getAllByText("AI Agent").length).toBeGreaterThan(0);
    expect(screen.getByText("expand")).toBeInTheDocument();
  });
});
