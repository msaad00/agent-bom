import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { GraphEntityDrawer } from "@/components/graph-entity-drawer";
import type { LineageNodeData } from "@/components/lineage-nodes";

const noop = () => {};

// A vulnerability node rich enough to populate every tab: Overview (severity /
// CVSS / identifier), Relationships (edge + neighbor counts), Impact
// (impact-by-type), and Attributes (data sources / compliance / raw attrs).
function richNode(): LineageNodeData {
  return {
    label: "CVE-2024-9999",
    nodeType: "vulnerability",
    severity: "high",
    cvssScore: 9.1,
    neighborCount: 4,
    sourceCount: 2,
    incomingEdgeCount: 2,
    outgoingEdgeCount: 1,
    impactCount: 5,
    maxImpactDepth: 3,
    impactByType: { package: 3, agent: 1 },
    dataSources: ["osv"],
    complianceTags: ["SOC2"],
    attributes: { node_id: "vuln:cve-2024-9999", blast_scope: "prod-estate" },
  } as unknown as LineageNodeData;
}

describe("graph entity drawer tabs", () => {
  it("renders a tab per populated group instead of one long column", () => {
    render(<GraphEntityDrawer data={richNode()} onClose={noop} enrich={false} />);

    expect(screen.getByTestId("graph-drawer-tab-overview")).toBeTruthy();
    expect(screen.getByTestId("graph-drawer-tab-relationships")).toBeTruthy();
    expect(screen.getByTestId("graph-drawer-tab-impact")).toBeTruthy();
    expect(screen.getByTestId("graph-drawer-tab-attributes")).toBeTruthy();
  });

  it("shows Overview by default and hides the other sections until selected", () => {
    render(<GraphEntityDrawer data={richNode()} onClose={noop} enrich={false} />);

    // Overview panel is active and carries the type-specific hero detail.
    expect(screen.getByTestId("graph-drawer-panel-overview")).toBeTruthy();
    expect(screen.getByText("CVSS")).toBeTruthy();

    // Content that belongs to other tabs must not be mounted yet.
    expect(screen.queryByText("Neighbors")).toBeNull();
    expect(screen.queryByText("Data Sources")).toBeNull();
  });

  it("switches to Relationships and reveals the graph-context rows", () => {
    render(<GraphEntityDrawer data={richNode()} onClose={noop} enrich={false} />);

    fireEvent.click(screen.getByTestId("graph-drawer-tab-relationships"));

    expect(screen.getByTestId("graph-drawer-panel-relationships")).toBeTruthy();
    expect(screen.getByText("Neighbors")).toBeTruthy();
    expect(screen.getByText("Incoming edges")).toBeTruthy();
    expect(screen.getByText("Affected nodes")).toBeTruthy();
    // Overview-only content is gone once we leave that tab.
    expect(screen.queryByText("CVSS")).toBeNull();
  });

  it("switches to Impact and Attributes without dropping their data", () => {
    render(<GraphEntityDrawer data={richNode()} onClose={noop} enrich={false} />);

    fireEvent.click(screen.getByTestId("graph-drawer-tab-impact"));
    expect(screen.getByTestId("graph-drawer-panel-impact")).toBeTruthy();
    expect(screen.getByText(/Package: 3/)).toBeTruthy();

    fireEvent.click(screen.getByTestId("graph-drawer-tab-attributes"));
    expect(screen.getByTestId("graph-drawer-panel-attributes")).toBeTruthy();
    expect(screen.getByText("Data Sources")).toBeTruthy();
    expect(screen.getByText("Compliance Tags")).toBeTruthy();
    expect(screen.getByText("Blast Scope")).toBeTruthy();
  });

  it("exposes a keyboard/pointer resize handle in overlay mode", () => {
    render(<GraphEntityDrawer data={richNode()} onClose={noop} enrich={false} />);
    expect(screen.getByLabelText("Resize drawer")).toBeTruthy();
  });

  it("collapses to no tab bar when only Overview has content", () => {
    const bare = {
      label: "checkout-agent",
      nodeType: "agent",
      severity: "none",
    } as unknown as LineageNodeData;
    render(<GraphEntityDrawer data={bare} onClose={noop} enrich={false} />);
    // A single group must not render a lone, pointless tab strip.
    expect(screen.queryByTestId("graph-drawer-tab-relationships")).toBeNull();
    expect(screen.queryByRole("tablist")).toBeNull();
  });
});
