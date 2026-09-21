import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { api } from "@/lib/api";
import type { GraphNodeDetailResponse } from "@/lib/api-types";
import { GraphEntityDrawer } from "@/components/graph-entity-drawer";
import type { LineageNodeData } from "@/components/lineage-nodes";

const noop = () => {};
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });

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
  it("retains loaded finding evidence when a later canvas response refreshes the same node", async () => {
    const data = { label: "pyyaml@5.3", nodeType: "package", attributes: { node_id: "pkg:42" } } as LineageNodeData;
    const getNode = vi.spyOn(api, "getGraphNode").mockResolvedValue({
      node: { id: "pkg:42", entity_type: "package", attributes: {} },
      edges_in: [], edges_out: [{ id: "finding", source: "pkg:42", target: "vulnerability:CVE-2020-14343", relationship: "vulnerable_to" }],
      neighbors: ["vulnerability:CVE-2020-14343"], sources: ["scan"],
      impact: { affected_count: 0, affected_by_type: {}, max_depth_reached: 0 },
    } as unknown as GraphNodeDetailResponse);
    const { rerender } = render(<GraphEntityDrawer data={data} scanId="scan-one" onClose={noop} />);
    expect(await screen.findByText("Findings", { exact: true })).toBeTruthy();
    rerender(<GraphEntityDrawer data={{ ...data, label: "Updated canvas label" }} scanId="scan-one" onClose={noop} />);
    expect(screen.getByText("Findings", { exact: true })).toBeTruthy();
    expect(getNode).toHaveBeenCalledTimes(1);

    // Detail belongs to one snapshot and cannot leak into another while its request is pending.
    getNode.mockImplementation(() => new Promise(() => {}));
    rerender(<GraphEntityDrawer data={data} scanId="scan-two" onClose={noop} />);
    expect(screen.queryByText("Findings", { exact: true })).toBeNull();
    expect(screen.getByText("Finding count unavailable")).toBeTruthy();
  });

  it.each(["overlay", "docked"] as const)("portals mobile %s detail beyond the constrained canvas with keyboard dismissal", async (variant) => {
    vi.stubGlobal("matchMedia", vi.fn().mockReturnValue({ matches: true, media: "(max-width: 639px)",
      addEventListener: vi.fn(), removeEventListener: vi.fn(), addListener: vi.fn(), removeListener: vi.fn(), dispatchEvent: vi.fn(), onchange: null }));
    const close = vi.fn();
    const trigger = document.createElement("button");
    document.body.appendChild(trigger);
    trigger.focus();
    const { container, unmount } = render(<div style={{ height: 300, overflow: "hidden", transform: "translateX(0)" }}>
      <GraphEntityDrawer data={richNode()} onClose={close} enrich={false} variant={variant} />
    </div>);
    const dialog = await screen.findByRole("dialog", { name: "CVE-2024-9999" });
    expect(container.contains(dialog)).toBe(false);
    expect(screen.getByTestId("graph-entity-drawer").className).toContain("fixed inset-0");
    expect(document.body.style.overflow).toBe("hidden");
    expect(screen.queryByLabelText("Resize drawer")).toBeNull();
    fireEvent.click(screen.getByTestId("graph-drawer-tab-relationships"));
    expect(screen.getByText("Incoming edges")).toBeTruthy();
    expect(screen.getByTestId("graph-drawer-panel-relationships").className).toContain("overflow-y-auto");
    fireEvent.click(screen.getByRole("button", { name: "Back" }));
    expect(close).toHaveBeenCalledTimes(1);
    await waitFor(() => expect(dialog.contains(document.activeElement)).toBe(true));
    fireEvent.keyDown(document, { key: "Escape" });
    expect(close).toHaveBeenCalledTimes(2);
    unmount();
    expect(document.activeElement).toBe(trigger);
    expect(document.body.style.overflow).not.toBe("hidden");
    trigger.remove();
  });

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
    expect(screen.getByText("Upstream connections")).toBeTruthy();
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

  it("qualifies structural counts without claiming successful exploitation or damage", () => {
    render(<GraphEntityDrawer data={richNode()} onClose={noop} enrich={false} />);
    fireEvent.click(screen.getByTestId("graph-drawer-tab-impact"));
    expect(screen.getByText("Upstream connected entities")).toBeTruthy();
    expect(screen.getByText(/do not establish exploitability, successful actions or observed damage/)).toBeTruthy();
    expect(screen.getByText("Traversal completeness unavailable")).toBeTruthy();
    expect(screen.getByText("3 hops explored")).toBeTruthy();
  });

  it.each([
    ["depth_limit", "Hop limit reached; additional upstream connections may exist."],
    ["traversal_budget", "Traversal limit reached; additional upstream connections may exist."],
  ])("preserves bounded impact metadata from the node API: %s", async (reason, explanation) => {
    vi.spyOn(api, "getGraphNode").mockResolvedValue({
      node: { id: "vuln:cve-2024-9999", attributes: {} },
      edges_in: [], edges_out: [], neighbors: [], sources: [],
      impact: { affected_count: 4, affected_by_type: { package: 3, agent: 1 }, max_depth_reached: 3,
        completeness: { status: "truncated", complete: false, truncated: true, sampled: false, returned: 4, reason } },
    } as unknown as GraphNodeDetailResponse);
    render(<GraphEntityDrawer data={richNode()} scanId="scan-proof" onClose={noop} />);
    fireEvent.click(screen.getByTestId("graph-drawer-tab-impact"));
    expect(await screen.findByText("Partial traversal · 4 entities returned")).toBeTruthy();
    expect(screen.getByText(explanation)).toBeTruthy();
    expect(screen.queryByText("Recorded upstream traversal complete")).toBeNull();
  });

  it("keeps a complete zero-result traversal inspectable without claiming no exposure", () => {
    const data: LineageNodeData = { ...richNode(), impactByType: {}, impactCount: 0, maxImpactDepth: 0,
      impactCompleteness: { status: "complete", complete: true, truncated: false, sampled: false, returned: 0, total: 0 } };
    render(<GraphEntityDrawer data={data} onClose={noop} enrich={false} />);
    fireEvent.click(screen.getByTestId("graph-drawer-tab-impact"));
    expect(screen.getByText("No upstream entities returned")).toBeTruthy();
    expect(screen.getByText("Recorded upstream traversal complete")).toBeTruthy();
    expect(screen.getByText(/do not establish exploitability/)).toBeTruthy();
  });

  it("drills a direct relationship without losing its direction or selected neighbor", async () => {
    vi.spyOn(api, "getGraphNode").mockResolvedValue({
      node: { id: "vuln:cve-2024-9999", attributes: {} },
      edges_in: [{ id: "e1", source: "package:sample", target: "vuln:cve-2024-9999", relationship: "vulnerable_to" }],
      edges_out: [], neighbors: ["package:sample"], sources: ["scan"],
      impact: { affected_count: 1, affected_by_type: { package: 1 }, max_depth_reached: 1 },
    } as unknown as GraphNodeDetailResponse);
    const inspect = vi.fn();
    render(<GraphEntityDrawer data={richNode()} scanId="scan-proof" onClose={noop} onInspectNode={inspect} />);
    fireEvent.click(screen.getByTestId("graph-drawer-tab-relationships"));
    fireEvent.click(await screen.findByRole("button", { name: "Incoming · vulnerable to · package:sample" }));
    expect(inspect).toHaveBeenCalledWith("package:sample");
    expect(api.getGraphNode).toHaveBeenCalledWith("vuln:cve-2024-9999", "scan-proof");
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
