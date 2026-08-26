/**
 * The two overview renderers that a large estate falls back to — the 2D canvas
 * and the sigma/WebGL stage — paint pixels and nothing else. A screen-reader
 * user reaching `/graph` past 200 nodes got a bare `aria-label` naming the
 * widget and a sentence about the draw budget: no node, no relationship, no
 * severity. The product's core value has to have a text equivalent.
 */
import { render, screen, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { GraphTextAlternative } from "@/components/graph-text-alternative";
import { buildGraphTextAlternative } from "@/lib/graph-text-alternative";
import type {
  LargeGraphOverviewModel,
  LargeGraphOverviewSummary,
  LargeGraphNode,
  LargeGraphEdge,
} from "@/lib/large-graph-overview";
import type { LineageNodeType } from "@/components/lineage-nodes";

function node(
  id: string,
  nodeType: LineageNodeType,
  label: string,
  severity?: string,
): LargeGraphNode {
  return {
    id,
    x: 0,
    y: 0,
    label,
    color: "#000",
    size: 4,
    nodeType,
    severity,
    highlighted: false,
    hidden: false,
    forceLabel: false,
  };
}

function edge(source: string, target: string, relationship: string): LargeGraphEdge {
  return {
    id: `${source}->${target}`,
    source,
    target,
    relationship,
    color: "#000",
    size: 1,
    hidden: false,
  };
}

const NODES: LargeGraphNode[] = [
  node("a1", "agent", "checkout-agent"),
  node("s1", "server", "payments-api"),
  node("s2", "server", "billing-api"),
  node("p1", "package", "requests 2.31.0"),
  node("v1", "vulnerability", "CVE-2026-1111", "critical"),
  node("v2", "vulnerability", "CVE-2026-2222", "low"),
  node("c1", "credential", "STRIPE_KEY"),
];

const EDGES: LargeGraphEdge[] = [
  edge("a1", "s1", "calls"),
  edge("a1", "s2", "calls"),
  edge("s1", "p1", "depends_on"),
  edge("p1", "v1", "has_finding"),
  edge("p1", "v2", "has_finding"),
  edge("s1", "c1", "exposes_cred"),
];

function model(
  overrides: Partial<LargeGraphOverviewModel> = {},
): LargeGraphOverviewModel {
  return {
    nodes: NODES,
    edges: EDGES,
    nodeById: new Map(NODES.map((n) => [n.id, n])),
    sourceNodeCount: NODES.length,
    sourceEdgeCount: EDGES.length,
    omittedNodeCount: 0,
    omittedEdgeCount: 0,
    ...overrides,
  };
}

const SUMMARY: LargeGraphOverviewSummary = {
  nodes: 7,
  edges: 6,
  findings: 2,
  criticalFindings: 1,
  credentials: 1,
  tools: 0,
  topRelationships: [{ relationship: "calls", count: 2 }],
};

describe("buildGraphTextAlternative", () => {
  it("counts every drawn node by type, not just the ones the canvas labels", () => {
    const text = buildGraphTextAlternative(model(), SUMMARY);
    expect(text.nodeTypes).toEqual(
      expect.arrayContaining([
        { nodeType: "server", count: 2 },
        { nodeType: "vulnerability", count: 2 },
        { nodeType: "agent", count: 1 },
        { nodeType: "credential", count: 1 },
      ]),
    );
    expect(text.nodeTypes.reduce((sum, item) => sum + item.count, 0)).toBe(7);
  });

  it("counts every drawn relationship by kind", () => {
    const text = buildGraphTextAlternative(model(), SUMMARY);
    expect(text.relationships).toEqual([
      { relationship: "calls", count: 2 },
      { relationship: "has_finding", count: 2 },
      { relationship: "depends_on", count: 1 },
      { relationship: "exposes_cred", count: 1 },
    ]);
  });

  it("leads with the highest severity, then the most connected", () => {
    const text = buildGraphTextAlternative(model(), SUMMARY);
    expect(text.rows[0]).toMatchObject({
      label: "CVE-2026-1111",
      severity: "critical",
    });
    const labels = text.rows.map((row) => row.label);
    // requests 2.31.0 has 3 edges, payments-api 3, billing-api 1 — the
    // unrated nodes rank among themselves by how connected they are.
    expect(labels.indexOf("payments-api")).toBeLessThan(
      labels.indexOf("billing-api"),
    );
  });

  it("reports connection counts from the edges actually drawn", () => {
    const text = buildGraphTextAlternative(model(), SUMMARY);
    const byLabel = new Map(text.rows.map((row) => [row.label, row]));
    expect(byLabel.get("payments-api")!.connections).toBe(3);
    expect(byLabel.get("billing-api")!.connections).toBe(1);
    expect(byLabel.get("STRIPE_KEY")!.connections).toBe(1);
  });

  it("names both endpoints and the relationship in every connection sentence", () => {
    const text = buildGraphTextAlternative(model(), SUMMARY);
    expect(text.connections).toContain(
      "payments-api exposes cred STRIPE_KEY",
    );
    expect(text.connections).toContain("checkout-agent calls payments-api");
  });

  it("states the omitted counts instead of silently truncating", () => {
    const text = buildGraphTextAlternative(
      model({ sourceNodeCount: 12_400, sourceEdgeCount: 41_000, omittedNodeCount: 12_393, omittedEdgeCount: 40_994 }),
      { ...SUMMARY, nodes: 12_400, edges: 41_000 },
      { maxRows: 3, maxConnections: 2 },
    );
    expect(text.headline).toContain("12,400");
    expect(text.headline).toContain("41,000");
    expect(text.rows).toHaveLength(3);
    expect(text.rowsNote).toContain("3");
    expect(text.rowsNote).toContain("7");
    expect(text.connections).toHaveLength(2);
    expect(text.connectionsNote).toContain("6");
  });

  it("survives an empty graph without inventing content", () => {
    const empty = buildGraphTextAlternative(
      model({ nodes: [], edges: [], nodeById: new Map(), sourceNodeCount: 0, sourceEdgeCount: 0 }),
      { ...SUMMARY, nodes: 0, edges: 0, findings: 0, criticalFindings: 0, credentials: 0, tools: 0, topRelationships: [] },
    );
    expect(empty.rows).toEqual([]);
    expect(empty.connections).toEqual([]);
    expect(empty.headline).toContain("0 nodes");
  });
});

describe("<GraphTextAlternative>", () => {
  it("keeps parallel relationship sentences keyed independently", () => {
    const first = edge("a1", "s1", "calls");
    const second = { ...edge("a1", "s1", "calls"), id: "a1->s1:duplicate" };
    const consoleError = vi.spyOn(console, "error").mockImplementation(() => {});

    render(
      <GraphTextAlternative
        id="overview-text"
        renderer="2D canvas overview"
        model={model({ edges: [first, second] })}
        summary={SUMMARY}
      />,
    );

    expect(
      consoleError.mock.calls.some((args) =>
        args.map(String).join(" ").includes("same key"),
      ),
    ).toBe(false);
    consoleError.mockRestore();
  });

  it("exposes the graph as a named region a screen reader can reach", () => {
    render(
      <GraphTextAlternative
        id="overview-text"
        renderer="2D canvas overview"
        model={model()}
        summary={SUMMARY}
      />,
    );
    const region = screen.getByRole("region", {
      name: /graph contents, text equivalent/i,
    });
    expect(region).toBeInTheDocument();
  });

  it("renders every node as a real table row with its type and severity", () => {
    render(
      <GraphTextAlternative
        id="overview-text"
        renderer="2D canvas overview"
        model={model()}
        summary={SUMMARY}
      />,
    );
    const table = screen.getByRole("table", { name: /nodes drawn/i });
    const rows = within(table).getAllByRole("row");
    // 7 nodes + the header row.
    expect(rows).toHaveLength(8);
    const critical = within(table).getByRole("row", { name: /CVE-2026-1111/ });
    expect(critical).toHaveTextContent("vulnerability");
    expect(critical).toHaveTextContent("critical");
  });

  it("spells out the relationships, so the edges are not canvas-only either", () => {
    render(
      <GraphTextAlternative
        id="overview-text"
        renderer="2D canvas overview"
        model={model()}
        summary={SUMMARY}
      />,
    );
    expect(
      screen.getByText("payments-api depends on requests 2.31.0"),
    ).toBeInTheDocument();
  });

  it("does not take up any of the canvas it describes", () => {
    const { container } = render(
      <GraphTextAlternative
        id="overview-text"
        renderer="2D canvas overview"
        model={model()}
        summary={SUMMARY}
      />,
    );
    expect(container.firstElementChild).toHaveClass("sr-only");
  });
});
