import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { DiffPreview } from "@/app/graph/graph-page-client";
import type { GraphDiffNode } from "@/lib/api-types";

// graph-page-client pulls next/navigation at module scope; stub the hooks so the
// import resolves even though DiffPreview itself never calls them.
vi.mock("next/navigation", () => ({
  useRouter: () => ({ replace: vi.fn(), push: vi.fn() }),
  usePathname: () => "/graph",
  useSearchParams: () => new URLSearchParams(),
}));

function node(overrides: Partial<GraphDiffNode>): GraphDiffNode {
  return {
    id: "node-1",
    entity_type: "package",
    label: "requests@2.0",
    status: "active",
    severity: "high",
    severity_id: 3,
    risk_score: 7.5,
    change_kind: "new",
    ...overrides,
  };
}

describe("DiffPreview", () => {
  it("renders rich node objects by label without throwing (was: objects as React child)", () => {
    // Regression: /v1/graph/diff returns node OBJECTS for added/removed; the old
    // type said string[] and rendered {item}, crashing the Lineage canvas with
    // "Objects are not valid as a React child".
    const nodes = [
      node({ id: "a", label: "requests@2.0" }),
      node({ id: "b", label: "flask@1.1" }),
    ];
    expect(() => render(<DiffPreview label="Added" items={nodes} />)).not.toThrow();
    expect(screen.getByText("requests@2.0")).toBeInTheDocument();
    expect(screen.getByText("flask@1.1")).toBeInTheDocument();
  });

  it("still renders bare node-id strings (the nodes_changed shape)", () => {
    render(<DiffPreview label="Changed" items={["graph:node:xyz", "graph:node:abc"]} />);
    expect(screen.getByText("graph:node:xyz")).toBeInTheDocument();
    expect(screen.getByText("graph:node:abc")).toBeInTheDocument();
  });

  it("falls back to id when a node has no label", () => {
    render(<DiffPreview label="Removed" items={[node({ id: "only-id", label: "" })]} />);
    expect(screen.getByText("only-id")).toBeInTheDocument();
  });
});
