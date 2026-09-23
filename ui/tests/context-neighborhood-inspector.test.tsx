import { fireEvent, render, screen } from "@testing-library/react";
import { expect, it, vi } from "vitest";
import { ContextNeighborhoodInspector } from "@/components/context-neighborhood-inspector";
import type { ContextGraphNode } from "@/lib/context-graph";

it("finds an exact hidden ID without merging names and preserves canonical types", () => {
  const onFocus = vi.fn();
  const onExpandGroup = vi.fn();
  const nodes: ContextGraphNode[] = [{ id: "role:one", kind: "tool", entity_type: "iam_role", label: "Shared name", metadata: {} }];
  const allNodes = [...nodes, { ...nodes[0]!, id: "role:other" }];
  render(<ContextNeighborhoodInspector nodes={nodes} allNodes={allNodes} edges={[]} selectedId={null} selectedEdge={null} hiddenCount={1} hiddenGroups={[{ kind: "iam_role", count: 1, nodeIds: ["role:other"], nodeIdsTruncated: false }]} expansionLabel="root" canCollapse={false} onSelect={vi.fn()} onExpandGroup={onExpandGroup} onCollapse={vi.fn()} onFocus={onFocus} onClose={vi.fn()} />);
  expect(screen.getByText("iam role", { selector: "summary" })).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Show 1 iam role · 1 hidden" }));
  expect(onExpandGroup).toHaveBeenCalledWith("iam_role");
  fireEvent.change(screen.getByLabelText("Find loaded entity"), { target: { value: "role:other" } });
  fireEvent.click(screen.getByRole("button", { name: /Shared name.*role:other/ }));
  expect(onFocus).toHaveBeenCalledWith("role:other");
  expect(screen.getByText(/Shared infrastructure is not proof/)).toBeInTheDocument();
});
