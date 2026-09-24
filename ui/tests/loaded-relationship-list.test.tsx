import { fireEvent, render, screen } from "@testing-library/react";
import { expect, it, vi } from "vitest";
import { LoadedRelationshipList } from "@/components/persisted-context-view";
import type { UnifiedEdge } from "@/lib/graph-schema";

vi.mock("@xyflow/react", () => ({}));

it("exposes relationships beyond the initial page and collapses without changing evidence", () => {
  const edges = Array.from({ length: 51 }, (_, i) => ({ source: "agent:one", target: `server:${i}`, relationship: "uses", direction: "directed", evidence: {} } as UnifiedEdge));
  const onSelect = vi.fn();
  render(<LoadedRelationshipList nodeId="agent:one" incident={edges} label={id => id} onSelect={onSelect} />);
  expect(screen.getByRole("status")).toHaveTextContent("Showing 24 of 51 loaded relationships");
  expect(screen.queryByText("server:24")).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Show 24 more relationships" }));
  expect(screen.getByRole("status")).toHaveTextContent("Showing 48 of 51");
  fireEvent.click(screen.getByRole("button", { name: "Show 3 more relationships" }));
  fireEvent.click(screen.getByRole("button", { name: /server:50/ }));
  expect(onSelect).toHaveBeenCalledWith(JSON.stringify(["agent:one", "server:50", "uses"]));
  fireEvent.click(screen.getByRole("button", { name: "Show fewer relationships" }));
  expect(screen.getByRole("status")).toHaveTextContent("Showing 24 of 51");
  expect(edges).toHaveLength(51);
});
