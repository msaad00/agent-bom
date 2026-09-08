import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { Agent } from "@/lib/api";
import { AgentTopology } from "@/components/agent-topology";
vi.mock("@xyflow/react", () => ({
  ReactFlow: ({ nodes }: { nodes: { id: string }[] }) => <div data-testid="canvas">{nodes.map(n => <span key={n.id}>{n.id}</span>)}</div>,
  ReactFlowProvider: ({ children }: { children: React.ReactNode }) => children,
  Background: () => null, Controls: () => null, Handle: () => null, Position: { Right: "right", Left: "left" },
  useReactFlow: () => ({ fitView: vi.fn(), getViewport: () => ({x:0,y:0,zoom:1}), setViewport: vi.fn() }),
}));
vi.mock("@/lib/use-dagre-lr", () => ({ useDagreLrLayout: (nodes: unknown[]) => ({ nodes, pending: false }) }));
vi.mock("@/lib/theme-mode", () => ({ useThemeMode: () => "light" }));
vi.mock("@/components/topology-detail-drawer", () => ({ TopologyDetailDrawer: ({ selection }: { selection: { name?: string } | null }) => selection ? <div>Selected {selection.name}</div> : null }));
const agents: Agent[] = [
 { name: "attention", agent_type: "custom", mcp_servers: [{ name: "private-api", credential_env_vars: ["API_TOKEN"], packages: [] }] },
 { name: "ordinary", agent_type: "custom", mcp_servers: [{ name: "docs", packages: [] }] },
 { name: "unlinked", agent_type: "custom", mcp_servers: [] },
];
describe("topology attention view", () => {
 it("filters a small mesh without inventing a risk path and restores all inventory", () => {
  render(<AgentTopology agents={agents} />);
  expect(screen.getByRole("button", { name: /Needs attention/ })).toHaveAttribute("aria-pressed", "true");
  expect(screen.getByTestId("canvas")).toHaveTextContent("agent-attention");
  expect(screen.getByTestId("canvas")).not.toHaveTextContent("agent-ordinary");
  expect(screen.queryByRole("button", { name: "Risk path" })).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: /Full mesh/ }));
  expect(screen.getByTestId("canvas")).toHaveTextContent("agent-ordinary");
  expect(screen.getByTestId("canvas")).not.toHaveTextContent("agent-unlinked");
  fireEvent.click(screen.getByRole("button", { name: "Inspect Unlinked" }));
  expect(screen.getByText("Selected unlinked")).toBeVisible();
 });
 it("shows an honest empty attention state with a full inventory action", () => {
  render(<AgentTopology agents={agents.slice(1)} />);
  expect(screen.getByText("No attention signals in this mesh")).toBeVisible();
  expect(screen.queryByTestId("canvas")).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: /Full mesh/ }));
  expect(screen.getByTestId("canvas")).toHaveTextContent("agent-ordinary");
 });
});
