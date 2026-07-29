import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { GraphEntityDrawer } from "@/components/graph-entity-drawer";
import type { LineageNodeData } from "@/components/lineage-nodes";

function node(nodeType: string, label = "checkout-agent"): LineageNodeData {
  return { label, nodeType, severity: "none" } as unknown as LineageNodeData;
}

const noop = () => {};

describe("graph quarantine action", () => {
  it("offers containment on an agent node", () => {
    render(
      <GraphEntityDrawer data={node("agent")} onClose={noop} enrich={false} onQuarantine={noop} />,
    );
    expect(screen.getByTestId("graph-quarantine-agent")).toHaveTextContent("Quarantine agent");
  });

  it("is not offered on non-agent nodes", () => {
    render(
      <GraphEntityDrawer data={node("package", "left-pad")} onClose={noop} enrich={false} onQuarantine={noop} />,
    );
    expect(screen.queryByTestId("graph-quarantine-agent")).toBeNull();
  });

  it("is absent entirely when no handler is supplied", () => {
    render(<GraphEntityDrawer data={node("agent")} onClose={noop} enrich={false} />);
    expect(screen.queryByTestId("graph-quarantine-agent")).toBeNull();
  });

  it("requires a second confirming click before it commits", () => {
    const onQuarantine = vi.fn();
    render(
      <GraphEntityDrawer
        data={node("agent")}
        onClose={noop}
        enrich={false}
        onQuarantine={onQuarantine}
        quarantineState="confirming"
        quarantineMessage="Blocks every tool call"
      />,
    );
    expect(screen.getByTestId("graph-quarantine-agent")).toHaveTextContent("Confirm");
    expect(screen.getByText(/Blocks every tool call/)).toBeTruthy();
  });

  it("disables the control while pending and once done", () => {
    const { rerender } = render(
      <GraphEntityDrawer
        data={node("agent")}
        onClose={noop}
        enrich={false}
        onQuarantine={noop}
        quarantineState="pending"
      />,
    );
    expect(screen.getByTestId("graph-quarantine-agent")).toBeDisabled();

    rerender(
      <GraphEntityDrawer
        data={node("agent")}
        onClose={noop}
        enrich={false}
        onQuarantine={noop}
        quarantineState="done"
      />,
    );
    expect(screen.getByTestId("graph-quarantine-agent")).toBeDisabled();
  });

  it("surfaces a failure instead of silently doing nothing", () => {
    render(
      <GraphEntityDrawer
        data={node("agent")}
        onClose={noop}
        enrich={false}
        onQuarantine={noop}
        quarantineState="error"
        quarantineMessage='"checkout-agent" is not registered in the fleet roster, so it cannot be quarantined.'
      />,
    );
    expect(screen.getByText(/not registered in the fleet roster/)).toBeTruthy();
  });
});
