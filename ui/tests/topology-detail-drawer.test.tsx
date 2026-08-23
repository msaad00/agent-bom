import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { TopologyDetailDrawer } from "@/components/topology-detail-drawer";
import type { Agent } from "@/lib/api";

const agents = [
  {
    name: "claude-desktop",
    agent_type: "claude",
    mcp_servers: [
      {
        name: "github",
        packages: [{ name: "octokit", version: "4.0.0", vulnerabilities: [] }],
        tools: [{ name: "create_issue" }],
        env: { GITHUB_TOKEN: "***" },
      },
    ],
  },
] as unknown as Agent[];

describe("TopologyDetailDrawer", () => {
  it("traps modal focus, closes on Escape, and restores the trigger", async () => {
    const onClose = vi.fn();
    const trigger = document.createElement("button");
    document.body.appendChild(trigger);
    trigger.focus();

    const { unmount } = render(
      <TopologyDetailDrawer
        agents={agents}
        selection={{ kind: "agent", name: "claude-desktop" }}
        onClose={onClose}
      />,
    );

    const panel = screen.getByRole("dialog").querySelector("aside");
    expect(panel).not.toBeNull();
    await waitFor(() => expect(panel).toHaveFocus());
    fireEvent.keyDown(document, { key: "Escape" });
    expect(onClose).toHaveBeenCalledTimes(1);

    unmount();
    expect(trigger).toHaveFocus();
    trigger.remove();
  });

  it("uses bounded tabs instead of one long detail column", () => {
    render(
      <TopologyDetailDrawer
        agents={agents}
        selection={{ kind: "agent", name: "claude-desktop" }}
        onClose={vi.fn()}
      />,
    );

    expect(screen.getByRole("tab", { name: "Overview" })).toHaveAttribute("aria-selected", "true");
    expect(screen.queryByText("github")).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("tab", { name: /Services/ }));
    expect(screen.getByRole("tabpanel")).toHaveAccessibleName("Services1");
    expect(screen.getByText("github")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("tab", { name: "Actions" }));
    expect(screen.getByRole("link", { name: /Open security graph/ })).toBeInTheDocument();
  });
});
