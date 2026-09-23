import { fireEvent, render, screen } from "@testing-library/react";
import { expect, it, vi } from "vitest";
import { LateralPanel } from "@/components/context-lens-view";
import { lateralPathKey, type LateralPath } from "@/lib/context-graph";

it("selects a lower-ranked recorded path and exposes more paths without an unbounded initial list", () => {
  const paths: LateralPath[] = Array.from({ length: 7 }, (_, i) => ({
    source: "agent:desktop", target: `server:${i}`, hops: ["agent:desktop", `server:${i}`], edges: [],
    composite_risk: 9 - i, summary: `Path ${i}`, credential_exposure: [], tool_exposure: [], vuln_ids: [],
  }));
  const onSelectPath = vi.fn();
  render(<LateralPanel paths={paths} risks={[]} selectedAgent="desktop" pathFocusActive focusedPathKey={lateralPathKey(paths[1]!)} onSelectPath={onSelectPath} agents={[]} />);
  const buttons = screen.getAllByRole("button", { name: /Inspect path:/ });
  expect(buttons).toHaveLength(5);
  expect(buttons[1]).toHaveAttribute("aria-pressed", "true");
  expect(buttons[0]).toHaveAttribute("aria-pressed", "false");
  fireEvent.click(buttons[2]!);
  expect(onSelectPath).toHaveBeenCalledWith(paths[2]);
  fireEvent.click(screen.getByRole("button", { name: "Show more paths" }));
  expect(screen.getAllByRole("button", { name: /Inspect path:/ })).toHaveLength(7);
  expect(screen.queryByRole("button", { name: "Show more paths" })).toBeNull();
});
