import { afterEach, expect, it, vi } from "vitest";
import { act, fireEvent, render, screen } from "@testing-library/react";
import type { Node } from "@xyflow/react";
import { useContextLayout } from "@/lib/use-context-layout";

let resize: () => void;
let width = 1100, height = 250;
const nodes: Node[] = Array.from({ length: 3 }, (_, i) => ({ id: String(i), data: {}, position: { x: 0, y: 0 } }));
const edges = [{ id: "a", source: "0", target: "1" }, { id: "b", source: "1", target: "2" }];
function Harness({ scope = "first", expanded = false }: { scope?: string; expanded?: boolean }) {
  const layout = useContextLayout(expanded ? [...nodes, { id: "3", data: {}, position: { x: 0, y: 0 } }] : nodes, edges, false, scope, true);
  return <div ref={layout.canvasRef}><output>{layout.direction}</output>
    <button onClick={() => layout.selectMode("horizontal")}>Horizontal</button>
    <button onClick={() => layout.selectMode("vertical")}>Vertical</button>
    <button onClick={() => layout.selectMode("auto")}>Auto</button></div>;
}
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });
it("holds Auto during expansion/resize and honors manual overrides until Auto is selected", () => {
  vi.spyOn(HTMLElement.prototype, "getBoundingClientRect").mockImplementation(() => ({ width, height, x: 0, y: 0, top: 0, left: 0, right: width, bottom: height, toJSON() {} }));
  vi.stubGlobal("ResizeObserver", class { constructor(callback: () => void) { resize = callback; } observe() {} disconnect() {} });
  const view = render(<Harness />);
  expect(screen.getByRole("status")).toHaveTextContent("LR");
  width = 340; height = 650;
  act(() => resize());
  view.rerender(<Harness expanded />);
  expect(screen.getByRole("status")).toHaveTextContent("LR");
  fireEvent.click(screen.getByText("Vertical"));
  expect(screen.getByRole("status")).toHaveTextContent("TB");
  view.rerender(<Harness scope="new" />);
  expect(screen.getByRole("status")).toHaveTextContent("TB");
  fireEvent.click(screen.getByText("Horizontal"));
  expect(screen.getByRole("status")).toHaveTextContent("LR");
  // The real observer updates the canvas; Auto then compares fresh bounds.
  act(() => resize());
  fireEvent.click(screen.getByText("Auto"));
  expect(screen.getByRole("status")).toHaveTextContent("TB");
});
