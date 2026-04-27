/**
 * Smoke test for the row virtualization pattern that the agents page uses
 * to render large estates without mounting every card. Mirrors the
 * `useVirtualizer({ getScrollElement, estimateSize, overscan })` shape so
 * a regression in `@tanstack/react-virtual` or in the wiring would be
 * caught before the full agents page suite is touched.
 *
 * jsdom does not implement layout (`offsetHeight` is always 0), so we mock
 * the scroll-element rect via Object.defineProperty so the virtualizer
 * believes there is a 600px viewport and 800k px of content. Without that,
 * the virtualizer assumes everything fits and renders all rows — which is
 * not the regression we want to lock against.
 */

import { render, cleanup } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { useRef } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";

const ROW_HEIGHT = 80;
const TOTAL_ROWS = 1000;
const VIEWPORT_HEIGHT = 600;

function VirtualList({ count }: { count: number }) {
  const scrollRef = useRef<HTMLDivElement | null>(null);

  // jsdom's clientHeight returns 0 by default; pin a viewport size so the
  // virtualizer has a window to mount rows into.
  const setRef = (el: HTMLDivElement | null) => {
    scrollRef.current = el;
    if (el) {
      Object.defineProperty(el, "clientHeight", { configurable: true, value: VIEWPORT_HEIGHT });
      Object.defineProperty(el, "offsetHeight", { configurable: true, value: VIEWPORT_HEIGHT });
    }
  };

  const virtualizer = useVirtualizer({
    count,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 5,
  });

  return (
    <div ref={setRef} style={{ height: VIEWPORT_HEIGHT, overflow: "auto" }} data-testid="scroll-root">
      <div
        style={{ height: `${virtualizer.getTotalSize()}px`, position: "relative", width: "100%" }}
      >
        {virtualizer.getVirtualItems().map((item) => (
          <div
            key={item.index}
            data-testid="virtual-row"
            data-index={item.index}
            style={{
              position: "absolute",
              top: 0,
              left: 0,
              right: 0,
              transform: `translateY(${item.start}px)`,
              height: ROW_HEIGHT,
            }}
          >
            row {item.index}
          </div>
        ))}
      </div>
    </div>
  );
}

afterEach(() => {
  cleanup();
});

describe("agents-page row virtualization", () => {
  it("mounts only a window of rows for a large estate, not the full set", () => {
    const { getAllByTestId } = render(<VirtualList count={TOTAL_ROWS} />);

    // Viewport ~600px / ROW_HEIGHT 80px = ~8 visible rows + overscan 5 on
    // each side = ≤ ~18 mounted DOM rows, well under TOTAL_ROWS. The exact
    // count depends on overscan timing; lock the upper bound at 50 to give
    // the library room to evolve without flaking the test, while still
    // catching the regression where every row mounts.
    const mounted = getAllByTestId("virtual-row");

    expect(mounted.length).toBeLessThan(50);
    expect(mounted.length).toBeGreaterThan(0);
    expect(TOTAL_ROWS).toBeGreaterThan(mounted.length * 10);
  });

  it("renders nothing extra when the row count is zero", () => {
    const { queryAllByTestId } = render(<VirtualList count={0} />);
    expect(queryAllByTestId("virtual-row")).toHaveLength(0);
  });
});
