import { act, fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { Drawer } from "@/components/drawer";

function renderDrawer(props: Partial<React.ComponentProps<typeof Drawer>> = {}) {
  const onClose = props.onClose ?? vi.fn();
  render(
    <Drawer open title="Finding detail" onClose={onClose} {...props}>
      <p>body</p>
    </Drawer>,
  );
  return { onClose };
}

describe("Drawer", () => {
  it("renders the overlay above the nav header so the Close X is clickable (#3966)", () => {
    renderDrawer();
    const dialog = screen.getByRole("dialog");
    // The fixed top nav is z-[60]; a lower drawer paints its Close X under the
    // nav band and makes it unclickable. The overlay must sit above the nav.
    expect(dialog.className).toContain("z-[80]");
    const overlayZ = 80;
    const navHeaderZ = 60;
    expect(overlayZ).toBeGreaterThan(navHeaderZ);
  });

  it("closes when the header Close button is clicked", () => {
    const { onClose } = renderDrawer();
    const closeButtons = screen.getAllByRole("button", { name: "Close" });
    // The last "Close" control is the header X (the first is the backdrop).
    fireEvent.click(closeButtons[closeButtons.length - 1]!);
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("closes on Escape for keyboard accessibility", () => {
    const { onClose } = renderDrawer();
    fireEvent.keyDown(document, { key: "Escape" });
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("renders nothing when closed", () => {
    renderDrawer({ open: false });
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("lets keyboard users resize the panel within the shared drawer contract", () => {
    renderDrawer();
    const handle = screen.getByRole("button", { name: "Resize drawer" });
    const panel = screen.getByRole("dialog").querySelector("aside");
    expect(panel).not.toBeNull();

    fireEvent.keyDown(handle, { key: "ArrowLeft" });
    expect(panel).toHaveStyle({ width: "688px" });
    fireEvent.keyDown(handle, { key: "Home" });
    expect(panel).toHaveStyle({ width: "360px" });
  });
});


it("keeps keyboard focus inside an open drawer when its close callback changes", () => {
  const frames = new Map<number, FrameRequestCallback>();
  let frameId = 0;
  vi.stubGlobal("requestAnimationFrame", (callback: FrameRequestCallback) => {
    frames.set(++frameId, callback);
    return frameId;
  });
  vi.stubGlobal("cancelAnimationFrame", (id: number) => frames.delete(id));
  const flushFrames = () => act(() => {
    const pending = [...frames.values()];
    frames.clear();
    pending.forEach(callback => callback(0));
  });
  const trigger = document.createElement("button");
  document.body.append(trigger);
  trigger.focus();
  const originalClose = vi.fn();
  const latestClose = vi.fn();
  const view = render(<Drawer open title="Columns" onClose={originalClose}><button>Move Observed up</button></Drawer>);
  try {
    flushFrames();
    const move = screen.getByRole("button", { name: "Move Observed up" });
    move.focus();
    view.rerender(<Drawer open title="Columns" onClose={latestClose}><button>Move Observed up</button></Drawer>);
    flushFrames();
    expect(move).toHaveFocus();
    fireEvent.keyDown(document, { key: "Escape" });
    expect(latestClose).toHaveBeenCalledOnce();
    expect(originalClose).not.toHaveBeenCalled();
    view.rerender(<Drawer open={false} title="Columns" onClose={latestClose}><button>Move Observed up</button></Drawer>);
    expect(trigger).toHaveFocus();
  } finally {
    view.unmount();
    trigger.remove();
    vi.unstubAllGlobals();
  }
});
