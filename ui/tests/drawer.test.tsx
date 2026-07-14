import { fireEvent, render, screen } from "@testing-library/react";
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
});
