import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { useState } from "react";

import { CommandPalette, type CommandPaletteAction } from "@/components/command-palette";

vi.mock("next/link", () => ({
  default: ({ href, children, ...rest }: { href: string; children: React.ReactNode; [key: string]: unknown }) => (
    <a href={href} {...rest}>
      {children}
    </a>
  ),
}));

function Icon() {
  return <span aria-hidden="true" />;
}

function Harness({ actions = [], onClose = vi.fn() }: { actions?: CommandPaletteAction[]; onClose?: () => void }) {
  const [query, setQuery] = useState("");
  return (
    <CommandPalette
      query={query}
      setQuery={setQuery}
      onClose={onClose}
      actions={actions}
      links={[{ href: "/findings", label: "Findings", group: "Scan", icon: Icon }]}
    />
  );
}

describe("CommandPalette", () => {
  it("shows page links and command actions", () => {
    render(<Harness actions={[{ id: "refresh", label: "Refresh current view", group: "Action", icon: Icon, run: vi.fn() }]} />);

    expect(screen.getByRole("link", { name: /findings/i })).toHaveAttribute("href", "/findings");
    expect(screen.getByRole("button", { name: /refresh current view/i })).toBeInTheDocument();
  });

  it("filters actions by keyword", () => {
    render(
      <Harness
        actions={[
          { id: "copy", label: "Copy current URL", group: "Action", icon: Icon, keywords: ["share"], run: vi.fn() },
        ]}
      />
    );

    fireEvent.change(screen.getByPlaceholderText("Search pages and commands..."), { target: { value: "share" } });

    expect(screen.getByRole("button", { name: /copy current url/i })).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /findings/i })).not.toBeInTheDocument();
  });

  it("runs an action and closes the palette", () => {
    const run = vi.fn();
    const onClose = vi.fn();
    render(<Harness onClose={onClose} actions={[{ id: "focus", label: "Focus main content", group: "Action", icon: Icon, run }]} />);

    fireEvent.click(screen.getByRole("button", { name: /focus main content/i }));

    expect(run).toHaveBeenCalledTimes(1);
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("closes on Escape", () => {
    const onClose = vi.fn();
    render(<Harness onClose={onClose} />);

    fireEvent.keyDown(window, { key: "Escape" });

    expect(onClose).toHaveBeenCalledTimes(1);
  });
});
