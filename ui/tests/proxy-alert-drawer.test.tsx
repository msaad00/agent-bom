import { describe, expect, it, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";

import { ProxyAlertDrawer } from "@/components/proxy-alert-drawer";
import type { ProxyAlert } from "@/lib/api";

/**
 * The alert drawer rendered every field as its own full-width bordered card:
 * nine boxes, one short value each, ~90px of vertical per word. Five of them
 * repeated facts already shown in the header subtitle.
 *
 * A drawer is a reading surface. It has to be scannable at a glance and sized
 * to the content, not a mile-long column at a fixed 32rem.
 */

const alert = {
  severity: "high",
  detector: "replay",
  tool_name: "github-server.push_files",
  event_type: "tool call blocked",
  decision: "deny",
  reason_code: "replay_blocked",
  session_id: "demo-estate",
  source_id: "demo-estate-gateway",
  agent_name: "shadow-agent (unregistered)",
  ts: "2026-08-07T00:29:46Z",
} as unknown as ProxyAlert;

beforeEach(() => {
  // jsdom here has no working Storage; mirror the stub the graph tests use.
  const values = new Map<string, string>();
  Object.defineProperty(window, "localStorage", {
    configurable: true,
    value: {
      get length() { return values.size; },
      clear: () => values.clear(),
      getItem: (key: string) => values.get(key) ?? null,
      key: (index: number) => [...values.keys()][index] ?? null,
      removeItem: (key: string) => { values.delete(key); },
      setItem: (key: string, value: string) => { values.set(key, value); },
    } satisfies Storage,
  });
});

describe("ProxyAlertDrawer", () => {
  it("moves focus into the modal and restores the trigger on close", async () => {
    const trigger = document.createElement("button");
    document.body.appendChild(trigger);
    trigger.focus();

    const { unmount } = render(<ProxyAlertDrawer alert={alert} onClose={() => {}} />);
    const panel = screen.getByRole("dialog").querySelector("aside");
    expect(panel).not.toBeNull();
    await waitFor(() => expect(panel).toHaveFocus());

    unmount();
    expect(trigger).toHaveFocus();
    trigger.remove();
  });

  it("lays fields out in a grid rather than one card per value", () => {
    render(<ProxyAlertDrawer alert={alert} onClose={() => {}} />);

    const list = screen.getByTestId("proxy-alert-fields");
    expect(list.className).toMatch(/grid/);
    // Two columns, so nine short values cost roughly five rows, not nine.
    expect(list.className).toMatch(/grid-cols-2/);
  });

  it("exposes a width control so the drawer fits its content", () => {
    render(<ProxyAlertDrawer alert={alert} onClose={() => {}} />);

    expect(screen.getByRole("separator", { name: /resize/i })).toBeInTheDocument();
  });

  it("remembers a resized width across mounts", () => {
    const { unmount } = render(<ProxyAlertDrawer alert={alert} onClose={() => {}} />);
    const handle = screen.getByRole("separator", { name: /resize/i });

    // Keyboard resize keeps the handle usable without a pointer.
    fireEvent.keyDown(handle, { key: "ArrowLeft" });
    unmount();

    render(<ProxyAlertDrawer alert={alert} onClose={() => {}} />);
    expect(window.localStorage.getItem("agent-bom-drawer-width")).toBeTruthy();
  });

  it("still shows every field value", () => {
    render(<ProxyAlertDrawer alert={alert} onClose={() => {}} />);

    // Density must not cost information.
    expect(screen.getByText("demo-estate-gateway")).toBeInTheDocument();
    expect(screen.getByText("demo-estate")).toBeInTheDocument();
  });
});
