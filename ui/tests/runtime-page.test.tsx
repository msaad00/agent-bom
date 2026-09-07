import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import RuntimePage from "@/app/runtime/page";

const { proxyMock, gatewayMock, replaceMock, navigation } = vi.hoisted(() => ({
  navigation: { query: "tab=proxy" },
  replaceMock: vi.fn(),
  proxyMock: vi.fn(() => <div>proxy surface</div>),
  gatewayMock: vi.fn(() => <div>gateway surface</div>),
}));

vi.mock("next/navigation", () => ({
  useRouter: () => ({ replace: replaceMock }),
  useSearchParams: () => new URLSearchParams(navigation.query),
}));

vi.mock("@/app/proxy/ProxyDashboard", () => ({
  default: () => proxyMock(),
}));

vi.mock("@/app/gateway/GatewayDashboard", () => ({
  default: () => gatewayMock(),
}));

describe("RuntimePage", () => {
  beforeEach(() => {
    navigation.query = "tab=proxy";
    replaceMock.mockClear();
    proxyMock.mockClear();
    gatewayMock.mockClear();
  });

  it("selects Gateway from its explicit setup URL and connects tabs to the panel", () => {
    navigation.query = "tab=gateway";
    render(<RuntimePage />);
    const tab = screen.getByRole("tab", { name: "Gateway" });
    const panel = screen.getByRole("tabpanel", { name: "Gateway" });
    expect(tab).toHaveAttribute("aria-selected", "true");
    expect(tab).toHaveAttribute("aria-controls", panel.id);
    expect(panel).toHaveAttribute("aria-labelledby", tab.id);
    for (const control of screen.getAllByRole("tab")) {
      const controlled = document.getElementById(control.getAttribute("aria-controls")!);
      expect(controlled).not.toBeNull();
      expect(controlled).toHaveAttribute("aria-labelledby", control.id);
    }
    expect(screen.getByText("gateway surface")).toBeInTheDocument();
  });

  it.each([
    ["proxy", "ArrowRight", "gateway"], ["proxy", "ArrowLeft", "gateway"],
    ["gateway", "ArrowRight", "proxy"], ["gateway", "ArrowLeft", "proxy"],
    ["gateway", "Home", "proxy"], ["proxy", "End", "gateway"],
  ])("navigates %s with %s to %s without losing focus", (from, key, next) => {
    navigation.query = `tab=${from}`;
    const view = render(<RuntimePage />);
    const fromTab = screen.getByRole("tab", { name: from === "proxy" ? "Proxy" : "Gateway" });
    fromTab.focus();
    fireEvent.keyDown(fromTab, { key });
    expect(replaceMock).toHaveBeenCalledWith(`/runtime?tab=${next}`);
    navigation.query = `tab=${next}`;
    view.rerender(<RuntimePage />);
    const nextTab = screen.getByRole("tab", { name: next === "proxy" ? "Proxy" : "Gateway" });
    expect(nextTab).toHaveFocus();
    expect(nextTab).toHaveAttribute("tabindex", "0");
    expect(nextTab).toHaveAttribute("aria-selected", "true");
    expect(fromTab).toHaveAttribute("tabindex", "-1");
  });

  it("renders the unified runtime shell with embedded proxy content", async () => {
    render(<RuntimePage />);

    expect(await screen.findByRole("heading", { name: "Runtime" })).toBeInTheDocument();
    expect(screen.getByText("proxy surface")).toBeInTheDocument();
    expect(proxyMock).toHaveBeenCalled();
    expect(gatewayMock).not.toHaveBeenCalled();
  });
});
