import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import RuntimePage from "@/app/runtime/page";

const { proxyMock, gatewayMock } = vi.hoisted(() => ({
  proxyMock: vi.fn(() => <div>proxy surface</div>),
  gatewayMock: vi.fn(() => <div>gateway surface</div>),
}));

vi.mock("next/navigation", () => ({
  useRouter: () => ({ replace: vi.fn() }),
  useSearchParams: () => new URLSearchParams("tab=proxy"),
}));

vi.mock("@/app/proxy/ProxyDashboard", () => ({
  default: () => proxyMock(),
}));

vi.mock("@/app/gateway/GatewayDashboard", () => ({
  default: () => gatewayMock(),
}));

describe("RuntimePage", () => {
  beforeEach(() => {
    proxyMock.mockClear();
    gatewayMock.mockClear();
  });

  it("renders the unified runtime shell with embedded proxy content", async () => {
    render(<RuntimePage />);

    expect(await screen.findByRole("heading", { name: "Runtime" })).toBeInTheDocument();
    expect(screen.getByText("proxy surface")).toBeInTheDocument();
    expect(proxyMock).toHaveBeenCalled();
    expect(gatewayMock).not.toHaveBeenCalled();
  });
});
