import { render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import ProxyDashboard from "@/app/proxy/page";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    getProxyStatus: vi.fn(),
    getProxyAlerts: vi.fn(),
    getPostureCounts: vi.fn(),
  },
}));

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    api: apiMock,
  };
});

describe("Deployment surface lock cards", () => {
  beforeEach(() => {
    Object.values(apiMock).forEach((mockFn) => mockFn.mockReset());
    apiMock.getProxyStatus.mockResolvedValue({ status: "no_proxy_session" });
    apiMock.getProxyAlerts.mockResolvedValue({ alerts: [], count: 0 });
    apiMock.getPostureCounts.mockResolvedValue({
      has_proxy: false,
      has_gateway: false,
      has_traces: false,
      scan_count: 1,
      deployment_mode: "local",
    });
  });

  it("renders the guided proxy lock card when proxy telemetry is inactive", async () => {
    render(<ProxyDashboard />);

    await waitFor(() =>
      expect(screen.getByText("Proxy is not active in this deployment")).toBeInTheDocument(),
    );
    expect(screen.getByText("Runtime proxy audit or detector telemetry")).toBeInTheDocument();
    expect(screen.getByText("agent-bom proxy --help")).toBeInTheDocument();
  });
});
