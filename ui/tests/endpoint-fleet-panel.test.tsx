import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { EndpointFleetPanel } from "@/components/endpoint-fleet-panel";

const { apiMock } = vi.hoisted(() => ({
  apiMock: { listFleetEndpoints: vi.fn() },
}));

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

function endpoint(id: string, system = "Darwin") {
  return {
    endpoint_id: id,
    tenant_id: "default",
    platform: { system, release: "25.6", machine: "arm64" },
    counts: { applications: 192, processes: 463, services: 518, listeners: 5, containers: 0, images: 20 },
    collector_status: { applications: "complete", processes: "complete", containers: "unavailable" },
    collector_messages: { containers: "Podman unavailable" },
    privacy: { process_arguments_collected: false, environment_values_collected: false },
    completeness: "partial",
    last_scan_id: "scan-a",
    observed_at: "2026-08-17T00:00:00Z",
    updated_at: "2026-08-17T00:00:00Z",
  };
}

describe("EndpointFleetPanel", () => {
  beforeEach(() => apiMock.listFleetEndpoints.mockReset());

  it("shows a compact, honest endpoint summary and partial collector reason", async () => {
    const user = userEvent.setup();
    apiMock.listFleetEndpoints.mockResolvedValue({
      endpoints: [endpoint("device-a")], count: 1, total: 1, limit: 25, offset: 0, has_more: false,
    });
    render(<EndpointFleetPanel />);

    expect(await screen.findByText("device-a")).toBeInTheDocument();
    expect(screen.getByText("192 apps")).toBeInTheDocument();
    expect(screen.getByText("463 processes")).toBeInTheDocument();
    const disclosure = screen.getByRole("button", { expanded: false });
    disclosure.focus();
    await user.keyboard("{Enter}");
    expect(disclosure).toHaveAttribute("aria-expanded", "true");
    expect(screen.getByText(/Podman unavailable/)).toBeInTheDocument();
    expect(screen.getByText(/arguments and environment values are not collected/i)).toBeInTheDocument();
  });

  it("filters and paginates without rendering an unbounded endpoint list", async () => {
    apiMock.listFleetEndpoints
      .mockResolvedValueOnce({ endpoints: Array.from({ length: 25 }, (_, index) => endpoint(`device-${index}`)), count: 25, total: 26, limit: 25, offset: 0, has_more: true })
      .mockResolvedValueOnce({ endpoints: [endpoint("device-25", "Windows")], count: 1, total: 26, limit: 25, offset: 25, has_more: false })
      .mockResolvedValueOnce({ endpoints: [endpoint("device-25", "Windows")], count: 1, total: 1, limit: 25, offset: 0, has_more: false });

    render(<EndpointFleetPanel />);
    expect(await screen.findAllByTestId("endpoint-row")).toHaveLength(25);
    fireEvent.click(screen.getByRole("button", { name: /Next/i }));
    await waitFor(() => expect(apiMock.listFleetEndpoints).toHaveBeenLastCalledWith(expect.objectContaining({ offset: 25 })));
    fireEvent.change(screen.getByLabelText("Filter endpoints"), { target: { value: "windows" } });
    await waitFor(() => expect(apiMock.listFleetEndpoints).toHaveBeenLastCalledWith(expect.objectContaining({ search: "windows", offset: 0 })));
  });
});
