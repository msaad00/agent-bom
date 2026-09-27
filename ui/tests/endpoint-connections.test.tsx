import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { EndpointConnectionsPanel } from "@/components/endpoint-connections";

const mock = vi.hoisted(() => ({
  endpointConnections: vi.fn(),
  createEndpointConnection: vi.fn(),
  syncEndpointConnection: vi.fn(),
  endpointDevices: vi.fn(),
  updateEndpointConnection: vi.fn(),
}));
vi.mock("@/lib/api", () => ({ api: mock }));
const connection = {
  id: "c",
  name: "Fleet",
  provider: "crowdstrike",
  enabled: true,
};
const sync = {
  status: "partial",
  device_count: 1,
  expected_count: 3,
  gap: "permission_denied",
  updated_at: "2026-09-27T00:00:00Z",
};
beforeEach(() => {
  vi.clearAllMocks();
  mock.endpointConnections.mockResolvedValue({
    connections: [{ connection, sync }],
  });
});

describe("Endpoint connections", () => {
  it("shows partial denominators and forbids viewer mutations", async () => {
    render(<EndpointConnectionsPanel canManage={false} />);
    expect(
      await screen.findByText("partial · 1 / 3 devices"),
    ).toBeInTheDocument();
    expect(screen.getByText(/permission denied/)).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Resume sync" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Connect endpoint provider" }),
    ).not.toBeInTheDocument();
  });
  it("renders healthy sensor separately from unknown compliance", async () => {
    mock.endpointDevices.mockResolvedValue({
      sync,
      offset: 0,
      limit: 25,
      devices: [
        {
          device_id: "scoped",
          hostname: "Laptop",
          managed: true,
          compliant: null,
          disk_encrypted: null,
          last_seen: "",
          observed_at: "now",
          attributes: { freshness: "fresh", sensor_healthy: true },
        },
      ],
    });
    render(<EndpointConnectionsPanel canManage />);
    fireEvent.click(
      await screen.findByRole("button", { name: "Inspect evidence" }),
    );
    expect(await screen.findByText("Laptop")).toBeInTheDocument();
    expect(
      screen.getByRole("dialog", { name: "Endpoint device evidence" }),
    ).toBeInTheDocument();
    expect(
      screen.queryByText("Agent associations · Laptop"),
    ).not.toBeInTheDocument();
    expect(
      screen.getByRole("tab", { name: "Associations" }),
    ).toBeInTheDocument();
    expect(screen.getAllByText("Unknown")).toHaveLength(2);
    expect(
      screen.getByRole("columnheader", { name: "Sensor healthy" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("columnheader", { name: "Compliant" }),
    ).toBeInTheDocument();
  });
  it("persists write-only credentials and clears the password input", async () => {
    mock.createEndpointConnection.mockResolvedValue(connection);
    mock.endpointDevices.mockResolvedValue({
      sync: null,
      devices: [],
      offset: 0,
      limit: 25,
    });
    render(<EndpointConnectionsPanel canManage />);
    fireEvent.click(
      screen.getByRole("button", { name: "Connect endpoint provider" }),
    );
    fireEvent.change(screen.getByLabelText("Connection name"), {
      target: { value: "Macs" },
    });
    fireEvent.change(screen.getByLabelText("Jamf instance URL"), {
      target: { value: "https://acme.jamfcloud.com" },
    });
    fireEvent.change(screen.getByLabelText("Client ID"), {
      target: { value: "id" },
    });
    fireEvent.change(screen.getByLabelText("Client secret"), {
      target: { value: "secret" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save connection" }));
    await waitFor(() =>
      expect(mock.createEndpointConnection).toHaveBeenCalledWith(
        expect.objectContaining({
          provider: "jamf",
          account_id: "acme.jamfcloud.com",
          client_secret: "secret",
        }),
      ),
    );
    await waitFor(() =>
      expect(screen.queryByLabelText("Client secret")).not.toBeInTheDocument(),
    );
    expect(mock.syncEndpointConnection).not.toHaveBeenCalled();
  });
  it("does not fetch private records in the demo", () => {
    render(<EndpointConnectionsPanel canManage demo />);
    expect(mock.endpointConnections).not.toHaveBeenCalled();
    expect(
      screen.queryByRole("button", { name: "Connect endpoint provider" }),
    ).not.toBeInTheDocument();
  });
  it("ignores a late device response after selecting another connection", async () => {
    mock.endpointConnections.mockResolvedValue({
      connections: [
        { connection, sync },
        { connection: { ...connection, id: "other", name: "Other" }, sync },
      ],
    });
    let resolveFirst: (value: unknown) => void = () => {};
    mock.endpointDevices.mockImplementation((id: string) =>
      id === "c"
        ? new Promise((resolve) => {
            resolveFirst = resolve;
          })
        : Promise.resolve({ sync: null, devices: [], offset: 0, limit: 25 }),
    );
    render(<EndpointConnectionsPanel canManage />);
    const buttons = await screen.findAllByRole("button", {
      name: "Inspect evidence",
    });
    fireEvent.click(buttons[0]!);
    fireEvent.click(buttons[1]!);
    await screen.findByText("No device evidence in this collection.");
    resolveFirst({
      sync: null,
      devices: [{ device_id: "old", hostname: "Stale response" }],
      offset: 0,
      limit: 25,
    });
    await waitFor(() =>
      expect(screen.queryByText("Stale response")).not.toBeInTheDocument(),
    );
  });
});
