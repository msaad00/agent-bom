import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import FleetPage from "@/app/fleet/page";

const { apiMock, authState } = vi.hoisted(() => ({
  apiMock: {
    listFleet: vi.fn(),
    getFleetStats: vi.fn(),
    syncFleet: vi.fn(),
    updateFleetState: vi.fn(),
    quarantineFleetAgent: vi.fn(),
  },
  authState: { canManageFleet: false },
}));

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return { ...actual, api: apiMock, formatDate: (value: string) => value };
});
vi.mock("@/components/auth-provider", () => ({
  useAuthState: () => ({
    session: { auth_required: true, role: authState.canManageFleet ? "admin" : "viewer" },
    hasCapability: (capability: string) => capability === "fleet.manage" && authState.canManageFleet,
  }),
}));
vi.mock("@/hooks/use-deployment-context", () => ({ useDeploymentContext: () => ({ counts: null }) }));
vi.mock("@/lib/theme-colors", () => ({
  useChartTheme: () => ({
    severity: { unrated: "#777" },
    status: { warn: "#f90", success: "#0a0", danger: "#d00" },
    text: "#aaa",
    border: "#444",
    tooltip: { bg: "#111", border: "#444", text: "#fff" },
  }),
}));
vi.mock("@/components/endpoint-fleet-panel", () => ({ EndpointFleetPanel: () => <div /> }));
vi.mock("recharts", () => ({
  ResponsiveContainer: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
  BarChart: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
  Bar: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
  XAxis: () => null,
  YAxis: () => null,
  Tooltip: () => null,
  Cell: () => null,
}));

const AGENT = {
  agent_id: "agent-1",
  name: "Developer laptop",
  agent_type: "desktop",
  lifecycle_state: "discovered",
  trust_score: 42,
  trust_factors: {},
  server_count: 1,
  package_count: 2,
  credential_count: 0,
  vuln_count: 1,
  owner: "platform",
  environment: "dev",
  last_discovery: "2026-08-18T00:00:00Z",
  config_path: null,
};

describe("FleetPage protected actions", () => {
  beforeEach(() => {
    authState.canManageFleet = false;
    Object.values(apiMock).forEach((mock) => mock.mockReset());
    apiMock.listFleet.mockResolvedValue({ agents: [AGENT], total: 1 });
    apiMock.getFleetStats.mockResolvedValue({
      total: 1,
      by_state: { discovered: 1 },
      low_trust_count: 1,
      avg_trust_score: 42,
    });
  });

  it("keeps sync, lifecycle, and quarantine controls disabled for viewers", async () => {
    render(<FleetPage />);
    expect(screen.getByRole("button", { name: "Sync Now" })).toBeDisabled();
    const row = await screen.findByRole("button", { name: /Developer laptop/ });
    fireEvent.click(row);
    await waitFor(() => expect(screen.getByRole("button", { name: "Pending Review" })).toBeDisabled());
    expect(screen.getByTestId("fleet-quarantine-deny")).toBeDisabled();
  });
});
