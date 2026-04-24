import { render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import GatewayPage from "@/app/gateway/page";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    listGatewayPolicies: vi.fn(),
    getGatewayStats: vi.fn(),
    listGatewayAudit: vi.fn(),
    createGatewayPolicy: vi.fn(),
    deleteGatewayPolicy: vi.fn(),
    updateGatewayPolicy: vi.fn(),
    evaluateGateway: vi.fn(),
  },
}));

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    api: apiMock,
  };
});

describe("GatewayPage", () => {
  beforeEach(() => {
    Object.values(apiMock).forEach((mockFn) => mockFn.mockReset());
    apiMock.listGatewayPolicies.mockResolvedValue({ policies: [], count: 0 });
    apiMock.listGatewayAudit.mockResolvedValue({ entries: [], count: 0 });
    apiMock.getGatewayStats.mockResolvedValue({
      total_policies: 2,
      enforce_count: 1,
      audit_count: 1,
      enabled_count: 2,
      total_rules: 3,
      audit_entries: 4,
      blocked_count: 2,
      alerted_count: 1,
      policy_runtime: {
        source: "control_plane",
        source_kind: "policy_store",
        enabled_policies: 2,
        rollout_mode: "mixed",
        summary: "Mixed rollout: some rules block while others remain advisory.",
        total_rules: 3,
        blocking_rules: 1,
        advisory_rules: 2,
        allowlist_rules: 0,
        default_deny_rules: 0,
        read_only_rules: 0,
        secret_path_rules: 1,
        unknown_egress_rules: 1,
        denied_tool_classes: ["network"],
        blocks_requests: true,
        advisory_only: false,
        default_deny: false,
        protects_secret_paths: true,
        restricts_unknown_egress: true,
      },
    });
  });

  it("surfaces runtime rollout posture and protective controls", async () => {
    render(<GatewayPage />);

    await waitFor(() => expect(screen.getByText("Runtime posture")).toBeInTheDocument());
    expect(screen.getByText("mixed")).toBeInTheDocument();
    expect(screen.getByText("Mixed rollout: some rules block while others remain advisory.")).toBeInTheDocument();
    expect(screen.getByText("Enabled policies")).toBeInTheDocument();
    expect(screen.getByText("Secret path guard")).toBeInTheDocument();
    expect(screen.getByText("Unknown egress guard")).toBeInTheDocument();
    expect(screen.getByText("Denied tool classes: network")).toBeInTheDocument();
  });
});
