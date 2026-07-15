import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { DeployGatePanel } from "@/components/deploy-gate-panel";
import type { DeployDecision, GraphDeployDecisionResponse } from "@/lib/api";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    graphShouldIDeploy: vi.fn(),
  },
}));

vi.mock("@/lib/api", () => ({ api: apiMock }));

function decisionResponse(decision: DeployDecision, maxRisk: number): GraphDeployDecisionResponse {
  return {
    schema_version: "v1",
    tool: "should_i_deploy",
    tenant_id: "default",
    scan_id: "scan-1",
    candidate: { value: "agent:claude-desktop" },
    decision,
    maxRisk,
    thresholds: { warnRisk: 40, blockRisk: 80 },
    reasons: [`Top matched exposure path risk is ${maxRisk} for agent:claude-desktop.`],
    matchedPathCount: 1,
    matchedPaths: [
      {
        id: "p1",
        label: "claude-desktop → left-pad → CVE-2024-1",
        summary: "",
        riskScore: maxRisk,
        severity: "high",
        source: { id: "agent:claude-desktop", label: "claude-desktop", role: "agent" },
        target: { id: "cve", label: "CVE-2024-1", role: "finding" },
        hops: [],
        relationships: [],
        nodeIds: [],
        edgeIds: [],
        findings: ["CVE-2024-1"],
        reachableTools: [],
        exposedCredentials: [],
      },
    ],
  };
}

beforeEach(() => {
  apiMock.graphShouldIDeploy.mockReset();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("DeployGatePanel", () => {
  it("calls the deploy-gate endpoint with the candidate and scan id and renders GO", async () => {
    apiMock.graphShouldIDeploy.mockResolvedValue(decisionResponse("allow", 12));
    render(<DeployGatePanel scanId="scan-1" />);

    fireEvent.change(screen.getByLabelText("Deploy candidate"), {
      target: { value: "agent:claude-desktop" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Run gate" }));

    await waitFor(() =>
      expect(apiMock.graphShouldIDeploy).toHaveBeenCalledWith({
        candidate: "agent:claude-desktop",
        scanId: "scan-1",
      }),
    );
    const verdict = await screen.findByTestId("deploy-gate-verdict");
    expect(verdict).toHaveAttribute("data-decision", "allow");
    expect(verdict).toHaveTextContent("GO");
  });

  it("renders REVIEW for a warn decision", async () => {
    apiMock.graphShouldIDeploy.mockResolvedValue(decisionResponse("warn", 55));
    render(<DeployGatePanel scanId="scan-1" />);

    fireEvent.change(screen.getByLabelText("Deploy candidate"), { target: { value: "svc:x" } });
    fireEvent.click(screen.getByRole("button", { name: "Run gate" }));

    const verdict = await screen.findByTestId("deploy-gate-verdict");
    expect(verdict).toHaveAttribute("data-decision", "warn");
    expect(verdict).toHaveTextContent("REVIEW");
    expect(verdict).toHaveTextContent("55.0");
  });

  it("renders BLOCK for a block decision with matched exposure paths", async () => {
    apiMock.graphShouldIDeploy.mockResolvedValue(decisionResponse("block", 91));
    render(<DeployGatePanel scanId="scan-1" />);

    fireEvent.change(screen.getByLabelText("Deploy candidate"), { target: { value: "svc:x" } });
    fireEvent.click(screen.getByRole("button", { name: "Run gate" }));

    const verdict = await screen.findByTestId("deploy-gate-verdict");
    expect(verdict).toHaveAttribute("data-decision", "block");
    expect(verdict).toHaveTextContent("BLOCK");
    expect(verdict).toHaveTextContent("CVE-2024-1");
  });

  it("does not call the endpoint with an empty candidate", () => {
    render(<DeployGatePanel />);
    expect(screen.getByRole("button", { name: "Run gate" })).toBeDisabled();
  });
});
