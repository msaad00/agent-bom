import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { OverviewCockpit } from "@/components/overview-cockpit";

describe("OverviewCockpit", () => {
  const baseProps = {
    grade: "F",
    score: 37,
    critical: 2,
    high: 10,
    kev: 1,
    credentials: 8,
    agents: 8,
    cves: 15,
    scans: 1,
    latestScan: "Jul 9, 10:45 PM",
    mode: "Local",
    summaryReady: true,
    severity: { critical: 2, high: 10, medium: 3, low: 0, total: 15 },
    domains: null,
    topPath: {
      key: "cve-1",
      riskScore: 10,
      href: "/security-graph",
      nodes: [
        { type: "cve" as const, label: "CVE-2020-14343" },
        { type: "agent" as const, label: "cursor" },
      ],
    },
    exposurePaths: [],
    signals: { tools: 23, packages: 17, activeServices: 7, connected: true },
    onPersonaChange: vi.fn(),
  };

  it("renders executive risk themes without attack-path chains", () => {
    render(<OverviewCockpit {...baseProps} persona="executive" />);

    expect(screen.getByText("Top risks")).toBeInTheDocument();
    expect(screen.getAllByText(/no attack-path chains/i).length).toBeGreaterThan(0);
    expect(screen.getByText("Governance actions")).toBeInTheDocument();
    expect(screen.queryByText("Priority exposure path")).not.toBeInTheDocument();
  });

  it("renders engineer attack-path panel", () => {
    render(<OverviewCockpit {...baseProps} persona="engineer" />);

    expect(screen.getByText("Priority exposure path")).toBeInTheDocument();
    expect(screen.getByText("Investigate")).toBeInTheDocument();
    expect(screen.getByText("CVE-2020-14343")).toBeInTheDocument();
  });

  it("switches persona via lens toggle", async () => {
    const user = userEvent.setup();
    const onPersonaChange = vi.fn();
    render(<OverviewCockpit {...baseProps} persona="executive" onPersonaChange={onPersonaChange} />);

    await user.click(screen.getByRole("button", { name: "Engineer" }));
    expect(onPersonaChange).toHaveBeenCalledWith("engineer");
  });

  it("shows compliance and activated services snapshots", () => {
    render(
      <OverviewCockpit
        {...baseProps}
        persona="executive"
        compliance={{
          overallScore: 72,
          overallStatus: "warning",
          frameworks: [
            { id: "owasp-llm", label: "OWASP LLM Top 10", pass: 8, warn: 1, fail: 1, total: 10 },
            { id: "cis", label: "CIS Controls v8", pass: 10, warn: 0, fail: 0, total: 10 },
          ],
        }}
        services={{
          cloud_accounts: { state: "live", count: 2 },
          compliance: { state: "connected", count: 1 },
          fleet: { state: "locked", count: 0 },
        }}
      />,
    );

    expect(screen.getByTestId("overview-compliance-snapshot")).toBeInTheDocument();
    expect(screen.getByText("OWASP LLM Top 10")).toBeInTheDocument();
    expect(screen.getByTestId("overview-activated-services")).toBeInTheDocument();
    expect(screen.getByText("Cloud accounts")).toBeInTheDocument();
  });

  it("lets operators collapse overview sections", async () => {
    const user = userEvent.setup();
    render(
      <OverviewCockpit
        {...baseProps}
        persona="executive"
        compliance={{
          overallScore: 90,
          overallStatus: "pass",
          frameworks: [{ id: "cis", label: "CIS Controls v8", pass: 10, warn: 0, fail: 0, total: 10 }],
        }}
      />,
    );

    expect(screen.getByText("CIS Controls v8")).toBeVisible();
    await user.click(screen.getByRole("button", { name: /Compliance/i }));
    expect(screen.getByText("CIS Controls v8")).not.toBeVisible();
  });
});
