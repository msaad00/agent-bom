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
});
