import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

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
  };

  it("renders a single exec overview without altitude lenses or next-steps farm", () => {
    render(<OverviewCockpit {...baseProps} />);

    expect(screen.getByText("Command center")).toBeInTheDocument();
    expect(screen.getByText("Top risks")).toBeInTheDocument();
    expect(screen.queryByText("Next steps")).not.toBeInTheDocument();
    expect(screen.queryByText("Severity roll-up")).not.toBeInTheDocument();
    expect(screen.getByText("Risk posture")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "CISO" })).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Agent mesh/i })).toHaveAttribute("href", "/agents/topology");
  });

  it("surfaces risk themes and links into findings / compliance", () => {
    render(<OverviewCockpit {...baseProps} />);

    expect(screen.getByText(/2 critical findings need attention/i)).toBeInTheDocument();
    expect(screen.getByText(/Known exploit exposure: CVE-2020-14343/i)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Critical findings" })).toHaveAttribute(
      "href",
      "/findings?severity=critical",
    );
    expect(screen.getByRole("link", { name: "Compliance evidence" })).toHaveAttribute(
      "href",
      "/compliance",
    );
  });

  it("shows compliance and compact live-surface chips when evidence exists", () => {
    render(
      <OverviewCockpit
        {...baseProps}
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
        issueMatrix={{
          vulnerability: { critical: 1, high: 4, medium: 2, low: 0 },
          misconfiguration: { critical: 0, high: 3, medium: 1, low: 0 },
          secret: { critical: 1, high: 1, medium: 0, low: 0 },
          identity: { critical: 0, high: 0, medium: 0, low: 0 },
          totals: { critical: 2, high: 8, medium: 3, low: 0 },
          byType: { vulnerability: 7, misconfiguration: 4, secret: 2, identity: 0 },
          openTotal: 13,
        }}
      />,
    );

    expect(screen.getByTestId("overview-compliance-snapshot")).toBeInTheDocument();
    expect(screen.getByText("OWASP LLM Top 10")).toBeInTheDocument();
    expect(screen.getByTestId("overview-activated-services")).toBeInTheDocument();
    expect(screen.getByText("Live surfaces")).toBeInTheDocument();
    expect(screen.getByText("Cloud accounts")).toBeInTheDocument();
    expect(screen.getByTestId("overview-severity-issue-strip")).toBeInTheDocument();
    expect(screen.getByText("Open issues")).toBeInTheDocument();
    expect(screen.getByText("Misconfig 4")).toBeInTheDocument();
    expect(screen.getByText("KEV 1")).toBeInTheDocument();
    expect(screen.getByText("Secrets 8")).toBeInTheDocument();
    expect(screen.getByText("Compliance 72%")).toBeInTheDocument();
  });

  it("does not show green compliance pass tiles without scan evidence", () => {
    render(
      <OverviewCockpit
        {...baseProps}
        scans={0}
        compliance={{
          overallScore: 0,
          overallStatus: "pass",
          frameworks: [{ id: "cis", label: "CIS Controls v8", pass: 10, warn: 0, fail: 0, total: 10 }],
        }}
      />,
    );

    expect(screen.queryByText("CIS Controls v8")).not.toBeInTheDocument();
    expect(screen.getByText(/Empty estates do not show pass tiles/i)).toBeInTheDocument();
  });

  it("lets operators collapse overview sections", async () => {
    const user = userEvent.setup();
    render(
      <OverviewCockpit
        {...baseProps}
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
