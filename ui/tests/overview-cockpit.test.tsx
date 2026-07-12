import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { OverviewCockpit } from "@/components/overview-cockpit";
import type { OverviewResponse } from "@/lib/api";

function domain(
  label: string,
  metric: number,
  metricLabel: string,
  status: OverviewResponse["domains"]["cloud"]["status"],
  href: string,
): OverviewResponse["domains"]["cloud"] {
  return { label, href, metric, metric_label: metricLabel, status, detail: {} };
}

const sampleDomains: OverviewResponse["domains"] = {
  cloud: domain("Cloud posture", 3, "accounts connected", "ok", "/connections"),
  vuln: domain("Vuln / SCA", 15, "open CVEs", "critical", "/findings?issue=vulnerability"),
  code: domain("Code / repo", 0, "repo scans", "idle", "/scan"),
  runtime: domain("Runtime", 2, "active surfaces", "ok", "/gateway"),
  cost: domain("LLM Cost", 0, "USD tracked", "idle", "/cost"),
  identity: domain("NHI / Identity", 8, "identities + agents", "ok", "/identity"),
  ops: domain("Ops", 1, "completed scans", "ok", "/jobs"),
};

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
    // De-dup: the old redundant "Connected estate" list and "Live surfaces" pill
    // strip are gone — the cross-lane grid is the single estate view.
    expect(screen.queryByText("Connected estate")).not.toBeInTheDocument();
    expect(screen.queryByText("Live surfaces")).not.toBeInTheDocument();
    expect(screen.queryByTestId("overview-activated-services")).not.toBeInTheDocument();
  });

  it("renders one canonical cross-lane coverage grid without repeating signals", () => {
    render(<OverviewCockpit {...baseProps} domains={sampleDomains} />);

    const grid = screen.getByTestId("overview-cross-lane-coverage");
    expect(grid).toBeInTheDocument();
    // Every lane appears exactly once — no triple-render of the same number.
    expect(screen.getByText("Cloud posture")).toBeInTheDocument();
    expect(screen.getAllByText("Cloud posture")).toHaveLength(1);
    expect(screen.getByText("Vuln / SCA")).toBeInTheDocument();
    expect(screen.getByText("NHI / Identity")).toBeInTheDocument();
    // 5 of 7 lanes report signal (code + cost are idle).
    expect(screen.getByText(/5 of 7 lanes reporting/i)).toBeInTheDocument();
  });

  it("keeps connected data sources out of leadership lanes and links to connections", () => {
    render(
      <OverviewCockpit
        {...baseProps}
        domains={sampleDomains}
        services={{ data_sources: { state: "connected", count: 2 } }}
      />,
    );

    expect(screen.queryByText("Data sources")).not.toBeInTheDocument();
    expect(screen.getByText(/5 of 7 lanes reporting/i)).toBeInTheDocument();
    expect(screen.getByText(/2 connected/i)).toBeInTheDocument();
  });

  it("surfaces risk themes and links into findings / compliance", () => {
    render(<OverviewCockpit {...baseProps} />);

    expect(screen.getByText(/2 critical findings need attention/i)).toBeInTheDocument();
    expect(screen.getByText("CVE-2020-14343")).toBeInTheDocument();
    expect(screen.getByText("cursor")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Critical findings" })).toHaveAttribute(
      "href",
      "/findings?severity=critical",
    );
    expect(screen.getByRole("link", { name: "Compliance evidence" })).toHaveAttribute(
      "href",
      "/compliance",
    );
  });

  it("shows compliance and open-issue chips when evidence exists", () => {
    render(
      <OverviewCockpit
        {...baseProps}
        domains={sampleDomains}
        compliance={{
          overallScore: 72,
          overallStatus: "warning",
          frameworks: [
            { id: "owasp-llm", label: "OWASP LLM Top 10", pass: 8, warn: 1, fail: 1, total: 10 },
            { id: "cis", label: "CIS Controls v8", pass: 10, warn: 0, fail: 0, total: 10 },
          ],
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
    expect(screen.getByTestId("overview-severity-issue-strip")).toBeInTheDocument();
    expect(screen.getByText("Open issues")).toBeInTheDocument();
    expect(screen.getByText("Misconfig 4")).toBeInTheDocument();
    expect(screen.getByText("KEV 1")).toBeInTheDocument();
    expect(screen.getByText("Secrets 8")).toBeInTheDocument();
    expect(screen.getByText("Compliance 72%")).toBeInTheDocument();
  });

  it("surfaces the last scan time and an honest zero-state", () => {
    const { rerender } = render(<OverviewCockpit {...baseProps} />);
    expect(screen.getByText(/Last scan · Jul 9, 10:45 PM/i)).toBeInTheDocument();

    rerender(
      <OverviewCockpit {...baseProps} grade="—" score={undefined} scans={0} latestScan={null} />,
    );
    expect(screen.getByText("No completed scans")).toBeInTheDocument();
    expect(screen.getByText(/Connect a surface or run a scan to grade posture/i)).toBeInTheDocument();
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

  it("shows evaluated compliance when every control fails and the score is zero", () => {
    render(
      <OverviewCockpit
        {...baseProps}
        compliance={{
          overallScore: 0,
          overallStatus: "fail",
          frameworks: [{ id: "cis", label: "CIS Controls v8", pass: 0, warn: 0, fail: 10, total: 10 }],
        }}
      />,
    );

    expect(screen.getByText("Compliance 0%")).toBeInTheDocument();
    expect(screen.getByText("CIS Controls v8")).toBeInTheDocument();
    expect(screen.getByText(/0% overall · 1 framework need attention/i)).toBeInTheDocument();
    expect(screen.queryByText(/coverage appears after the first completed scan/i)).not.toBeInTheDocument();
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
