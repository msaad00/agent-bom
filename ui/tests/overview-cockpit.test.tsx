import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { OverviewCockpit } from "@/components/overview-cockpit";
import { buildExecExposurePaths } from "@/lib/dashboard-data";
import type { OverviewResponse, OverviewTopRisk } from "@/lib/api";

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

  it("renders an estate/operations strip without the security-duplicate lanes", () => {
    render(<OverviewCockpit {...baseProps} domains={sampleDomains} />);

    const strip = screen.getByTestId("overview-estate-ops");
    expect(strip).toBeInTheDocument();
    // The old 7-lane cross-lane grid no longer exists as such.
    expect(screen.queryByTestId("overview-cross-lane-coverage")).not.toBeInTheDocument();
    // Cloud posture / Vuln / SCA / Code / repo duplicate the five security
    // coverage lanes above, so they must NOT appear as operational tiles.
    expect(within(strip).queryByText("Cloud posture")).not.toBeInTheDocument();
    expect(within(strip).queryByText("Vuln / SCA")).not.toBeInTheDocument();
    expect(within(strip).queryByText("Code / repo")).not.toBeInTheDocument();
    // Only the genuinely-operational lanes render.
    expect(within(strip).getByText("Runtime")).toBeInTheDocument();
    expect(within(strip).getByText("NHI / Identity")).toBeInTheDocument();
    expect(within(strip).getByText("Ops")).toBeInTheDocument();
    // 3 of 4 active — cost is idle, so it de-emphasizes into a Connect prompt
    // instead of a loud zero tile.
    expect(within(strip).getByText(/3 of 4 operational lanes active/i)).toBeInTheDocument();
    expect(within(strip).getByText("LLM Cost")).toBeInTheDocument();
    expect(within(strip).getByText("Connect")).toBeInTheDocument();
  });

  it("renders the five security coverage lanes with reconciled severity strips", () => {
    const coverage = [
      { domain: "cspm" as const, label: "CSPM", href: "/findings?domain=cspm", count: 3, severity: { critical: 1, high: 1, medium: 0, low: 0, unrated: 1 } },
      { domain: "vuln" as const, label: "Vuln mgmt", href: "/findings?domain=vuln", count: 2, severity: { critical: 2, high: 0, medium: 0, low: 0, unrated: 0 } },
      { domain: "aspm" as const, label: "ASPM", href: "/findings?domain=aspm", count: 0, severity: { critical: 0, high: 0, medium: 0, low: 0, unrated: 0 } },
      { domain: "dspm" as const, label: "DSPM", href: "/findings?domain=dspm", count: 0, severity: { critical: 0, high: 0, medium: 0, low: 0, unrated: 0 } },
      { domain: "aispm" as const, label: "AISPM", href: "/findings?domain=aispm", count: 1, severity: { critical: 0, high: 0, medium: 1, low: 0, unrated: 0 } },
    ];
    render(<OverviewCockpit {...baseProps} domains={sampleDomains} coverage={coverage} />);

    const section = screen.getByTestId("overview-security-coverage");
    expect(section).toBeInTheDocument();
    // Lanes are labeled as overlapping disciplines so a user never sums them.
    expect(screen.getByText(/lenses can overlap/i)).toBeInTheDocument();
    expect(screen.getByText(/not additive/i)).toBeInTheDocument();
    // Each lane links to its domain-filtered findings view.
    expect(screen.getByTestId("coverage-lane-cspm")).toHaveAttribute("href", "/findings?domain=cspm");
    // Unrated is surfaced as its own chip when present.
    expect(screen.getByText(/Unrated 1/)).toBeInTheDocument();
    // Empty lanes still render (DSPM at zero) so the row is always the five domains.
    expect(screen.getByTestId("coverage-lane-dspm")).toBeInTheDocument();
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
    expect(screen.getByText(/3 of 4 operational lanes active/i)).toBeInTheDocument();
    expect(screen.getByText(/2 connected/i)).toBeInTheDocument();
  });

  it("renders the top-risk strip from overview.top_risks for a bulk estate with no scans (#4063)", () => {
    // A hub/bulk-ingested estate has no scan jobs, so the scan-derived blast path
    // is empty. The strip must still populate from the server-reconciled
    // top_risks and each row must drill to real finding rows.
    const topRisks: OverviewTopRisk[] = [
      { vulnerability_id: "CVE-2026-5555", package: "urllib3", severity: "critical", risk_score: 9.6, is_kev: true, cvss_score: 9.8, epss_score: 0.6, affected_agents: ["Ingest Bot"] },
      { vulnerability_id: "CVE-2026-4444", package: "lodash", severity: "high", risk_score: 7.1, is_kev: false, cvss_score: 7.5, epss_score: 0.2, affected_agents: [] },
    ];
    const exposurePaths = buildExecExposurePaths([], topRisks);
    render(
      <OverviewCockpit
        {...baseProps}
        topPath={null}
        exposurePaths={exposurePaths}
        critical={1}
        high={1}
      />,
    );

    expect(screen.getByText("CVE-2026-5555")).toBeInTheDocument();
    expect(screen.getByText("urllib3")).toBeInTheDocument();
    expect(screen.getByText("CVE-2026-4444")).toBeInTheDocument();
    // Worst-first row drills to the exact CVE's finding rows (non-empty target).
    const worst = screen.getByText("CVE-2026-5555").closest("a");
    expect(worst).toHaveAttribute("href", "/findings?cve=CVE-2026-5555");
  });

  it("shows an honest empty strip when there are genuinely no risks (#4063)", () => {
    render(<OverviewCockpit {...baseProps} topPath={null} exposurePaths={[]} critical={0} high={0} />);
    expect(
      screen.getByText(/Run a scan to correlate CVEs, packages, agents, and credentials/i),
    ).toBeInTheDocument();
    expect(screen.queryByText(/CVE-/)).not.toBeInTheDocument();
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

  it("never asserts 'no vulnerabilities' while open CVEs are present", () => {
    // Backend posture summary is derived from only the latest single scan, so it
    // can read "No vulnerabilities found" even when the estate rollup shows open
    // CVEs (#3940). The exec read must stay consistent with the visible counts.
    render(
      <OverviewCockpit
        {...baseProps}
        postureSummary="No vulnerabilities found; strong best-practice/config posture (A, 95%)"
        critical={0}
        high={0}
        cves={78}
      />,
    );

    expect(screen.queryByText(/no vulnerabilities/i)).not.toBeInTheDocument();
    expect(screen.getByText(/78 open CVEs across connected surfaces/i)).toBeInTheDocument();
  });

  it("shows the posture score as a percentage alongside the letter grade", () => {
    render(<OverviewCockpit {...baseProps} grade="C" score={62} />);

    // Percent appears both in the grade badge and the headline score line.
    expect(screen.getAllByText("62%").length).toBeGreaterThan(0);
    expect(screen.getByText("Grade C")).toBeInTheDocument();
  });

  it("carries operational lane scope hints as tooltips, not visible sentences", () => {
    render(<OverviewCockpit {...baseProps} domains={sampleDomains} />);

    const strip = screen.getByTestId("overview-estate-ops");
    // The scope clarifier is a title tooltip on the tile, not always-visible copy.
    const runtimeTile = within(strip).getByText("Runtime").closest("a");
    expect(runtimeTile).toHaveAttribute("title", expect.stringMatching(/Live runtime surfaces/i));
    expect(within(strip).queryByText(/Live runtime surfaces — gateway/i)).not.toBeInTheDocument();
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

  it("never renders a green PASS for a framework with zero evaluated controls (#3889)", () => {
    render(
      <OverviewCockpit
        {...baseProps}
        compliance={{
          overallScore: 100,
          overallStatus: "pass",
          frameworks: [
            // Evaluated (some findings mapped) — legitimately shows.
            { id: "cis", label: "CIS Controls v8", pass: 8, warn: 1, fail: 1, total: 10 },
            // Scan ran but nothing mapped: 0 evaluated must read "Not evaluated".
            { id: "soc2", label: "SOC 2", pass: 0, warn: 0, fail: 0, total: 65 },
          ],
        }}
      />,
    );

    expect(screen.getByText("SOC 2")).toBeInTheDocument();
    expect(screen.getByText(/Not evaluated · 0\/65 controls/i)).toBeInTheDocument();
    // The unevaluated framework must not claim any pass count.
    expect(screen.queryByText(/0\/65 pass/i)).not.toBeInTheDocument();
  });

  it("renders the score breakdown explainer from weighted inputs (#3940)", () => {
    render(
      <OverviewCockpit
        {...baseProps}
        grade="C"
        score={70}
        scoreBreakdown={[
          { driver: "critical", label: "Critical findings", count: 2, weight: 12, contribution: 24 },
          { driver: "high", label: "High findings", count: 1, weight: 6, contribution: 6 },
          { driver: "medium", label: "Medium findings", count: 0, weight: 2, contribution: 0 },
        ]}
      />,
    );

    expect(screen.getByTestId("overview-score-explainer")).toBeInTheDocument();
    expect(screen.getByTestId("score-driver-critical")).toBeInTheDocument();
    expect(screen.getByText("−24.0")).toBeInTheDocument();
    // Zero-contribution drivers are omitted so the panel stays legible.
    expect(screen.queryByTestId("score-driver-medium")).not.toBeInTheDocument();
  });

  it("toggles the score display format and calls the persist handler (#3940)", async () => {
    const user = userEvent.setup();
    const onScoreFormatChange = vi.fn();
    render(
      <OverviewCockpit
        {...baseProps}
        grade="C"
        score={70}
        scoreFormat="percent"
        onScoreFormatChange={onScoreFormatChange}
      />,
    );

    const toggle = screen.getByTestId("score-format-toggle");
    await user.click(within(toggle).getByRole("button", { name: "Grade" }));
    expect(onScoreFormatChange).toHaveBeenCalledWith("grade");
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
