import { fireEvent, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { OverviewCockpit } from "@/components/overview-cockpit";
import { buildExecExposurePaths } from "@/lib/dashboard-data";
import type { OverviewResponse, OverviewTopRisk } from "@/lib/api";

beforeEach(() => {
  vi.stubGlobal("ResizeObserver", class {
    constructor(private callback: ResizeObserverCallback) {}
    observe() { this.callback([{ contentRect: { width: 1000 } } as ResizeObserverEntry], this as unknown as ResizeObserver); }
    unobserve() {}
    disconnect() {}
  });
});

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

  it("starts with posture and orders risk and asset drilldowns consistently", () => {
    render(<OverviewCockpit {...baseProps} />);
    expect(screen.getByRole("tab", { name: "Posture" })).toHaveAttribute("aria-selected", "true");
    expect(screen.getAllByRole("tab").map(tab => tab.textContent)).toEqual(["Posture", "Top risks", "Assets & coverage"]);
    expect(screen.getByRole("tabpanel", { name: "Posture" })).toBeVisible();
    expect(screen.getByRole("tab", { name: "Assets & coverage" })).toBeVisible();
    expect(screen.queryByRole("region", { name: "AI spend & usage" })).not.toBeInTheDocument();
  });

  it("opens risk details from posture without duplicating the detail", async () => {
    render(<OverviewCockpit {...baseProps} domains={sampleDomains} />);
    await userEvent.click(screen.getByRole("tab", { name: "Top risks" }));
    expect(screen.getByRole("tabpanel", { name: "Top risks" })).toBeVisible();
    expect(screen.getAllByRole("region", { name: "Selected risk" })).toHaveLength(1);
    await userEvent.click(screen.getByRole("tab", { name: "Posture" }));
    expect(screen.getByText("Posture score · 0–100, higher is better")).toBeVisible();
    expect(screen.getByRole("region", { name: "Findings by discipline" }).parentElement).toBe(screen.getByRole("region", { name: "Compliance & frameworks" }).parentElement);
  });

  it("keeps risk mappings in a separate disclosure when evaluated controls are available", async () => {
    const user = userEvent.setup();
    render(<OverviewCockpit {...baseProps} compliance={{ overallScore: 50, overallStatus: "fail", evaluatedControls: 2, totalControls: 12, frameworks: [
      { id: "cis", label: "CIS Controls", kind: "scored", pass: 1, fail: 1, warn: 0, total: 2 },
      { id: "atlas", label: "MITRE ATLAS", kind: "applicability", applicable: 3, pass: 0, fail: 0, warn: 0, total: 10 },
    ] }} />);
    expect(screen.getByText("1/2 evaluated controls pass")).toBeVisible();
    const results = screen.getByLabelText("Evaluated control results");
    expect(within(results).getByText("Controls passed").nextElementSibling).toHaveTextContent("1");
    expect(within(results).getByText("Controls failed").nextElementSibling).toHaveTextContent("1");
    expect(within(results).getByText("Controls need review").nextElementSibling).toHaveTextContent("0");
    expect(screen.getByText("50% pass rate")).toBeVisible();
    expect(within(results).queryByText(/framework/i)).not.toBeInTheDocument();
    const evaluated = screen.getByTestId("overview-evaluated-frameworks");
    const mappings = screen.getByTestId("overview-risk-mappings");
    expect(within(evaluated).queryByText("MITRE ATLAS")).not.toBeInTheDocument();
    expect(within(mappings).getByText("MITRE ATLAS")).not.toBeVisible();
    await user.click(within(mappings).getByRole("button", { name: /^Risk mappings/ }));
    expect(within(mappings).getByText("MITRE ATLAS")).toBeVisible();
    expect(within(mappings).getByRole("link", { name: /MITRE ATLAS/ })).toHaveAttribute("href", "/compliance?framework=atlas");
    expect(within(evaluated).getByText("CIS Controls")).toBeVisible();
  });

  it("shows available risk mappings when control evaluation is unavailable", () => {
    render(<OverviewCockpit {...baseProps} compliance={{ overallScore: 0, overallStatus: "no_data", evaluatedControls: 0, totalControls: 10, frameworks: [
      { id: "atlas", label: "MITRE ATLAS", kind: "applicability", applicable: 3, pass: 0, fail: 0, warn: 0, total: 10 },
      { id: "nist-ai-rmf", label: "NIST AI RMF", kind: "scored", pass: 0, fail: 0, warn: 0, total: 0 },
    ] }} />);
    expect(screen.getByText(/Control evaluation unavailable for completed scans/i)).toBeVisible();
    expect(screen.getByText("MITRE ATLAS")).toBeVisible();
    expect(screen.getByText("3/10 risks applicable")).toBeVisible();
    expect(screen.getByText("Control frameworks")).toBeVisible();
    expect(screen.getByText("NIST AI RMF")).toBeVisible();
    expect(screen.getByText("Not evaluated · 0/0 controls")).toBeVisible();
  });

  it("keeps the label in the flexible column when a framework has no logo", () => {
    render(<OverviewCockpit {...baseProps} compliance={{ overallScore: 50, overallStatus: "fail", evaluatedControls: 2, totalControls: 2, frameworks: [
      { id: "nist-800-53", label: "NIST SP 800-53", kind: "scored", pass: 1, fail: 1, warn: 0, total: 2 },
      { id: "cis", label: "CIS Controls", kind: "scored", pass: 0, fail: 0, warn: 0, total: 0 },
    ] }} />);
    for (const label of ["NIST SP 800-53", "CIS Controls"]) {
      const title = screen.getByText(label);
      const card = title.closest("a")!;
      expect(card).toHaveAttribute("href", `/compliance?framework=${label === "CIS Controls" ? "cis" : "nist-800-53"}`);
      expect(card.children[0]).toHaveAttribute("aria-hidden", "true");
      expect(card.children[1]).toContainElement(title);
      expect(card).toHaveTextContent(label === "CIS Controls" ? "Not evaluated" : "1 failed");
    }
    expect(screen.getByText("1/2 evaluated controls pass · 1 failed")).toBeVisible();
    expect(screen.getByText("Not evaluated · 0/0 controls")).toBeVisible();
  });

  it("does not keep a settled unknown scan scope in a loading state", () => {
    const view = render(<OverviewCockpit {...baseProps} loading={false} complianceLoading={false} scanScopeLoading scans={null} />);
    expect(screen.getByText("Loading control evaluation…")).toBeVisible();
    view.rerender(<OverviewCockpit {...baseProps} loading={false} complianceLoading={false} scanScopeLoading={false} scans={null} />);
    expect(screen.queryByText("Loading control evaluation…")).not.toBeInTheDocument();
    expect(screen.getByText("Control evaluation unavailable. Scan scope could not be established.")).toBeVisible();
    expect(screen.queryByText(/Framework coverage appears after the first completed scan/)).not.toBeInTheDocument();
  });

  it("shows security services before operations and lets the right panel collapse by keyboard", async () => {
    const user = userEvent.setup();
    render(<OverviewCockpit {...baseProps} domains={sampleDomains} coverage={[
      { domain: "aispm", label: "AISPM", href: "/findings?domain=aispm", count: 0, severity: { critical: 0, high: 0, medium: 0, low: 0, unrated: 0 } },
      { domain: "cspm", label: "CSPM", href: "/findings?domain=cspm", count: 0, severity: { critical: 0, high: 0, medium: 0, low: 0, unrated: 0 } },
    ]} />);
    const lanes = screen.getByTestId("overview-security-coverage");
    expect(lanes).toBeVisible();
    expect(within(lanes).getAllByRole("link")[0]).toHaveTextContent("Cloud security (CSPM)");
    expect(within(lanes).getByText("AI security (AISPM)")).toBeVisible();
    const toggle = screen.getByRole("button", { name: /^Findings by discipline/ });
    expect(toggle).toHaveTextContent("2 security disciplines");
    expect(toggle).toHaveAttribute("aria-expanded", "true");
    toggle.focus();
    await user.keyboard("{Enter}");
    expect(toggle).toHaveAttribute("aria-expanded", "false");
    expect(lanes).not.toBeVisible();
    expect(toggle).toHaveFocus();
    await user.keyboard(" ");
    expect(lanes).toBeVisible();
    expect(screen.getByRole("region", { name: "Risk overview" })).toBeVisible();
  });

  it("collapses compliance independently from coverage and risks", async () => {
    const user = userEvent.setup();
    render(<OverviewCockpit {...baseProps} domains={sampleDomains} />);
    const toggle = screen.getByRole("button", { name: /^Compliance & frameworks/ });
    toggle.focus();
    await user.keyboard("{Enter}");
    expect(toggle).toHaveAttribute("aria-expanded", "false");
    expect(toggle).toHaveFocus();
    expect(screen.getByText(/Control evaluation unavailable/i)).not.toBeVisible();
    expect(screen.getByRole("button", { name: /^Findings by discipline/ })).toHaveAttribute("aria-expanded", "true");
    expect(screen.getByRole("tab", { name: "Posture" })).toHaveAttribute("aria-selected", "true");
  });

  it("does not mix runtime operations into the findings discipline panel", () => {
    render(<OverviewCockpit {...baseProps} domains={sampleDomains} />);
    expect(screen.queryByTestId("overview-estate-ops")).not.toBeInTheDocument();
    expect(screen.queryByText("Operational signals")).not.toBeInTheDocument();
  });

  it("shows one grade and one numeric score in the posture summary", () => {
    render(<OverviewCockpit {...baseProps} grade="C" score={62} />);
    expect(screen.getAllByText("62%")).toHaveLength(1);
    expect(screen.getAllByText("Grade C")).toHaveLength(1);
  });

  it.each([
    "sbom:/private/tmp/reference/model.cdx.json",
    "sbom:C:\\reference\\model.cdx.json",
  ])("labels %s as an SBOM source and preserves its full technical value", async (source) => {
    const user = userEvent.setup();
    render(<OverviewCockpit {...baseProps} topPath={{
      ...baseProps.topPath,
      nodes: [{ type: "cve", label: "CVE-2020-14343" }, { type: "agent", label: source }],
    }} />);
    fireEvent.click(screen.getByRole("tab", { name: "Top risks" }));
    expect(within(screen.getByRole("region", { name: "Selected risk" })).getByText("SBOM source: model.cdx.json")).toBeVisible();
    expect(screen.queryByText(/Affected workload:/)).not.toBeInTheDocument();
    expect(screen.getByText(source)).not.toBeVisible();
    await user.click(screen.getByText("Technical details"));
    expect(screen.getByText(source)).toBeVisible();
  });

  it.each(["agent", "server"] as const)("preserves the affected workload label for a normal %s", (type) => {
    render(<OverviewCockpit {...baseProps} topPath={{
      ...baseProps.topPath,
      nodes: [{ type: "cve", label: "CVE-2020-14343" }, { type, label: "api-worker" }],
    }} />);
    fireEvent.click(screen.getByRole("tab", { name: "Top risks" }));
    expect(screen.getByText("Affected workload: api-worker")).toBeVisible();
    expect(screen.queryByText(/SBOM source:/)).not.toBeInTheDocument();
  });

  it("keeps exact technical identifiers behind a separate disclosure", async () => {
    const user = userEvent.setup();
    const findingId = "fdf2bafa-4d62-505a-b16c-4c74d646437f";
    render(<OverviewCockpit {...baseProps} topPath={{
      key: "opaque-finding", href: "/findings?severity=high", riskScore: 10,
      nodes: [
        { type: "cve", label: findingId, severity: "high" },
        { type: "package", label: "requests" },
        { type: "agent", label: "data-pipeline" },
        { type: "credential", label: "SERVICE_KEY" },
      ],
    }} />);
    expect(screen.getByText(findingId)).not.toBeVisible();
    fireEvent.click(screen.getByRole("tab", { name: "Top risks" }));
    expect(screen.getByRole("link", { name: /Affected workload: data-pipeline/i })).toHaveAttribute("href", "/findings?severity=high");
    expect(screen.queryByText("Finding in")).not.toBeInTheDocument();
    expect(screen.queryByText(/exposes a credential/i)).not.toBeInTheDocument();
    await user.click(screen.getByText("Technical details"));
    expect(screen.getByText(findingId)).toBeVisible();
    expect(screen.getByText("SERVICE_KEY")).toBeVisible();
  });

  it.each(["CVE-2020-14343", "GHSA-8q59-q68h-6hv4"])("keeps %s and package details out of the executive headline", async (advisory) => {
    render(<OverviewCockpit {...baseProps} topPath={{
      key: advisory, href: "/findings", riskScore: 9,
      impactCategory: "availability", affectedWorkloads: ["claims-api", "billing-api"],
      nodes: [{ type: "cve", label: advisory, severity: "high" }, { type: "package", label: "requests@2.0.0" }, { type: "agent", label: "claims-api" }],
    }} />);
    await userEvent.click(screen.getByRole("tab", { name: "Top risks" }));
    const risks = screen.getByRole("tabpanel", { name: "Top risks" });
    expect(within(risks).getByRole("link", { name: /Affected workload: claims-api and 1 more.*Could interrupt service/ })).toBeVisible();
    expect(within(risks).getByText(advisory)).not.toBeVisible();
    expect(within(risks).getByText("requests@2.0.0")).not.toBeVisible();
    expect(within(risks).getByText("Path priority")).not.toBeVisible();
    await userEvent.click(within(risks).getByText("Technical details"));
    expect(within(risks).getByText(advisory)).toBeVisible();
    expect(within(risks).getByText("claims-api, billing-api")).toBeVisible();
    expect(within(risks).getByText(/exploitation of this workload is not established/)).toBeVisible();
  });

  it("does not invent an impact when the source has no impact metadata", async () => {
    render(<OverviewCockpit {...baseProps} />);
    await userEvent.click(screen.getByRole("tab", { name: "Top risks" }));
    expect(screen.getByText(/Its effect on this workload needs review/)).toBeVisible();
    expect(screen.queryByText(/Could allow attacker-controlled code/)).not.toBeInTheDocument();
  });

  it("renders a single exec overview without altitude lenses or next-steps farm", () => {
    render(<OverviewCockpit {...baseProps} />);

    expect(screen.getByText("Risk overview")).toBeInTheDocument();
    expect(screen.getByText("Top risks")).toBeInTheDocument();
    expect(screen.queryByText("Next steps")).not.toBeInTheDocument();
    expect(screen.queryByText("Severity roll-up")).not.toBeInTheDocument();
    expect(screen.getByText("Risk posture")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "CISO" })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("tab", { name: "Top risks" }));
    expect(screen.getByRole("link", { name: /Agent mesh/i })).toHaveAttribute("href", "/agents/topology");
    // De-dup: the old redundant "Connected estate" list and "Live surfaces" pill
    // strip are gone — the cross-lane grid is the single estate view.
    expect(screen.queryByText("Connected estate")).not.toBeInTheDocument();
    expect(screen.queryByText("Live surfaces")).not.toBeInTheDocument();
    expect(screen.queryByTestId("overview-activated-services")).not.toBeInTheDocument();
    expect(screen.queryByText(/Trend unavailable/i)).not.toBeInTheDocument();
    expect(screen.getByText(/Current evidence snapshot/i)).toBeInTheDocument();
    expect(screen.queryByText(/Highest priority:/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/critical path/i)).not.toBeInTheDocument();
  });

  it("renders a scan-backed posture change when trend history exists", () => {
    render(
      <OverviewCockpit
        {...baseProps}
        postureTrend={{ direction: "improved", delta: 8, previousScore: 29, points: 2 }}
      />,
    );

    expect(screen.getByTestId("overview-posture-trend")).toHaveTextContent(
      "Improved 8 points since the previous scan",
    );
  });

  it("does not label configured services as collection coverage", () => {
    render(<OverviewCockpit {...baseProps} domains={sampleDomains} />);
    expect(screen.queryByText(/3 of 3 active/)).not.toBeInTheDocument();
    expect(screen.queryByText("LLM Cost")).not.toBeInTheDocument();
  });

  it("renders the five security coverage lanes with reconciled severity counts", async () => {
    const coverage = [
      { domain: "cspm" as const, label: "CSPM", href: "/findings?domain=cspm", count: 3, severity: { critical: 1, high: 1, medium: 0, low: 0, unrated: 1 } },
      { domain: "vuln" as const, label: "Vuln mgmt", href: "/findings?domain=vuln", count: 2, severity: { critical: 2, high: 0, medium: 0, low: 0, unrated: 0 } },
      { domain: "aspm" as const, label: "ASPM", href: "/findings?domain=aspm", count: 0, severity: { critical: 0, high: 0, medium: 0, low: 0, unrated: 0 } },
      { domain: "dspm" as const, label: "DSPM", href: "/findings?domain=dspm", count: 0, severity: { critical: 0, high: 0, medium: 0, low: 0, unrated: 0 } },
      { domain: "aispm" as const, label: "AISPM", href: "/findings?domain=aispm", count: 1, severity: { critical: 0, high: 0, medium: 1, low: 0, unrated: 0 } },
    ].map((lane) => ({ ...lane, evidence_status: "complete" as const, count_exact: true }));
    render(<OverviewCockpit {...baseProps} domains={sampleDomains} coverage={coverage} />);

    expect(screen.getByRole("button", { name: /Findings by discipline/i })).toBeVisible();
    const section = screen.getByTestId("overview-security-coverage");
    expect(section).toBeInTheDocument();
    // Lanes are labeled as overlapping disciplines so a user never sums them.
    expect(within(section).getByText(/overlapping finding counts/i)).toBeInTheDocument();
    expect(screen.getByText(/not additive/i)).toBeInTheDocument();
    // The magnitude must carry its unit. A bare number under a heading called
    // CSPM reads as assets, accounts or data stores depending on the reader —
    // all wrong. These are findings, which is what the severity chips sum to.
    expect(screen.getByText(/Zero findings does not establish assessment coverage/i)).toBeInTheDocument();
    expect(screen.getAllByText(/^findings?$/i).length).toBeGreaterThan(0);
    // Each lane links to its domain-filtered findings view.
    expect(screen.getByTestId("coverage-lane-cspm")).toHaveAttribute("href", "/findings?domain=cspm");
    // Unrated is surfaced as its own chip when present.
    expect(screen.getByText(/Unrated 1/)).not.toBeVisible();
    await userEvent.setup().click(screen.getByRole("button", { name: "Show severity breakdown" }));
    expect(screen.getByText(/Unrated 1/)).toBeVisible();
    expect(screen.getByRole("button", { name: "Hide severity breakdown" })).toHaveAttribute("aria-expanded", "true");
    // Empty lanes still render (DSPM at zero), but never present missing evidence
    // as a factual zero.
    expect(screen.getByTestId("coverage-lane-dspm")).toBeInTheDocument();
    expect(within(screen.getByTestId("coverage-lane-dspm")).getByText("No open findings")).toBeInTheDocument();
    expect(within(screen.getByTestId("coverage-lane-dspm")).queryByText("0")).not.toBeInTheDocument();
  });

  it("does not present legacy discipline values as exact current counts", async () => {
    render(<OverviewCockpit {...baseProps} coverage={[
      { domain: "aispm", label: "AISPM", href: "/findings?domain=aispm", count: 17, severity: { critical: 17, high: 0, medium: 0, low: 0, unrated: 0 } },
    ]} />);
    const lane = within(screen.getByTestId("coverage-lane-aispm"));
    expect(lane.getByText("Count unavailable")).toBeInTheDocument();
    expect(lane.queryByText("17")).not.toBeInTheDocument();
    expect(lane.queryByText("Critical 17")).not.toBeInTheDocument();
  });

  it.each(["partial", "unavailable"] as const)("discloses %s discipline counts without claiming no evidence", async (evidenceStatus) => {
    const severity = { critical: 0, high: 0, medium: 0, low: 0, unrated: 0 };
    render(<OverviewCockpit {...baseProps} coverage={[
      { domain: "aispm", label: "AISPM", href: "/findings?domain=aispm", count: 0, severity, evidence_status: evidenceStatus, count_exact: false },
      { domain: "cspm", label: "CSPM", href: "/findings?domain=cspm", count: 2, severity: { ...severity, high: 2 }, evidence_status: evidenceStatus, count_exact: false },
    ]} />);
    expect(screen.queryByText("No evidence")).not.toBeInTheDocument();
    expect(screen.queryByText("No open findings")).not.toBeInTheDocument();
    expect(screen.getByText("≥2")).toBeInTheDocument();
    expect(within(screen.getByTestId("coverage-lane-aispm")).getByText(evidenceStatus === "partial" ? "Partial count" : "Count unavailable")).toBeInTheDocument();
  });

  it("keeps asset read failures distinct from an empty estate", async () => {
    render(<OverviewCockpit {...baseProps} inventoryUnavailable />);
    await userEvent.click(screen.getByRole("tab", { name: "Assets & coverage" }));
    expect(screen.getByText("Recorded asset summary unavailable.")).toBeVisible();
    expect(screen.queryByText("0 recorded asset records")).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Open asset inventory" })).toHaveAttribute("href", "/inventory");
  });

  it("renders the top-risk strip from overview.top_risks for a bulk estate with no scans (#4063)", async () => {
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

    fireEvent.click(screen.getByRole("tab", { name: "Top risks" }));
    expect(screen.getByRole("link", { name: /Affected workload: Ingest Bot/ })).toBeVisible();
    await userEvent.click(screen.getByRole("button", { name: /Workload not identified/ }));
    expect(screen.getByRole("link", { name: /Affected workload not identified/ })).toBeVisible();
    await userEvent.click(screen.getByRole("button", { name: /Ingest Bot/ }));
    // Worst-first row drills to the exact CVE's finding rows (non-empty target).
    const worst = screen.getByRole("link", { name: /Affected workload: Ingest Bot/ });
    expect(worst).toHaveAttribute("href", "/findings?cve=CVE-2026-5555");
  });

  it("shows an honest empty strip when there are genuinely no risks (#4063)", () => {
    render(<OverviewCockpit {...baseProps} topPath={null} exposurePaths={[]} critical={0} high={0} />);
    expect(
      screen.getByText(/No prioritized findings in the current overview/i),
    ).toBeInTheDocument();
    expect(screen.queryByText(/CVE-/)).not.toBeInTheDocument();
  });

  it("keeps risk evidence scoped to its original navigation target", () => {
    render(<OverviewCockpit {...baseProps} findingsScopeLabel="Current findings · configured window" />);
    fireEvent.click(screen.getByRole("tab", { name: "Top risks" }));
    expect(screen.getByRole("link", {name: /Affected workload: cursor/i})).toHaveAttribute("href", "/security-graph");
    expect(screen.getByRole("link", {name: /Open investigation/})).toHaveAttribute("href", "/security-graph");
  });

  it("shows compliance and open-issue chips when evidence exists", () => {
    render(
      <OverviewCockpit
        {...baseProps}
        domains={sampleDomains}
        compliance={{
          overallScore: 72,
          overallStatus: "warning",
          evaluatedControls: 20,
          totalControls: 40,
          frameworks: [
            { id: "owasp-llm", label: "OWASP LLM Top 10", kind: "applicability", applicable: 8, pass: 0, warn: 0, fail: 0, total: 10 },
            { id: "cis", label: "CIS Controls v8", kind: "scored", pass: 10, warn: 0, fail: 0, total: 10 },
          ],
        }}
        issueMatrix={{
          vulnerability: { critical: 1, high: 4, medium: 2, low: 0 },
          misconfiguration: { critical: 0, high: 3, medium: 1, low: 0 },
          secret: { critical: 1, high: 1, medium: 0, low: 0 },
          pii: { critical: 0, high: 0, medium: 0, low: 0 },
          identity: { critical: 0, high: 0, medium: 0, low: 0 },
          unclassified: { critical: 0, high: 0, medium: 0, low: 0 },
          totals: { critical: 2, high: 8, medium: 3, low: 0 },
          byType: { vulnerability: 7, misconfiguration: 4, secret: 2, pii: 0, identity: 0, unclassified: 0 },
          openTotal: 13,
        }}
      />,
    );

    expect(screen.getByTestId("overview-compliance-snapshot")).toBeInTheDocument();
    expect(screen.getByText("OWASP LLM Top 10")).toBeInTheDocument();
    expect(screen.getByText("8/10 risks applicable")).toBeInTheDocument();
    expect(screen.queryByText(/8\/10 pass/i)).not.toBeInTheDocument();
    expect(screen.getByTestId("overview-severity-issue-strip")).toBeInTheDocument();
    expect(screen.getByText("Open issues")).toBeInTheDocument();
    expect(screen.getByText("Misconfig 4")).toBeInTheDocument();
    expect(screen.getByText("KEV 1")).toBeInTheDocument();
    expect(screen.getByText("Secrets 8")).toBeInTheDocument();
    expect(screen.getByText("Compliance 72%")).toBeInTheDocument();
  });

  it("makes observed freshness prominent and keeps missing timestamps unavailable", () => {
    const { rerender } = render(<OverviewCockpit {...baseProps} />);
    const freshness = screen.getByTestId("overview-freshness");
    expect(within(freshness).getByText("Last successful scan")).toBeInTheDocument();
    expect(within(freshness).getByText("Jul 9, 10:45 PM")).toBeInTheDocument();

    rerender(
      <OverviewCockpit {...baseProps} latestScan={null} />,
    );
    expect(screen.getByTestId("overview-freshness")).toHaveTextContent(
      "Last successful scan unavailable",
    );

    rerender(
      <OverviewCockpit {...baseProps} grade="—" score={undefined} scans={0} latestScan={null} />,
    );
    expect(screen.getByTestId("overview-freshness")).toHaveTextContent("No completed scan evidence");
    expect(screen.getByText(/Connect a surface or run a scan to grade posture/i)).toBeInTheDocument();
  });

  it("labels posture and freshness as loading before the overview hydrates", () => {
    render(
      <OverviewCockpit
        {...baseProps}
        grade="—"
        score={undefined}
        scans={null}
        latestScan={null}
        summaryReady={false}
        loading
      />,
    );

    expect(screen.getByTestId("overview-freshness")).toHaveTextContent("Loading scan evidence");
    expect(screen.getByText("Loading posture…")).toBeInTheDocument();
    expect(screen.queryByText("Awaiting scan")).not.toBeInTheDocument();
    expect(screen.queryByText("Last successful scan unavailable")).not.toBeInTheDocument();
  });

  it("keeps pending posture neutral even when a prior adverse score is present", () => {
    render(<OverviewCockpit {...baseProps} grade="F" score={42} loading />);

    const score = screen.getByTestId("overview-posture-score");
    expect(score).toHaveTextContent("Loading posture…");
    expect(score).toHaveClass("bg-surface-muted", "text-foreground");
    expect(score).not.toHaveClass("bg-red-500/10", "text-red-700");
    expect(screen.queryByTestId("score-format-toggle")).not.toBeInTheDocument();
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
    expect(
      screen.getByText(/78 unique open CVEs across connected surfaces/i),
    ).toBeInTheDocument();
  });

  it("distinguishes unique CVEs from finding instances in the posture headline", () => {
    render(<OverviewCockpit {...baseProps} cves={799} critical={440} high={1337} />);

    expect(
      screen.getByText(
        /799 unique open CVEs · 440 critical findings · 1,337 high findings across connected surfaces/i,
      ),
    ).toBeInTheDocument();
    expect(screen.queryByText(/799 open CVEs · 440 critical · 1337 high/i)).not.toBeInTheDocument();
  });

  it("keeps the command center evidence-first instead of repeating an onboarding journey", () => {
    render(<OverviewCockpit {...baseProps} exposurePaths={[baseProps.topPath]} />);

    expect(screen.queryByTestId("overview-team-journey")).not.toBeInTheDocument();
    expect(screen.queryByText("Turn exposure into a verified fix")).not.toBeInTheDocument();
    expect(screen.getByText("Risk posture")).toBeInTheDocument();
    expect(screen.getByText("Open issues")).toBeInTheDocument();
    expect(screen.getByText("Top risks")).toBeInTheDocument();
  });

  it("shows the posture score as a percentage alongside the letter grade", () => {
    render(<OverviewCockpit {...baseProps} grade="C" score={62} />);

    // Percent appears both in the grade badge and the headline score line.
    expect(screen.getAllByText("62%").length).toBeGreaterThan(0);
    expect(screen.getByText("Grade C")).toBeInTheDocument();
  });

  it("labels the grade as a current snapshot and points to ranked remediation evidence", () => {
    render(<OverviewCockpit {...baseProps} grade="C" score={62} />);

    expect(screen.getByText(/current evidence snapshot.*prioritize remediation/i)).toBeInTheDocument();
    expect(screen.queryByText(/improved|declined/i)).not.toBeInTheDocument();
  });

  it("bounds the risk list to five and keeps only the selected detail mounted", async () => {
    render(<OverviewCockpit {...baseProps} exposurePaths={Array.from({length: 8}, (_, i) => ({...baseProps.topPath, key: `risk-${i}`, riskScore: 8-i, nodes: [{type: "agent" as const, label: `agent-${i}`}]}))} />);
    fireEvent.click(screen.getByRole("tab", { name: "Top risks" }));
    const list = screen.getByRole("group", {name: "Select a risk"});
    expect(within(list).getAllByRole("button")).toHaveLength(5);
    await userEvent.click(within(list).getByRole("button", {name: /agent-3/}));
    expect(screen.getAllByRole("region", {name: "Selected risk"})).toHaveLength(1);
    expect(within(screen.getByRole("region", {name: "Selected risk"})).getByText("Affected workload: agent-3")).toBeVisible();
  });

  it("does not show green compliance pass tiles without scan evidence", () => {
    render(
      <OverviewCockpit
        {...baseProps}
        scans={0}
        compliance={{
          overallScore: 0,
          overallStatus: "pass",
          evaluatedControls: 0,
          totalControls: 10,
          frameworks: [{ id: "cis", label: "CIS Controls v8", kind: "scored", pass: 10, warn: 0, fail: 0, total: 10 }],
        }}
      />,
    );

    expect(screen.queryByText("CIS Controls v8")).not.toBeInTheDocument();
    expect(screen.getByText(/Empty estates do not show pass tiles/i)).toBeInTheDocument();
  });

  it("does not tell operators to run a scan when completed scans lack mapped compliance evidence", () => {
    render(
      <OverviewCockpit
        {...baseProps}
        compliance={{
          overallScore: 0,
          overallStatus: "warning",
          evaluatedControls: 0,
          totalControls: 10,
          frameworks: [{ id: "cis", label: "CIS Controls v8", kind: "scored", pass: 0, warn: 0, fail: 0, total: 10 }],
        }}
      />,
    );

    expect(screen.getByText(/Control evaluation unavailable for completed scans/i)).toBeInTheDocument();
    expect(screen.getByText(/Review scan scope and evaluation status/i)).toBeInTheDocument();
    expect(screen.queryByText(/Run a scan to light up/i)).not.toBeInTheDocument();
  });

  it("shows evaluated compliance when every control fails and the score is zero", () => {
    render(
      <OverviewCockpit
        {...baseProps}
        compliance={{
          overallScore: 0,
          overallStatus: "fail",
          evaluatedControls: 10,
          totalControls: 10,
          frameworks: [{ id: "cis", label: "CIS Controls v8", kind: "scored", pass: 0, warn: 0, fail: 10, total: 10 }],
        }}
      />,
    );

    expect(screen.getByText("Compliance 0%")).toBeInTheDocument();
    expect(screen.getByText("CIS Controls v8")).toBeInTheDocument();
    expect(screen.getByText("0/10 evaluated controls pass")).toBeVisible();
    expect(screen.getByText("1 framework needs attention")).toBeVisible();
    expect(screen.queryByText(/coverage appears after the first completed scan/i)).not.toBeInTheDocument();
  });

  it("never renders a compliance percentage when the API says no_data", () => {
    // The live shape of a completed scan over an estate with nothing gradeable:
    // every passing control is detective ("we scan"), so the backend reports
    // overall_status "no_data". The frameworks DO carry real pass counts, so a
    // pass/warn/fail test alone reads this as evaluated and renders
    // "Compliance 100%" over an unmeasured estate.
    render(
      <OverviewCockpit
        {...baseProps}
        compliance={{
          overallScore: 100,
          overallStatus: "no_data",
          evaluatedControls: 8,
          totalControls: 240,
          frameworks: [
            { id: "nist-csf", label: "NIST CSF", kind: "scored", pass: 3, warn: 0, fail: 0, total: 14 },
            { id: "nist-800-53", label: "NIST 800-53", kind: "scored", pass: 2, warn: 0, fail: 0, total: 29 },
            { id: "cis", label: "CIS Controls v8", kind: "scored", pass: 3, warn: 0, fail: 0, total: 10 },
          ],
        }}
      />,
    );

    expect(screen.queryByText("Compliance 100%")).not.toBeInTheDocument();
    expect(screen.queryByText(/100% of 8 evaluated controls/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/0 frameworks need attention/i)).not.toBeInTheDocument();
    // Same treatment the Trust Center already uses for this status: an explicit
    // em dash, not a hidden chip that leaves the reader guessing.
    expect(screen.getByText("Compliance —")).toBeInTheDocument();
    expect(screen.getByText(/Control evaluation unavailable for completed scans/i)).toBeInTheDocument();
  });

  it("never renders a green PASS for a framework with zero evaluated controls (#3889)", () => {
    render(
      <OverviewCockpit
        {...baseProps}
        compliance={{
          overallScore: 100,
          overallStatus: "pass",
          evaluatedControls: 10,
          totalControls: 20,
          frameworks: [
            // Evaluated (some findings mapped) — legitimately shows.
            { id: "cis", label: "CIS Controls v8", kind: "scored", pass: 8, warn: 1, fail: 1, total: 10 },
            // Scan ran but nothing mapped: 0 evaluated must read "Not evaluated".
            { id: "soc2", label: "SOC 2", kind: "scored", pass: 0, warn: 0, fail: 0, total: 65 },
          ],
        }}
      />,
    );

    expect(screen.getByText("SOC 2")).toBeInTheDocument();
    expect(screen.getByText(/Not evaluated · 0\/65 controls/i)).toBeInTheDocument();
    // The unevaluated framework must not claim any pass count.
    expect(screen.queryByText(/0\/65 pass/i)).not.toBeInTheDocument();
  });

  it("shows four priority frameworks and expands the rest in a keyboard-accessible region", async () => {
    const user = userEvent.setup();
    const frameworks = Array.from({ length: 9 }, (_, index) => ({
      id: `framework-${index + 1}`,
      label: `Framework ${index + 1}`,
      kind: "scored" as const,
      pass: index === 8 ? 0 : 1,
      warn: 0,
      fail: index === 8 ? 1 : 0,
      total: 1,
    }));

    render(
      <OverviewCockpit
        {...baseProps}
        compliance={{
          overallScore: 88,
          overallStatus: "fail",
          evaluatedControls: 9,
          totalControls: 9,
          frameworks,
        }}
      />,
    );

    expect(screen.getByText(/1 framework needs attention/i)).toBeInTheDocument();
    expect(screen.getByText("8/9 evaluated controls pass")).toBeVisible();
    expect(screen.queryByText("Framework 8")).not.toBeInTheDocument();
    expect(screen.getByText("Framework 9")).toBeVisible();
    const summary = screen.getByTestId("overview-evaluated-frameworks");
    expect(within(summary).getAllByRole("link")).toHaveLength(4);
    expect(within(summary).queryByText(/^fail$/i)).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Show all 9 control frameworks" }));
    expect(screen.getByText("Framework 8")).toBeVisible();
    expect(within(summary).getAllByRole("link")).toHaveLength(9);
    expect(within(summary).getByRole("region", { name: "Control framework list" })).toHaveAttribute("tabindex", "0");
  });

  it("explains nonlinear pressure and the worse scan posture without subtracting the inputs", async () => {
    const user = userEvent.setup();
    render(<OverviewCockpit {...baseProps} score={37} scoreFloored={true} scoreBreakdown={[
      { driver: "critical", label: "Critical findings", count: 2, weight: 12, contribution: 24 },
      { driver: "high", label: "High findings", count: 10, weight: 6, contribution: 60 },
      { driver: "other", label: "Other findings", count: 61, weight: 2, contribution: 122 },
    ]} />);
    await user.click(screen.getByRole("tab", { name: "Posture" }));
    await user.click(screen.getByRole("button", { name: /What influences this score/ }));
    expect(screen.getByText("Total weighted pressure: 206.0")).toBeVisible();
    expect(screen.getByText(/nonlinear/i)).toBeVisible();
    expect(screen.getByText(/worse recorded scan posture/i)).toBeVisible();
    expect(screen.getByText("37%")).toBeVisible();
    expect(screen.queryByText(/points off 100|Score = 100|−122/)).not.toBeInTheDocument();
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
    expect(screen.getByText("24.0")).toBeInTheDocument();
    // Bars represent proportions of weighted pressure, never score deductions.
    expect(screen.getByTestId("score-pressure-critical")).toHaveStyle({ width: "80%" });
    expect(screen.getByTestId("score-pressure-high")).toHaveStyle({ width: "20%" });
    expect(screen.getByText(/Bars show each input.s share of weighted pressure/)).toBeInTheDocument();
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

    await user.click(screen.getByRole("tab", { name: "Posture" }));
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
          evaluatedControls: 10,
          totalControls: 10,
          frameworks: [{ id: "cis", label: "CIS Controls v8", kind: "scored", pass: 10, warn: 0, fail: 0, total: 10 }],
        }}
      />,
    );

    expect(screen.getByText("CIS Controls v8")).toBeVisible();
    await user.click(screen.getByRole("button", { name: /Control frameworks/i }));
    expect(screen.getByText("CIS Controls v8")).not.toBeVisible();
  });
});
