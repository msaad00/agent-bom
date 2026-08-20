import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import type { ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import FindingsPage from "@/app/findings/page";

const { apiMock, navigationState, authState, routerReplace } = vi.hoisted(() => ({
  apiMock: {
    listFindings: vi.fn(),
    listFindingTriage: vi.fn(),
    createException: vi.fn(),
    exportFindingTriageVex: vi.fn(),
    getPostureCounts: vi.fn(),
  },
  navigationState: { query: "" },
  authState: { canManageExceptions: true },
  routerReplace: vi.fn(),
}));

vi.mock("next/navigation", () => ({
  useSearchParams: () => new URLSearchParams(navigationState.query),
  useRouter: () => ({ replace: routerReplace }),
  usePathname: () => "/findings",
}));

vi.mock("next/link", () => ({
  default: ({ href, children }: { href: string; children: ReactNode }) => <a href={href}>{children}</a>,
}));

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    api: apiMock,
  };
});

vi.mock("@/components/auth-provider", () => ({
  useAuthState: () => ({
    session: { auth_required: true, role: authState.canManageExceptions ? "analyst" : "viewer" },
    hasCapability: (capability: string) => capability === "exceptions.manage" && authState.canManageExceptions,
  }),
}));

const canonicalFinding = {
  id: "finding-1",
  finding_class: "vulnerability",
  severity: "critical",
  cve_id: "CVE-2026-1234",
  title: "Remote command execution in package binding",
  description: "Remote command execution in package binding",
  asset: { name: "better-sqlite3", asset_type: "package" },
  source: "osv",
  scan_id: "scan-1",
  cvss_score: 9.8,
  epss_score: 0.71,
  fixed_version: "11.7.0",
  references: ["https://osv.dev/vulnerability/CVE-2026-1234"],
  advisory_sources: ["OSV"],
  affected_agents: ["developer-copilot"],
  affected_servers: ["github-mcp"],
  exposed_credentials: ["GITHUB_TOKEN"],
  exposed_tools: ["repo_write"],
  attack_vector_summary: "Agent reaches vulnerable MCP package.",
};

describe("FindingsPage", () => {
  beforeEach(() => {
    authState.canManageExceptions = true;
    navigationState.query = "";
    apiMock.listFindings.mockReset();
    apiMock.listFindingTriage.mockReset();
    apiMock.createException.mockReset();
    apiMock.exportFindingTriageVex.mockReset();
    apiMock.getPostureCounts.mockReset();
    routerReplace.mockReset();

    apiMock.listFindings.mockResolvedValue({
      schema_version: "v1",
      findings: [canonicalFinding],
      total: 1,
      has_more: false,
      next_cursor: "",
    });
    apiMock.listFindingTriage.mockResolvedValue({ triage: [] });
    apiMock.getPostureCounts.mockResolvedValue({
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      total: 0,
      kev: 0,
      compound_issues: 0,
    });
  });

  it("does not assert zero findings while the authoritative total is loading", async () => {
    let resolveFindings!: (value: {
      schema_version: string;
      findings: typeof canonicalFinding[];
      total: number;
      has_more: boolean;
      next_cursor: string;
    }) => void;
    apiMock.listFindings.mockReturnValue(
      new Promise((resolve) => {
        resolveFindings = resolve;
      }),
    );

    render(<FindingsPage />);

    expect(screen.getByTestId("findings-loading-state")).toBeInTheDocument();
    expect(screen.getByText(/Total unavailable/i)).toBeInTheDocument();
    expect(screen.queryByText(/0 findings/i)).not.toBeInTheDocument();

    await act(async () => {
      resolveFindings({
        schema_version: "v1",
        findings: [canonicalFinding],
        total: 1,
        has_more: false,
        next_cursor: "",
      });
    });
    expect(await screen.findByText("CVE-2026-1234")).toBeInTheDocument();
  });

  it("keeps findings as a compact queue and opens evidence in a drawer", async () => {
    render(<FindingsPage />);

    expect(await screen.findByText("Findings queue")).toBeInTheDocument();
    expect(screen.getByText("25 per page")).toBeInTheDocument();
    expect(await screen.findByText("CVE-2026-1234")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Open details for CVE-2026-1234" }));

    const drawer = await screen.findByRole("dialog", { name: "Finding details for CVE-2026-1234" });
    expect(within(drawer).getByText("Evidence drawer")).toBeInTheDocument();
    expect(within(drawer).getByText("Agent reaches vulnerable MCP package.")).toBeInTheDocument();
    expect(within(drawer).getByRole("link", { name: /Open in investigation/ })).toHaveAttribute(
      "href",
      expect.stringContaining("/security-graph"),
    );
    expect(within(drawer).queryByRole("tab", { name: "Exposure path" })).not.toBeInTheDocument();
    expect(drawer.querySelector("aside")).toHaveClass("max-w-2xl");
    expect(within(drawer).queryByText("Unavailable")).not.toBeInTheDocument();
    expect(within(drawer).queryByText("Last scanned")).not.toBeInTheDocument();
    expect(within(drawer).getByText(/Source did not provide/i)).toBeInTheDocument();

    const closeButtons = within(drawer).getAllByRole("button", { name: "Close" });
    fireEvent.click(closeButtons.at(-1)!);

    await waitFor(() => {
      expect(screen.queryByRole("dialog", { name: "Finding details for CVE-2026-1234" })).not.toBeInTheDocument();
    });
  });

  it("deep-links the exact finding row when a CVE affects more than one asset", async () => {
    navigationState.query = "finding=finding-2";
    apiMock.listFindings.mockResolvedValue({
      schema_version: "v1",
      findings: [
        canonicalFinding,
        {
          ...canonicalFinding,
          id: "finding-2",
          asset: { name: "second-package", asset_type: "package" },
          scan_id: "scan-2",
        },
      ],
      total: 2,
      has_more: false,
      next_cursor: "",
    });

    render(<FindingsPage />);

    const drawer = await screen.findByRole("dialog", {
      name: "Finding details for CVE-2026-1234",
    });
    expect(within(drawer).getByText("second-package")).toBeInTheDocument();

    const closeButtons = within(drawer).getAllByRole("button", { name: "Close" });
    fireEvent.click(closeButtons.at(-1)!);
    await waitFor(() => {
      expect(routerReplace).toHaveBeenLastCalledWith("/findings", { scroll: false });
    });

    fireEvent.click(screen.getAllByRole("button", { name: "Open details for CVE-2026-1234" })[0]!);
    await waitFor(() => {
      expect(routerReplace).toHaveBeenLastCalledWith(
        "/findings?finding=finding-1",
        { scroll: false },
      );
    });
  });

  it("links package and agent identities back into the findings investigation", async () => {
    render(<FindingsPage />);

    expect(await screen.findByRole("link", { name: "better-sqlite3" })).toHaveAttribute(
      "href",
      "/findings?q=better-sqlite3",
    );
    expect(screen.getByRole("link", { name: "developer-copilot" })).toHaveAttribute(
      "href",
      "/findings?q=developer-copilot",
    );
  });

  it("renders exception and triage writes disabled for a viewer", async () => {
    authState.canManageExceptions = false;
    render(<FindingsPage />);

    expect(await screen.findByText("CVE-2026-1234")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Mark false positive" })).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: "Open details for CVE-2026-1234" }));
    const drawer = await screen.findByRole("dialog", { name: "Finding details for CVE-2026-1234" });
    fireEvent.click(within(drawer).getByRole("tab", { name: "Triage" }));
    expect(within(drawer).getByRole("button", { name: "Investigate" })).toBeDisabled();
    expect(within(drawer).getByRole("button", { name: "Affected" })).toBeDisabled();
    expect(within(drawer).getByRole("button", { name: "Not affected" })).toBeDisabled();
  });

  it("uses the persisted package identity when an older finding has no asset object", async () => {
    apiMock.listFindings.mockResolvedValue({
      schema_version: "v1",
      findings: [
        {
          id: "finding-legacy-asset",
          finding_class: "vulnerability",
          severity: "high",
          cve_id: "CVE-2026-7777",
          package: "requests@2.32.4",
          source: "osv",
        },
      ],
      total: 1,
      has_more: false,
      next_cursor: "",
    });

    render(<FindingsPage />);

    expect(await screen.findByText("requests@2.32.4")).toBeInTheDocument();
    expect(screen.queryByText("asset")).not.toBeInTheDocument();
  });

  it("projects canonical vulnerability intelligence into the finding drawer without inventing missing facts", async () => {
    apiMock.listFindings.mockResolvedValue({
      total: 1,
      findings: [
        {
          id: "finding-intel-1",
          severity: "high",
          cvss_severity: "high",
          cve_id: "CVE-2026-4242",
          title: "PyYAML unsafe deserialization",
          asset: { name: "pyyaml", asset_type: "package" },
          source: "osv",
          scan_id: "scan-intel-1",
          cvss_score: 8.8,
          cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
          epss_score: 0.42,
          is_kev: true,
          fixed_version: "6.0.2",
          status: "open",
          first_seen: "2026-07-01T12:00:00Z",
          last_seen: "2026-07-21T15:30:00Z",
          scan_count: 3,
          advisory_sources: ["osv", "ghsa", "nvd", "cisa_kev"],
          aliases: ["GHSA-aaaa-bbbb-cccc"],
          references: [
            "https://osv.dev/vulnerability/CVE-2026-4242",
            "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
            "https://nvd.nist.gov/vuln/detail/CVE-2026-4242",
            "https://evil.example/phishing",
          ],
          evidence: {
            package_version: "5.3",
            epss_percentile: 97.5,
            kev_date_added: "2026-01-04",
            severity_source: "nvd",
            match_confidence_tier: "osv_range",
          },
        },
      ],
    });
    apiMock.listFindingTriage.mockResolvedValue({
      triage: [
        {
          id: "triage-1",
          vulnerability_id: "CVE-2026-4242",
          package: "pyyaml",
          server_name: "",
          queue_state: "assigned",
          decision: "under_investigation",
          decision_reason: "Validate runtime exposure.",
          assignee: "security-platform",
          created_by: "operator",
          created_at: "2026-07-22T12:00:00Z",
          reviewed_at: "",
          expires_at: "2026-08-05T12:00:00Z",
          tenant_id: "tenant-test",
          vex_eligible: false,
        },
      ],
    });

    render(<FindingsPage />);
    expect(await screen.findByText("CVE-2026-4242")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Open details for CVE-2026-4242" }));

    const drawer = await screen.findByRole("dialog", { name: "Finding details for CVE-2026-4242" });
    expect(within(drawer).getByText("v3.1 · high")).toBeInTheDocument();
    expect(within(drawer).getByText("97.5th percentile")).toBeInTheDocument();
    expect(within(drawer).getByText("Known exploited")).toBeInTheDocument();
    expect(within(drawer).getByText(/First seen/i)).toBeInTheDocument();
    expect(within(drawer).getByText(/Last observed/i)).toBeInTheDocument();
    expect(within(drawer).queryByText(/Last scanned/i)).not.toBeInTheDocument();
    expect(within(drawer).getByText("5.3 → 6.0.2")).toBeInTheDocument();
    expect(within(drawer).getByText("security-platform")).toBeInTheDocument();
    expect(within(drawer).queryByLabelText(/SLA: unavailable/i)).not.toBeInTheDocument();

    fireEvent.click(within(drawer).getByRole("tab", { name: "Evidence" }));
    expect(within(drawer).getByRole("link", { name: /OSV/i })).toHaveAttribute(
      "href",
      "https://osv.dev/vulnerability/CVE-2026-4242",
    );
    expect(within(drawer).getByRole("link", { name: /GitHub Advisory/i })).toHaveAttribute(
      "href",
      "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
    );
    expect(within(drawer).getByRole("link", { name: /NVD/i })).toHaveAttribute(
      "href",
      "https://nvd.nist.gov/vuln/detail/CVE-2026-4242",
    );
    expect(within(drawer).queryByRole("link", { name: /evil\.example/i })).not.toBeInTheDocument();
    expect(within(drawer).getByText("osv_range")).toBeInTheDocument();
    expect(within(drawer).getByText("scan-intel-1")).toBeInTheDocument();
  });

  it("renders the same CVE across multiple assets as distinct rows with unique keys", async () => {
    // Regression: rows were keyed by the CVE label, so one CVE affecting N
    // assets collapsed to a single key — React warned and could drop rows.
    // Each unified finding carries its own UUID, so keys must stay unique.
    const consoleError = vi.spyOn(console, "error").mockImplementation(() => {});
    apiMock.listFindings.mockResolvedValue({
      total: 3,
      findings: [
        { id: "uuid-1", severity: "high", cve_id: "CVE-2020-14343", title: "PyYAML RCE", asset: { name: "agent-alpha" } },
        { id: "uuid-2", severity: "high", cve_id: "CVE-2020-14343", title: "PyYAML RCE", asset: { name: "agent-beta" } },
        { id: "uuid-3", severity: "high", cve_id: "CVE-2020-14343", title: "PyYAML RCE", asset: { name: "agent-gamma" } },
      ],
    });

    render(<FindingsPage />);

    expect(await screen.findByText("Findings queue")).toBeInTheDocument();
    await waitFor(() => {
      expect(
        screen.getAllByRole("button", { name: "Open details for CVE-2020-14343" }).length,
      ).toBe(3);
    });

    const duplicateKeyWarning = consoleError.mock.calls.some((call) =>
      String(call[0] ?? "").includes("same key"),
    );
    expect(duplicateKeyWarning).toBe(false);
    consoleError.mockRestore();
  });

  it("tucks advanced filters into a Filters (n) popover with removable active chips", async () => {
    render(<FindingsPage />);
    expect(await screen.findByText("CVE-2026-1234")).toBeInTheDocument();

    // Advanced filters start collapsed: the toggle shows no active count and no
    // chips are rendered.
    const toggle = screen.getByTestId("findings-filters-toggle");
    expect(toggle).toHaveTextContent("Filters");
    expect(toggle).not.toHaveTextContent("(1)");
    expect(screen.queryByTestId("findings-active-filters")).not.toBeInTheDocument();

    // Open the popover and pick a domain facet.
    fireEvent.click(toggle);
    const popover = screen.getByTestId("findings-filters-popover");
    fireEvent.click(within(popover).getByRole("button", { name: "ASPM" }));

    // Active count reflects the selection and a removable chip surfaces it.
    await waitFor(() =>
      expect(screen.getByTestId("findings-filters-toggle")).toHaveTextContent("Filters (1)"),
    );
    const chip = screen.getByTestId("findings-chip-domain");
    expect(chip).toHaveTextContent("Domain: ASPM");

    // Removing the chip clears the filter (count returns to zero, chip gone).
    fireEvent.click(chip);
    await waitFor(() =>
      expect(screen.queryByTestId("findings-chip-domain")).not.toBeInTheDocument(),
    );
    expect(screen.getByTestId("findings-filters-toggle")).not.toHaveTextContent("(1)");
  });

  it("honours the compliance drill-through framework/control URL and surfaces removable chips", async () => {
    navigationState.query = "framework=soc2&control=CC6.1";
    render(<FindingsPage />);
    expect(await screen.findByText("Findings queue")).toBeInTheDocument();

    // The drill-through params are forwarded to the findings API.
    await waitFor(() =>
      expect(apiMock.listFindings).toHaveBeenLastCalledWith(
        expect.objectContaining({ framework: "soc2", control: "CC6.1" }),
      ),
    );

    // Both facets surface as removable chips.
    const frameworkChip = screen.getByTestId("findings-chip-framework");
    expect(frameworkChip).toHaveTextContent("Framework: SOC2");
    const controlChip = screen.getByTestId("findings-chip-control");
    expect(controlChip).toHaveTextContent("Control: CC6.1");

    // Clearing the framework drops the control too (a control without its
    // framework is meaningless) and re-queries without either param.
    fireEvent.click(frameworkChip);
    await waitFor(() =>
      expect(screen.queryByTestId("findings-chip-framework")).not.toBeInTheDocument(),
    );
    expect(screen.queryByTestId("findings-chip-control")).not.toBeInTheDocument();
    await waitFor(() => {
      const lastCall = apiMock.listFindings.mock.calls.at(-1)?.[0] ?? {};
      expect(lastCall).not.toHaveProperty("framework");
      expect(lastCall).not.toHaveProperty("control");
    });
  });

  it("owns owner and SLA workflow filters in the URL and canonical API", async () => {
    navigationState.query = "owner=payments-security&sla=overdue";
    render(<FindingsPage />);
    expect(await screen.findByText("Findings queue")).toBeInTheDocument();

    await waitFor(() =>
      expect(apiMock.listFindings).toHaveBeenLastCalledWith(
        expect.objectContaining({ owner: "payments-security", sla: "overdue" }),
      ),
    );
    expect(screen.getByTestId("findings-chip-owner")).toHaveTextContent("Owner: payments-security");
    expect(screen.getByTestId("findings-chip-sla")).toHaveTextContent("SLA: overdue");
  });

  it("sends the selected issue class to the paginated findings API", async () => {
    render(<FindingsPage />);
    expect(await screen.findByText("Findings queue")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Misconfigurations" }));

    await waitFor(() =>
      expect(apiMock.listFindings).toHaveBeenLastCalledWith(
        expect.objectContaining({ findingClass: "misconfiguration" }),
      ),
    );
  });

  it("sends free-text search to the canonical findings API", async () => {
    render(<FindingsPage />);
    expect(await screen.findByText("Findings queue")).toBeInTheDocument();

    fireEvent.change(screen.getByPlaceholderText("Search CVE, package, agent…"), {
      target: { value: "pyyaml" },
    });

    await waitFor(() =>
      expect(apiMock.listFindings).toHaveBeenLastCalledWith(
        expect.objectContaining({ query: "pyyaml" }),
      ),
    );
  });

  it("uses server facets for whole-query facts while keeping Engineering page metrics explicit", async () => {
    apiMock.listFindings.mockResolvedValue({
      schema_version: "v1",
      findings: [
        {
          id: "finding-engineering-1",
          finding_class: "vulnerability",
          severity: "high",
          cve_id: "CVE-2026-2222",
          title: "Reachable package issue",
          asset: { name: "pkg-a", asset_type: "package" },
          source: "osv",
          last_observed: "2026-07-25T12:00:00Z",
          owner: "platform-team",
          sla_due_at: "2026-08-01T12:00:00Z",
          fixed_version: "2.0.0",
          epss_score: 0.42,
        },
      ],
      total: 13,
      total_approximate: false,
      facets: {
        finding_class: { vulnerability: 9, misconfiguration: 2, secret: 1, identity: 0, unclassified: 1 },
        severity: { critical: 2, high: 7, medium: 3, low: 1, info: 0, unknown: 0 },
        status: { open: 12, resolved: 1 },
        domain: { cspm: 2, vuln: 9, aspm: 1, dspm: 0, aispm: 1 },
        freshness: { last_24_hours: 2, last_7_days: 3, last_30_days: 4, older: 1, unavailable: 3 },
      },
      facets_approximate: false,
    });

    render(<FindingsPage />);

    expect(await screen.findByText("CVE-2026-2222")).toBeInTheDocument();
    expect(apiMock.listFindings).toHaveBeenCalledWith(expect.objectContaining({ includeFacets: true }));
    const summary = screen.getByTestId("findings-workspace-summary");
    expect(within(summary).getByText("5 observed ≤7d")).toBeInTheDocument();
    expect(within(summary).getByText("Whole query")).toBeInTheDocument();
    expect(within(summary).getAllByText("Current page")).toHaveLength(3);
    expect(screen.getByRole("columnheader", { name: "Reach / exploit" })).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: "Owner / SLA" })).toBeInTheDocument();
    expect(screen.queryByRole("columnheader", { name: "Control mapping" })).not.toBeInTheDocument();
  });

  it("labels a budget-bounded scope walk partial instead of showing a silent empty page", async () => {
    apiMock.listFindings.mockResolvedValue({
      schema_version: "v1",
      findings: [],
      total: null,
      total_approximate: true,
      has_more: true,
      next_cursor: "cursor-next",
      scope_completeness: { status: "partial", reason: "scan_budget", scanned_rows: 20000, scan_budget: 20000 },
    });

    render(<FindingsPage />);

    const notice = await screen.findByTestId("findings-scope-partial");
    expect(notice).toHaveTextContent(/Partial results/i);
    expect(notice).toHaveTextContent("20,000");
  });

  it("shows no partial-results notice when the scope walk completed", async () => {
    apiMock.listFindings.mockResolvedValue({
      schema_version: "v1",
      findings: [canonicalFinding],
      total: 1,
      scope_completeness: { status: "complete", reason: "", scanned_rows: 300, scan_budget: 20000 },
    });

    render(<FindingsPage />);

    expect(await screen.findByText("CVE-2026-1234")).toBeInTheDocument();
    expect(screen.queryByTestId("findings-scope-partial")).not.toBeInTheDocument();
  });

  it("renders persisted graph reachability without inventing evidence for non-overlapping findings", async () => {
    apiMock.listFindings.mockResolvedValue({
      schema_version: "v1",
      findings: [
        {
          ...canonicalFinding,
          graph_reachable: true,
          graph_min_hop_distance: 2,
          graph_reachable_from_agents: ["agent:developer-copilot"],
        },
        {
          ...canonicalFinding,
          id: "finding-without-a-path",
          cve_id: "CVE-2026-5678",
          title: "Static finding without graph evidence",
          graph_reachable: null,
          graph_min_hop_distance: null,
          graph_reachable_from_agents: [],
        },
      ],
      total: 2,
      facets: {
        finding_class: { vulnerability: 2, misconfiguration: 0, secret: 0, identity: 0, unclassified: 0 },
        severity: { critical: 2, high: 0, medium: 0, low: 0, info: 0, unknown: 0 },
        status: { open: 2, resolved: 0 },
        domain: { cspm: 0, vuln: 2, aspm: 0, dspm: 0, aispm: 0 },
        freshness: { last_24_hours: 0, last_7_days: 0, last_30_days: 0, older: 0, unavailable: 2 },
      },
    });

    render(<FindingsPage />);

    expect(await screen.findByText("CVE-2026-1234")).toBeInTheDocument();
    const summary = screen.getByTestId("findings-workspace-summary");
    expect(within(summary).getByText("1 reachable")).toBeInTheDocument();
    expect(within(summary).getByText("1 assessed on this page")).toBeInTheDocument();
    expect(screen.getByText("Reachable · 2 hops")).toBeInTheDocument();
  });

  it("gives Compliance distinct columns, actions, and an evidence-first drawer", async () => {
    navigationState.query = "lens=trust";
    apiMock.listFindings.mockResolvedValue({
      schema_version: "v1",
      findings: [
        {
          id: "finding-compliance-1",
          finding_class: "misconfiguration",
          severity: "high",
          title: "Public storage policy",
          asset: { name: "bucket-a", asset_type: "cloud_resource" },
          source: "cloud_cis",
          last_observed: "2026-07-25T12:00:00Z",
          compliance_tags: ["CIS-2.1"],
          controls: [{ control_id: "SOC2-CC6.6" }],
        },
      ],
      total: 1,
      facets: {
        finding_class: { vulnerability: 0, misconfiguration: 1, secret: 0, identity: 0, unclassified: 0 },
        severity: { critical: 0, high: 1, medium: 0, low: 0, info: 0, unknown: 0 },
        status: { open: 1, resolved: 0 },
        domain: { cspm: 1, vuln: 0, aspm: 0, dspm: 0, aispm: 0 },
        freshness: { last_24_hours: 1, last_7_days: 0, last_30_days: 0, older: 0, unavailable: 0 },
      },
    });
    apiMock.listFindingTriage.mockResolvedValue({
      triage: [
        {
          id: "triage-compliance-1",
          vulnerability_id: "Public storage policy",
          package: "bucket-a",
          server_name: "",
          queue_state: "decided",
          decision: "affected",
          decision_reason: "Control owner confirmed impact.",
          assignee: "grc-team",
          created_by: "operator",
          created_at: "2026-07-25T12:00:00Z",
          reviewed_at: "2026-07-25T13:00:00Z",
          expires_at: "",
          tenant_id: "tenant-test",
          vex_eligible: false,
        },
      ],
    });

    render(<FindingsPage />);

    expect(await screen.findByText("Disposition queue")).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: "Control mapping" })).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: "Evidence freshness" })).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: "Disposition / attestation" })).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: "Affected scope" })).toBeInTheDocument();
    expect(screen.queryByRole("columnheader", { name: "Reach / exploit" })).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Review evidence" }));
    const drawer = await screen.findByRole("dialog", { name: "Finding details for Public storage policy" });
    expect(within(drawer).getByRole("tab", { name: "Evidence" })).toHaveAttribute("aria-selected", "true");
    expect(within(drawer).getByText("Compliance controls")).toBeInTheDocument();
    expect(within(drawer).getByText("SOC2-CC6.6")).toBeInTheDocument();
  });

  it("does not replace an authoritative empty server query with unfiltered legacy findings", async () => {
    apiMock.listFindings.mockResolvedValue({
      schema_version: "v1",
      findings: [],
      total: 0,
      facets: {
        finding_class: { vulnerability: 0, misconfiguration: 0, secret: 0, identity: 0, unclassified: 0 },
        severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0 },
        status: { open: 0, resolved: 0 },
        domain: { cspm: 0, vuln: 0, aspm: 0, dspm: 0, aispm: 0 },
        freshness: { last_24_hours: 0, last_7_days: 0, last_30_days: 0, older: 0, unavailable: 0 },
      },
    });

    render(<FindingsPage />);

    expect(await screen.findByText("No findings found")).toBeInTheDocument();
    expect(screen.queryByText("CVE-2026-1234")).not.toBeInTheDocument();
    expect(apiMock.listFindings).toHaveBeenCalledTimes(1);
  });

  it("defaults the time window to 90 days and can widen to all history (#4009)", async () => {
    apiMock.listFindings.mockResolvedValue({
      findings: [canonicalFinding],
      total: 1,
      window: { days: 90, since: "2026-04-01T00:00:00Z", applied: true, label: "Last 90 days" },
    });

    render(<FindingsPage />);
    expect(await screen.findByText("Findings queue")).toBeInTheDocument();

    // The default window is visible (not silently applied).
    expect(screen.getByTestId("findings-window-chip")).toHaveTextContent("Last 90 days");
    await waitFor(() =>
      expect(apiMock.listFindings).toHaveBeenCalledWith(expect.objectContaining({ windowDays: 90 })),
    );

    // Widening to "All time" re-queries with windowDays: 0.
    fireEvent.click(screen.getByTestId("findings-window-chip"));
    fireEvent.change(screen.getByTestId("findings-window-select"), { target: { value: "0" } });
    await waitFor(() =>
      expect(apiMock.listFindings).toHaveBeenCalledWith(expect.objectContaining({ windowDays: 0 })),
    );
  });

  it("follows opaque continuation while labeling an intentionally unknown total", async () => {
    navigationState.query = "scope=all";
    const finding = (index: number) => ({
      id: `uuid-${index}`,
      severity: "high",
      cve_id: `CVE-2026-${String(index).padStart(4, "0")}`,
      title: `Finding ${index}`,
      asset: { name: `asset-${index}` },
    });
    apiMock.listFindings
      .mockResolvedValueOnce({
        schema_version: "v1",
        findings: Array.from({ length: 25 }, (_, index) => finding(index)),
        count: 25,
        total: null,
        total_approximate: false,
        limit: 25,
        offset: 0,
        sort: "severity",
        cursor: "",
        next_cursor: "opaque-page-2",
        has_more: true,
        warnings: [],
        window: { days: 90, since: "2026-04-18T00:00:00Z", applied: true, label: "Last 90 days" },
      })
      .mockResolvedValueOnce({
        schema_version: "v1",
        findings: [finding(25)],
        count: 1,
        total: null,
        total_approximate: false,
        limit: 25,
        offset: 0,
        sort: "severity",
        cursor: "opaque-page-2",
        next_cursor: "",
        has_more: false,
        warnings: [],
        window: { days: 90, since: "2026-04-18T00:00:00Z", applied: true, label: "Last 90 days" },
      });

    render(<FindingsPage />);

    expect(await screen.findByText("Page 1 · total unavailable")).toBeInTheDocument();
    expect(screen.getByText("Current state · Last 90 days")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Next/i }));

    await waitFor(() =>
      expect(apiMock.listFindings).toHaveBeenLastCalledWith(
        expect.objectContaining({ cursor: "opaque-page-2", windowDays: 90 }),
      ),
    );
    expect(await screen.findByText("Page 2 · total unavailable")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Next/i })).toBeDisabled();
  });

  it("shows workload runtime evidence on the Evidence tab without conflating proxy runtime", async () => {
    apiMock.listFindings.mockResolvedValue({
      total: 1,
      findings: [
        {
          id: "uuid-runtime-1",
          severity: "high",
          cve_id: "CVE-2026-9999",
          title: "Workload disk finding",
          asset: { name: "i-0abc", asset_type: "cloud_resource" },
          workload_runtime_evidence: {
            state: "runtime_ioc_observed",
            signal_count: 2,
            source_kinds: ["edr"],
            latest_observed_at: "2026-07-21T12:00:00Z",
            clean_workload_assertion: false,
          },
        },
      ],
    });

    render(<FindingsPage />);
    expect(await screen.findByText("CVE-2026-9999")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Open details for CVE-2026-9999" }));
    const drawer = await screen.findByRole("dialog", { name: "Finding details for CVE-2026-9999" });
    fireEvent.click(within(drawer).getByRole("tab", { name: "Evidence" }));
    expect(within(drawer).getByText("Workload runtime evidence")).toBeInTheDocument();
    expect(within(drawer).getByText("IOC observed")).toBeInTheDocument();
    expect(within(drawer).getByText(/not a clean-workload assertion/i)).toBeInTheDocument();
    expect(within(drawer).getByText(/Distinct from proxy\/gateway runtime evidence/i)).toBeInTheDocument();
  });
});
