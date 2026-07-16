import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import type { ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import FindingsPage from "@/app/findings/page";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    listJobs: vi.fn(),
    getScan: vi.fn(),
    listFindings: vi.fn(),
    listFindingTriage: vi.fn(),
    createException: vi.fn(),
    exportFindingTriageVex: vi.fn(),
    getPostureCounts: vi.fn(),
  },
}));

vi.mock("next/navigation", () => ({
  useSearchParams: () => new URLSearchParams(),
  useRouter: () => ({ replace: vi.fn() }),
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

function scanJob() {
  return {
    job_id: "scan-1",
    status: "done",
    created_at: "2026-07-01T00:00:00Z",
    request: {},
    result: {
      agents: [
        {
          name: "developer-copilot",
          mcp_servers: [
            {
              name: "github-mcp",
              packages: [
                {
                  name: "better-sqlite3",
                  vulnerabilities: [
                    {
                      id: "CVE-2026-1234",
                      severity: "critical",
                      summary: "Remote command execution in package binding",
                      description: "Remote command execution in package binding",
                      cvss_score: 9.8,
                      epss_score: 0.71,
                      fixed_version: "11.7.0",
                      references: ["https://osv.dev/vulnerability/CVE-2026-1234"],
                      advisory_sources: ["OSV"],
                      aliases: [],
                    },
                  ],
                },
              ],
            },
          ],
        },
      ],
      blast_radius: [
        {
          vulnerability_id: "CVE-2026-1234",
          cvss_score: 9.8,
          epss_score: 0.71,
          fixed_version: "11.7.0",
          affected_servers: ["github-mcp"],
          exposed_credentials: ["GITHUB_TOKEN"],
          reachable_tools: ["repo_write"],
          graph_reachable: true,
          graph_min_hop_distance: 2,
          attack_vector_summary: "Agent reaches vulnerable MCP package.",
        },
      ],
      remediation_plan: [],
    },
  };
}

describe("FindingsPage", () => {
  beforeEach(() => {
    apiMock.listJobs.mockReset();
    apiMock.getScan.mockReset();
    apiMock.listFindings.mockReset();
    apiMock.listFindingTriage.mockReset();
    apiMock.createException.mockReset();
    apiMock.exportFindingTriageVex.mockReset();
    apiMock.getPostureCounts.mockReset();

    apiMock.listJobs.mockResolvedValue({
      jobs: [
        {
          job_id: "scan-1",
          status: "done",
          created_at: "2026-07-01T00:00:00Z",
        },
      ],
    });
    apiMock.getScan.mockResolvedValue(scanJob());
    apiMock.listFindings.mockResolvedValue({ findings: [], total: 0 });
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

  it("keeps findings as a compact queue and opens evidence in a drawer", async () => {
    render(<FindingsPage />);

    expect(await screen.findByText("Findings queue")).toBeInTheDocument();
    expect(screen.getByText("25 per page")).toBeInTheDocument();
    expect(await screen.findByText("CVE-2026-1234")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Open details for CVE-2026-1234" }));

    const drawer = await screen.findByRole("dialog", { name: "Finding details for CVE-2026-1234" });
    expect(within(drawer).getByText("Evidence drawer")).toBeInTheDocument();
    expect(within(drawer).getByText("Agent reaches vulnerable MCP package.")).toBeInTheDocument();
    fireEvent.click(within(drawer).getByRole("button", { name: "Exposure path" }));
    expect(within(drawer).getAllByText("GITHUB_TOKEN")).toHaveLength(2);

    const closeButtons = within(drawer).getAllByRole("button", { name: "Close" });
    fireEvent.click(closeButtons.at(-1)!);

    await waitFor(() => {
      expect(screen.queryByRole("dialog", { name: "Finding details for CVE-2026-1234" })).not.toBeInTheDocument();
    });
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

  it("defaults the time window to 90 days and can widen to all history (#4009)", async () => {
    apiMock.listFindings.mockResolvedValue({
      findings: [],
      total: 0,
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
});
