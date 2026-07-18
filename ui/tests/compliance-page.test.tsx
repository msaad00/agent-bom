import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import CompliancePage from "@/app/compliance/page";

vi.mock("next/navigation", () => ({
  useSearchParams: () => new URLSearchParams(""),
}));

// CIS drill-down fetches its own benchmark data on mount — stub it so the
// compliance page test stays focused on the dense framework/control surface.
vi.mock("@/components/cis-benchmark-detail", () => ({
  CISBenchmarkDetail: () => <div>cis benchmark</div>,
}));

// NIST 800-53 catalog drill also fetches its own data on mount — stub it so
// this page test only verifies the always-visible exec-line wiring (sourced
// straight off the already-loaded getCompliance() fixture below), leaving the
// per-control drill behavior to nist-800-53-catalog-detail.test.tsx.
vi.mock("@/components/nist-800-53-catalog-detail", () => ({
  Nist80053CatalogDetail: () => <div>nist 800-53 catalog drill</div>,
}));

const { compliance } = vi.hoisted(() => {
  const control = (
    code: string,
    name: string,
    status: "pass" | "warning" | "fail",
    findings: number,
  ) => ({
    code,
    name,
    findings,
    status,
    severity_breakdown: {},
    affected_packages: [],
    affected_agents: [],
  });
  const emptySummary = Object.fromEntries(
    [
      "owasp",
      "owasp_mcp",
      "atlas",
      "nist",
      "owasp_agentic",
      "eu_ai_act",
      "nist_csf",
      "iso_27001",
      "soc2",
      "cis",
      "cmmc",
      "nist_800_53",
      "fedramp",
      "pci_dss",
    ].flatMap((k) => [
      [`${k}_pass`, 0],
      [`${k}_warn`, 0],
      [`${k}_fail`, 0],
    ]),
  ) as Record<string, number>;
  return {
    compliance: {
      overall_score: 72,
      overall_status: "warning" as const,
      scan_count: 3,
      latest_scan: "2026-07-14T00:00:00Z",
      has_mcp_context: true,
      has_agent_context: true,
      owasp_llm_top10: [
        control("LLM01", "Prompt Injection", "fail", 4),
        control("LLM02", "Insecure Output Handling", "pass", 0),
      ],
      owasp_mcp_top10: [control("MCP01", "Tool Poisoning", "warning", 1)],
      mitre_atlas: [],
      nist_ai_rmf: [],
      owasp_agentic_top10: [],
      eu_ai_act: [],
      nist_csf: [],
      iso_27001: [],
      soc2: [],
      cis_controls: [],
      cmmc: [],
      nist_800_53: [],
      fedramp: [],
      pci_dss: [],
      aisvs_benchmark: { checks: [], summary: {} },
      nist_800_53_catalog: {
        framework: "nist-800-53",
        framework_key: "nist_800_53_catalog",
        framework_label: "NIST SP 800-53 Rev 5",
        representation: "catalog",
        source: "framework_control_catalog",
        vendor_asserted: true,
        status: "fail" as const,
        score: 62.5,
        summary: {
          pass: 3,
          fail: 4,
          warning: 1,
          error: 0,
          evaluated: 8,
          not_evaluated: 1006,
          catalog_size: 1014,
          coverage_pct: 0.79,
          score: 62.5,
        },
        controls: [],
        iso_27001_derived: {
          source: "nist_800_53_to_iso_27001_crosswalk",
          note: "ISO/IEC 27001:2022 Annex A control IDs implicated by the failing NIST controls.",
          controls: [],
        },
      },
      summary: {
        ...emptySummary,
        owasp_pass: 1,
        owasp_fail: 1,
        owasp_mcp_warn: 1,
        aisvs_pass: 0,
        aisvs_fail: 0,
        aisvs_error: 0,
        aisvs_not_applicable: 0,
      },
    },
  };
});

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    api: {
      getCompliance: vi.fn().mockResolvedValue(compliance),
      getFrameworkCatalogs: vi.fn().mockResolvedValue({ frameworks: {} }),
      getHubPosture: vi
        .fn()
        .mockResolvedValue({ totals: { combined: 0, native: 0, hub: 0 } }),
      // The catalog drill component is mocked out above, but stub its API
      // call too in case any other codepath reaches it during this test.
      getNist80053Catalog: vi.fn().mockResolvedValue(compliance.nist_800_53_catalog),
    },
  };
});

describe("CompliancePage (dense restyle)", () => {
  it("renders KPI strip, frameworks table, and control detail via split layout", async () => {
    render(<CompliancePage />);

    const strip = await screen.findByTestId("compliance-kpi-strip");
    expect(within(strip).getByText("Overall")).toBeInTheDocument();
    expect(within(strip).getByText("Passing")).toBeInTheDocument();
    expect(within(strip).getByText("Failing")).toBeInTheDocument();

    const table = screen.getByTestId("compliance-frameworks-table");
    // Short labels appear as the primary framework name.
    expect(within(table).getByText("LLM")).toBeInTheDocument();

    // The first failing framework (OWASP LLM) is auto-selected, so its
    // controls render in the detail pane.
    await waitFor(() =>
      expect(screen.getByText("Prompt Injection")).toBeInTheDocument(),
    );
  });

  it("surfaces the NIST SP 800-53 catalog exec line, visible without expanding", async () => {
    render(<CompliancePage />);
    await screen.findByTestId("compliance-kpi-strip");

    // The exec-altitude headline (score + honest evaluated/not_evaluated/error
    // buckets + coverage) comes straight off the already-loaded getCompliance()
    // fixture, so it is visible even though the drill Collapsible defaults open
    // and its child component (the per-control drill) is mocked out above.
    const section = screen.getByTestId("nist-800-53-catalog-section");
    expect(within(section).getByText("NIST SP 800-53 Rev 5")).toBeInTheDocument();
    expect(within(section).getByText(/vendor-asserted/i)).toBeInTheDocument();
    expect(within(section).getByText(/62\.5% score/)).toBeInTheDocument();
    expect(within(section).getByText(/8 evaluated/)).toBeInTheDocument();
    expect(within(section).getByText(/1,006 not evaluated/)).toBeInTheDocument();
    expect(within(section).getByText(/0 error/)).toBeInTheDocument();
    expect(within(section).getByText(/0\.79% coverage/)).toBeInTheDocument();
    expect(within(section).getByText("nist 800-53 catalog drill")).toBeInTheDocument();
  });

  it("opens the control drawer when a control row is clicked", async () => {
    render(<CompliancePage />);
    await screen.findByTestId("compliance-kpi-strip");

    const injection = await screen.findByText("Prompt Injection");
    fireEvent.click(injection);

    await waitFor(() =>
      expect(
        screen.getByRole("dialog", { name: /Control details for LLM01/i }),
      ).toBeInTheDocument(),
    );
  });
});
