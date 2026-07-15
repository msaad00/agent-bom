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
