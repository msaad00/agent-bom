/**
 * Behaviour guard for the one component built on TanStack Table.
 *
 * `ComplianceMatrix` is the only consumer of `@tanstack/react-table` in the
 * app, and it had no test. That made the v8 -> v9 upgrade unverifiable: v9
 * removes `useReactTable` and `createColumnHelper` from the package root and
 * moves the row-model factories behind a `/legacy` entry point, so the
 * migration is a real API change, not a version bump. Without a test, "it
 * compiles" would have been the only evidence that sorting, per-column
 * filtering and global search still worked.
 *
 * So these assert the table's *behaviour* — not its wiring — and are written
 * to pass identically on either major. They were run green against v8 before
 * the upgrade, and again after.
 */

import { fireEvent, render, screen, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { ComplianceMatrix } from "@/components/compliance-matrix";
import type { ComplianceResponse } from "@/lib/api";

function control(code: string, name: string, status: string, findings = 0) {
  return {
    code,
    name,
    status,
    findings,
    severity_breakdown: {},
    affected_packages: [],
    affected_agents: [],
  };
}

/** Two frameworks so the framework filter has something to exclude. */
function matrixData(): ComplianceResponse {
  return {
    overall_score: 40,
    overall_status: "fail",
    evaluated_controls: 4,
    total_controls: 4,
    coverage_pct: 100,
    scan_count: 1,
    latest_scan: "2026-08-10T00:00:00Z",
    has_mcp_context: true,
    summary: {},
    owasp_llm_top10: [
      control("LLM01", "Prompt Injection", "fail", 3),
      control("LLM02", "Insecure Output Handling", "pass"),
    ],
    owasp_mcp_top10: [
      control("MCP01", "Tool Poisoning", "warning", 1),
      control("MCP02", "Server Impersonation", "pass"),
    ],
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
  } as unknown as ComplianceResponse;
}

function bodyRowText(): string[] {
  const table = screen.getByRole("table");
  const body = table.querySelectorAll("tbody tr");
  return Array.from(body).map((row) => row.textContent ?? "");
}

describe("ComplianceMatrix", () => {
  it("renders one row per mapped control across every framework", () => {
    render(<ComplianceMatrix data={matrixData()} />);
    const rows = bodyRowText();
    expect(rows).toHaveLength(4);
    expect(rows.join(" ")).toContain("LLM01");
    expect(rows.join(" ")).toContain("MCP01");
  });

  it("narrows to matching controls as the reader searches", () => {
    render(<ComplianceMatrix data={matrixData()} />);
    fireEvent.change(screen.getByPlaceholderText(/search controls/i), {
      target: { value: "Prompt Injection" },
    });
    const rows = bodyRowText();
    expect(rows).toHaveLength(1);
    expect(rows[0]).toContain("LLM01");
  });

  it("reorders rows when a sortable header is clicked", () => {
    render(<ComplianceMatrix data={matrixData()} />);
    const header = screen.getByRole("table").querySelector("thead");
    const controlHeader = within(header as HTMLElement).getByText("Control");

    const before = bodyRowText();
    fireEvent.click(controlHeader);
    const ascending = bodyRowText();
    fireEvent.click(controlHeader);
    const descending = bodyRowText();

    expect(ascending).toHaveLength(before.length);
    // Sorting is only proven by the order actually changing between directions.
    expect(descending).not.toEqual(ascending);
    expect([...descending].reverse()).toEqual(ascending);
  });

  it("reports how many of the total rows survive the current filter", () => {
    render(<ComplianceMatrix data={matrixData()} />);
    expect(screen.getByText(/4 of 4 controls/)).toBeInTheDocument();

    fireEvent.change(screen.getByPlaceholderText(/search controls/i), {
      target: { value: "MCP" },
    });
    expect(screen.getByText(/2 of 4 controls/)).toBeInTheDocument();
  });

  it("keeps the evidence-triage disclaimer visible", () => {
    render(<ComplianceMatrix data={matrixData()} />);
    expect(screen.getByTestId("compliance-matrix-helper-disclaimer")).toBeVisible();
  });

  it("makes matrix rows drillable via onSelectControl", () => {
    const onSelect = vi.fn();
    render(<ComplianceMatrix data={matrixData()} onSelectControl={onSelect} />);

    const row = screen.getByText("LLM01").closest("tr");
    expect(row).not.toBeNull();
    fireEvent.click(row as HTMLElement);

    expect(onSelect).toHaveBeenCalledTimes(1);
    const payload = onSelect.mock.calls[0]![0];
    expect(payload.control.code).toBe("LLM01");
    expect(payload.frameworkLabel).toBe("OWASP LLM");
    // The catalog map travels with the control so the drawer can resolve names.
    expect(typeof payload.catalog).toBe("object");
  });

  it("opens the drawer on keyboard activation of a row", () => {
    const onSelect = vi.fn();
    render(<ComplianceMatrix data={matrixData()} onSelectControl={onSelect} />);

    const row = screen.getByText("MCP01").closest("tr") as HTMLElement;
    row.focus();
    fireEvent.keyDown(row, { key: "Enter" });
    expect(onSelect).toHaveBeenCalledTimes(1);
    expect(onSelect.mock.calls[0]![0].control.code).toBe("MCP01");
  });
});
