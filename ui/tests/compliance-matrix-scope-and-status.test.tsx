/**
 * The matrix must say what it covers, and render every status it receives.
 *
 * Two defects, both found by the rendered-UI audit on one screen:
 *
 * **1. It contradicts the tiles above it.** The tiles read
 * "150 of 195 controls evaluated" (20 passing + 130 failing); the Matrix tab
 * directly below reads "115 of 115 controls". Both numbers are correct about
 * themselves — the matrix deliberately covers six AI-specific frameworks
 * (OWASP LLM / MCP / Agentic, ATLAS, NIST AI RMF, EU AI Act) while the tiles
 * count all sixteen — but nothing on screen says the scopes differ, so a reader
 * sees 35 evaluated controls vanish between two adjacent panels.
 *
 * Same judgement as the NIST catalog line: when two honest numbers on one
 * screen measure different things, the fix is to say so, not to force them
 * equal.
 *
 * **2. It renders blank badges.** The status cell keyed `styles`/`labels` on
 * `pass | warning | fail` only. #4709 reclassified MITRE ATLAS as an
 * applicability overlay, so its 65 controls now arrive as `applicable` /
 * `not_applicable`, and other frameworks send `not_evaluated`. For those,
 * `labels[s]` is `undefined` — an empty pill — and `styles[s]` interpolates the
 * literal string "undefined" into the class list.
 */

import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { ComplianceMatrix } from "@/components/compliance-matrix";
import type { ComplianceResponse } from "@/lib/api";

function control(code: string, name: string, status: string) {
  return {
    code,
    name,
    status,
    findings: 0,
    severity_breakdown: {},
    affected_packages: [],
    affected_agents: [],
  };
}

function matrixData(): ComplianceResponse {
  return {
    overall_score: 13,
    overall_status: "fail",
    evaluated_controls: 150,
    total_controls: 195,
    coverage_pct: 76.9,
    scan_count: 1,
    latest_scan: "2026-08-10T00:00:00Z",
    has_mcp_context: true,
    summary: {},
    owasp_llm_top10: [control("LLM01", "Prompt Injection", "fail")],
    owasp_mcp_top10: [control("MCP01", "Tool Poisoning", "warning")],
    owasp_agentic_top10: [control("AGT01", "Agent Hijack", "pass")],
    // Post-#4709 ATLAS: an applicability overlay, not pass/fail.
    mitre_atlas: [
      control("AML.T0010", "AI Supply Chain Compromise", "applicable"),
      control("AML.T0011", "User Execution", "not_applicable"),
    ],
    nist_ai_rmf: [control("MEASURE-2.9", "Model Explanation", "not_evaluated")],
    eu_ai_act: [control("ART-15", "Accuracy and Robustness", "fail")],
  } as unknown as ComplianceResponse;
}

describe("compliance matrix scope", () => {
  it("says which frameworks it covers, so its count cannot read as the page total", () => {
    render(<ComplianceMatrix data={matrixData()} />);
    const body = document.body.textContent ?? "";
    // The page total is 150 of 195; the matrix counts 7. Without a scope label
    // the two adjacent numbers simply disagree.
    expect(body).toMatch(/AI framework|AI-specific|6 framework/i);
  });
});

describe("compliance matrix status rendering", () => {
  it("never renders an empty status badge", () => {
    render(<ComplianceMatrix data={matrixData()} />);
    const rows = document.querySelectorAll("table tbody tr");
    expect(rows.length).toBeGreaterThan(0);
    for (const row of rows) {
      const cells = row.querySelectorAll("td");
      const statusCell = cells[3];
      expect(statusCell?.textContent?.trim(), `empty status badge in row: ${row.textContent}`).toBeTruthy();
    }
  });

  it("never emits the literal string 'undefined' into a class list", () => {
    render(<ComplianceMatrix data={matrixData()} />);
    const offenders = Array.from(document.querySelectorAll("[class*='undefined']"));
    expect(offenders.map((el) => el.className)).toEqual([]);
  });

  it("labels an applicability status as applicability, not as a pass", () => {
    render(<ComplianceMatrix data={matrixData()} />);
    const table = screen.getByRole("table");
    expect(within(table).getByText(/^Applicable$/i)).toBeInTheDocument();
    expect(within(table).getByText(/^Not applicable$/i)).toBeInTheDocument();
  });

  it("renders not_evaluated as prose rather than a raw enum", () => {
    render(<ComplianceMatrix data={matrixData()} />);
    const table = screen.getByRole("table");
    expect(within(table).getByText(/^Not evaluated$/i)).toBeInTheDocument();
    expect(within(table).queryByText("not_evaluated")).toBeNull();
  });

  it("still renders the scored statuses it always did", () => {
    render(<ComplianceMatrix data={matrixData()} />);
    const table = screen.getByRole("table");
    expect(within(table).getByText(/^Pass$/)).toBeInTheDocument();
    expect(within(table).getByText(/^Warning$/)).toBeInTheDocument();
    expect(within(table).getAllByText(/^Fail$/).length).toBeGreaterThan(0);
  });
});
