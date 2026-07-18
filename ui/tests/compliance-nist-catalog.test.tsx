import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ComplianceNistCatalog } from "@/components/compliance-nist-catalog";
import type { NistCatalogDrill } from "@/lib/api";

// The seeded reconciliation estate (tests/test_compliance.py::_nist_catalog_scenario):
// fail 5 (SI-10, AC-3, SC-7, AC-2, IA-5), pass 1 (SC-28), error 1 (AC-6),
// evaluated 7, not_evaluated 1007, catalog 1014, score 14.3, coverage 0.69%.
// These MUST be the identical numbers the API drill / CLI / MCP report.
function scenarioDrill(): NistCatalogDrill {
  return {
    framework: "nist-800-53",
    framework_key: "nist_800_53_catalog",
    framework_label: "NIST SP 800-53 Rev 5",
    representation: "catalog",
    source: "framework_control_catalog",
    vendor_asserted: true,
    status: "fail",
    score: 14.3,
    summary: {
      pass: 1,
      fail: 5,
      warning: 0,
      error: 1,
      evaluated: 7,
      not_evaluated: 1007,
      catalog_size: 1014,
      coverage_pct: 0.69,
      score: 14.3,
    },
    families: [
      { family: "AC", total: 120, evaluated: 3, pass: 0, fail: 2, warning: 0, error: 1, not_evaluated: 117 },
      { family: "IA", total: 90, evaluated: 1, pass: 0, fail: 1, warning: 0, error: 0, not_evaluated: 89 },
      { family: "SC", total: 110, evaluated: 2, pass: 1, fail: 1, warning: 0, error: 0, not_evaluated: 108 },
      { family: "SI", total: 80, evaluated: 1, pass: 0, fail: 1, warning: 0, error: 0, not_evaluated: 79 },
      { family: "AU", total: 60, evaluated: 0, pass: 0, fail: 0, warning: 0, error: 0, not_evaluated: 60 },
    ],
    controls: [
      { control_id: "AC-2", title: "Account Management", status: "fail", findings: 0, evidencing_checks: ["cis:aws:1.12"], iso_27001_derived: ["A.5.16", "A.5.18"] },
      { control_id: "AC-3", title: "Access Enforcement", status: "fail", findings: 0, evidencing_checks: ["cis:aws:2.1.1"], iso_27001_derived: ["A.5.15"] },
      { control_id: "AC-6", title: "Least Privilege", status: "error", findings: 0, evidencing_checks: ["cis:aws:1.4"], iso_27001_derived: [] },
      { control_id: "IA-5", title: "Authenticator Management", status: "fail", findings: 0, evidencing_checks: ["cis:aws:1.12", "cis:aws:1.4"], iso_27001_derived: ["A.5.17"] },
      { control_id: "SC-7", title: "Boundary Protection", status: "fail", findings: 0, evidencing_checks: ["cis:aws:2.1.1"], iso_27001_derived: ["A.8.20", "A.8.22"] },
      { control_id: "SC-28", title: "Protection of Information at Rest", status: "pass", findings: 0, evidencing_checks: ["cis:aws:2.1.2"], iso_27001_derived: [] },
      { control_id: "SI-10", title: "Information Input Validation", status: "fail", findings: 1, evidencing_checks: ["cwe:CWE-20"], iso_27001_derived: ["A.8.26"] },
    ],
    iso_27001_derived: {
      source: "nist_800_53_to_iso_27001_crosswalk",
      note: "ISO/IEC 27001:2022 Annex A control IDs implicated by the failing NIST controls, derived from NIST's official SP 800-53 Rev 5 -> ISO 27001 crosswalk (identifiers only).",
      controls: ["A.5.15", "A.5.16", "A.5.17", "A.5.18", "A.8.20", "A.8.22", "A.8.26"],
    },
  };
}

function noDataDrill(): NistCatalogDrill {
  const d = scenarioDrill();
  return {
    ...d,
    status: "no_data",
    score: 0,
    summary: { pass: 0, fail: 0, warning: 0, error: 0, evaluated: 0, not_evaluated: 1014, catalog_size: 1014, coverage_pct: 0, score: 0 },
    families: d.families.map((f) => ({ ...f, evaluated: 0, pass: 0, fail: 0, warning: 0, error: 0, not_evaluated: f.total })),
    controls: [],
    iso_27001_derived: { ...d.iso_27001_derived, controls: [] },
  };
}

const getNist = vi.fn();

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return { ...actual, api: { getComplianceNist80053: (...a: unknown[]) => getNist(...a) } };
});

afterEach(() => {
  getNist.mockReset();
});

describe("ComplianceNistCatalog", () => {
  it("renders the exec line with score-over-evaluated, coverage, and honest buckets", async () => {
    getNist.mockResolvedValue(scenarioDrill());
    render(<ComplianceNistCatalog />);

    const panel = await screen.findByTestId("nist-catalog-panel");
    expect(within(panel).getByText("NIST SP 800-53 Rev 5")).toBeInTheDocument();
    // Vendor-asserted must be labeled — never implied "official".
    expect(within(panel).getByText(/vendor-asserted/i)).toBeInTheDocument();
    // Failing estate -> Non-compliant, never a green/100%.
    expect(within(panel).getByText("Non-compliant")).toBeInTheDocument();
    expect(within(panel).queryByText(/100%/)).not.toBeInTheDocument();

    const strip = within(panel).getByTestId("nist-catalog-buckets");
    expect(within(strip).getByText("14.3%")).toBeInTheDocument(); // score over evaluated
    expect(within(strip).getByText("0.69%")).toBeInTheDocument(); // coverage
    // Evaluated / not_evaluated / error explicit.
    expect(within(strip).getByText("7")).toBeInTheDocument();
    expect(within(strip).getByText("1,007")).toBeInTheDocument();
    // score is over EVALUATED only — copy must say so.
    expect(within(panel).getByText(/1 of 7 evaluated controls passing/i)).toBeInTheDocument();
  });

  it("drills to the engineer view: family rollup + evidencing checks + ISO-by-id", async () => {
    getNist.mockResolvedValue(scenarioDrill());
    render(<ComplianceNistCatalog />);
    await screen.findByTestId("nist-catalog-panel");

    // Open the engineer drill.
    fireEvent.click(screen.getByRole("button", { name: /control drill/i }));

    // Family rollup is the scale-aware entry (not a 1014-row tower).
    const families = await screen.findByTestId("nist-catalog-families");
    expect(within(families).getByText("AC")).toBeInTheDocument();
    expect(within(families).getByText("SC")).toBeInTheDocument();

    // Evaluated controls listed with evidencing checks; not_evaluated NOT listed by default.
    const controls = screen.getByTestId("nist-catalog-controls");
    expect(within(controls).getByText("SI-10")).toBeInTheDocument();
    expect(within(controls).getByText(/CWE-20/)).toBeInTheDocument();
    // 7 evaluated rows, never the 1007 not_evaluated remainder.
    expect(within(controls).queryByText("not_evaluated")).not.toBeInTheDocument();

    // ISO attribution is by identifier only, labeled derived-from-crosswalk.
    const iso = screen.getByTestId("nist-catalog-iso");
    expect(within(iso).getByText("A.8.26")).toBeInTheDocument();
    expect(within(iso).getByText(/NIST's official SP 800-53 Rev 5 -> ISO 27001 crosswalk/i)).toBeInTheDocument();
  });

  it("status filter narrows the list without changing headline counts", async () => {
    getNist.mockResolvedValue(scenarioDrill());
    render(<ComplianceNistCatalog />);
    await screen.findByTestId("nist-catalog-panel");
    fireEvent.click(screen.getByRole("button", { name: /control drill/i }));
    await screen.findByTestId("nist-catalog-controls");

    fireEvent.click(screen.getByRole("button", { name: /^Fail$/ }));
    const controls = screen.getByTestId("nist-catalog-controls");
    await waitFor(() => expect(within(controls).queryByText("SC-28")).not.toBeInTheDocument());
    expect(within(controls).getByText("SI-10")).toBeInTheDocument();
    // Headline buckets unchanged (display filter only).
    const strip = screen.getByTestId("nist-catalog-buckets");
    expect(within(strip).getByText("14.3%")).toBeInTheDocument();
    expect(within(strip).getByText("7")).toBeInTheDocument();
  });

  it("shows an honest not-evaluated state with no fabricated compliance", async () => {
    getNist.mockResolvedValue(noDataDrill());
    render(<ComplianceNistCatalog />);
    const panel = await screen.findByTestId("nist-catalog-panel");
    expect(within(panel).getByText("Not evaluated")).toBeInTheDocument();
    expect(within(panel).queryByText("Compliant")).not.toBeInTheDocument();
    expect(within(panel).queryByText(/100%/)).not.toBeInTheDocument();
  });
});
