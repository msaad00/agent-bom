import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { Nist80053CatalogDetail } from "@/components/nist-800-53-catalog-detail";
import type { Nist80053CatalogControl, Nist80053DrillResponse } from "@/lib/api";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    getNist80053Catalog: vi.fn(),
  },
}));

vi.mock("@/lib/api", () => ({
  api: apiMock,
}));

function makeControl(overrides: Partial<Nist80053CatalogControl>): Nist80053CatalogControl {
  return {
    control_id: "AC-2",
    title: "Account Management",
    status: "fail",
    findings: 3,
    evidencing_checks: ["cve-critical-high"],
    iso_27001_derived: ["A.5.16"],
    ...overrides,
  };
}

function makeDrill(overrides: Partial<Nist80053DrillResponse>): Nist80053DrillResponse {
  const controls = overrides.controls ?? [makeControl({})];
  return {
    framework: "nist-800-53",
    framework_key: "nist_800_53_catalog",
    framework_label: "NIST SP 800-53 Rev 5",
    representation: "catalog",
    source: "framework_control_catalog",
    vendor_asserted: true,
    status: "fail",
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
    families: [
      { family: "AC", total: 88, evaluated: 5, pass: 2, fail: 2, warning: 1, error: 0, not_evaluated: 83 },
      { family: "AU", total: 40, evaluated: 3, pass: 1, fail: 2, warning: 0, error: 0, not_evaluated: 37 },
    ],
    controls,
    iso_27001_derived: {
      source: "nist_800_53_to_iso_27001_crosswalk",
      note: "ISO/IEC 27001:2022 Annex A control IDs implicated by the failing NIST controls.",
      controls: ["A.5.16"],
    },
    ...overrides,
  };
}

beforeEach(() => {
  apiMock.getNist80053Catalog.mockReset();
});

afterEach(() => {
  vi.clearAllMocks();
});

describe("Nist80053CatalogDetail", () => {
  it("shows a loading state before the drill resolves", () => {
    apiMock.getNist80053Catalog.mockReturnValue(new Promise(() => {}));
    render(<Nist80053CatalogDetail />);
    expect(screen.getByText(/loading nist sp 800-53/i)).toBeInTheDocument();
  });

  it("renders an error state when the fetch fails", async () => {
    apiMock.getNist80053Catalog.mockRejectedValue(new Error("backend unavailable"));
    render(<Nist80053CatalogDetail />);
    expect(await screen.findByText(/backend unavailable/i)).toBeInTheDocument();
  });

  it("renders the exec buckets, vendor-asserted label, and coverage", async () => {
    apiMock.getNist80053Catalog.mockResolvedValue(makeDrill({}));
    render(<Nist80053CatalogDetail />);

    await screen.findByText("NIST SP 800-53 Rev 5");
    expect(screen.getByText(/vendor-asserted/i)).toBeInTheDocument();

    const strip = screen.getByTestId("nist-800-53-exec-strip");
    expect(within(strip).getByText("Evaluated")).toBeInTheDocument();
    expect(within(strip).getByText("8")).toBeInTheDocument();
    expect(within(strip).getByText("Not evaluated")).toBeInTheDocument();
    expect(within(strip).getByText("1,006")).toBeInTheDocument();
    expect(within(strip).getByText("Error")).toBeInTheDocument();
    expect(within(strip).getByText("Coverage")).toBeInTheDocument();
    expect(within(strip).getByText("0.79%")).toBeInTheDocument();
  });

  it("drills to controls with evidencing checks and ISO-by-id", async () => {
    apiMock.getNist80053Catalog.mockResolvedValue(
      makeDrill({
        controls: [
          makeControl({
            control_id: "AC-2",
            title: "Account Management",
            status: "fail",
            evidencing_checks: ["cve-critical-high"],
            iso_27001_derived: ["A.5.16"],
          }),
        ],
      }),
    );
    render(<Nist80053CatalogDetail />);

    // Family group is discoverable, and expanding it reveals the control row.
    const familyToggle = await screen.findByRole("button", { name: /AC family/i });
    fireEvent.click(familyToggle);

    expect(await screen.findByText("AC-2")).toBeInTheDocument();
    expect(screen.getByText("Account Management")).toBeInTheDocument();
    expect(screen.getByText("cve-critical-high")).toBeInTheDocument();
    expect(screen.getByText("A.5.16")).toBeInTheDocument();
    // ISO titles are never rendered, only the identifier.
    expect(screen.queryByText(/Annex A control text/i)).not.toBeInTheDocument();
  });

  it("filters the control list by status", async () => {
    apiMock.getNist80053Catalog.mockResolvedValue(
      makeDrill({
        controls: [
          makeControl({ control_id: "AC-2", title: "Account Management", status: "fail" }),
          makeControl({ control_id: "AC-3", title: "Access Enforcement", status: "pass", findings: 0 }),
        ],
        families: [
          { family: "AC", total: 88, evaluated: 2, pass: 1, fail: 1, warning: 0, error: 0, not_evaluated: 86 },
        ],
      }),
    );
    render(<Nist80053CatalogDetail />);

    const familyToggle = await screen.findByRole("button", { name: /AC family/i });
    fireEvent.click(familyToggle);
    await screen.findByText("AC-2");
    expect(screen.getByText("AC-3")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Fail" }));
    await waitFor(() => expect(screen.queryByText("AC-3")).not.toBeInTheDocument());
    expect(screen.getByText("AC-2")).toBeInTheDocument();
  });

  it("loads not-evaluated controls only after the explicit toggle", async () => {
    apiMock.getNist80053Catalog.mockResolvedValue(makeDrill({}));
    render(<Nist80053CatalogDetail />);
    await screen.findByText("NIST SP 800-53 Rev 5");

    expect(apiMock.getNist80053Catalog).toHaveBeenCalledWith(
      expect.not.objectContaining({ include_not_evaluated: true }),
    );

    fireEvent.click(screen.getByRole("button", { name: /show not-evaluated/i }));
    await waitFor(() =>
      expect(apiMock.getNist80053Catalog).toHaveBeenCalledWith(
        expect.objectContaining({ include_not_evaluated: true }),
      ),
    );
  });

  it("renders an honest no_data state instead of a fabricated pass", async () => {
    apiMock.getNist80053Catalog.mockResolvedValue(
      makeDrill({
        status: "no_data",
        score: 0,
        summary: {
          pass: 0,
          fail: 0,
          warning: 0,
          error: 0,
          evaluated: 0,
          not_evaluated: 1014,
          catalog_size: 1014,
          coverage_pct: 0,
          score: 0,
        },
        families: [],
        controls: [],
      }),
    );
    render(<Nist80053CatalogDetail />);

    expect(await screen.findByTestId("nist-800-53-status")).toHaveTextContent(/not evaluated/i);
    expect(screen.queryByText(/^Compliant$/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/100%/)).not.toBeInTheDocument();
    expect(screen.getByText(/no nist sp 800-53 controls have been evaluated yet/i)).toBeInTheDocument();
  });
});
