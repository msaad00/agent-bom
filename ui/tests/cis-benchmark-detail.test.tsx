import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { CISBenchmarkDetail } from "@/components/cis-benchmark-detail";
import type { CISBenchmarkCheck } from "@/lib/api";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    listCisBenchmarkChecks: vi.fn(),
  },
}));

vi.mock("@/lib/api", () => ({
  api: apiMock,
}));

function makeCheck(overrides: Partial<CISBenchmarkCheck>): CISBenchmarkCheck {
  return {
    scan_id: "scan-1",
    measured_at: "2026-06-24T00:00:00Z",
    cloud: "aws",
    check_id: "1.1",
    title: "Maintain current contact details",
    status: "fail",
    severity: "medium",
    cis_section: "1 - Identity and Access Management",
    evidence: "Contact info incomplete",
    resource_ids: [],
    remediation: {},
    fix_cli: "",
    fix_console: "",
    effort: "manual",
    priority: 0,
    guardrails: [],
    requires_human_review: false,
    ...overrides,
  };
}

const writeText = vi.fn().mockResolvedValue(undefined);

beforeEach(() => {
  apiMock.listCisBenchmarkChecks.mockReset();
  writeText.mockClear();
  Object.defineProperty(navigator, "clipboard", {
    value: { writeText },
    configurable: true,
  });
});

afterEach(() => {
  vi.clearAllMocks();
});

describe("CISBenchmarkDetail", () => {
  it("shows a loading state before checks resolve", () => {
    apiMock.listCisBenchmarkChecks.mockReturnValue(new Promise(() => {}));
    render(<CISBenchmarkDetail />);
    expect(screen.getByText(/loading cloud cis benchmark checks/i)).toBeInTheDocument();
  });

  it("renders an empty state when no checks exist", async () => {
    apiMock.listCisBenchmarkChecks.mockResolvedValue({ checks: [], count: 0, source: "scan_jobs" });
    render(<CISBenchmarkDetail />);
    expect(await screen.findByText(/no cloud cis benchmark checks yet/i)).toBeInTheDocument();
  });

  it("renders an error state with the fallback copy when the fetch fails opaquely", async () => {
    // An empty-message failure exercises the fallback string in the error UI.
    apiMock.listCisBenchmarkChecks.mockRejectedValue(new Error(""));
    render(<CISBenchmarkDetail />);
    expect(await screen.findByText(/could not load cloud cis benchmark checks/i)).toBeInTheDocument();
  });

  it("surfaces the underlying error message when one is present", async () => {
    apiMock.listCisBenchmarkChecks.mockRejectedValue(new Error("backend unavailable"));
    render(<CISBenchmarkDetail />);
    expect(await screen.findByText(/backend unavailable/i)).toBeInTheDocument();
  });

  it("renders failing checks by default with id, title, and badges", async () => {
    apiMock.listCisBenchmarkChecks.mockResolvedValue({
      checks: [
        makeCheck({ check_id: "1.4", title: "Eliminate root access keys", priority: 1, guardrails: ["identity"] }),
        makeCheck({ check_id: "3.1", title: "Ensure CloudTrail enabled", status: "pass" }),
      ],
      count: 2,
      source: "scan_jobs",
    });
    render(<CISBenchmarkDetail />);

    expect(await screen.findByText("Eliminate root access keys")).toBeInTheDocument();
    expect(screen.getByText("1.4")).toBeInTheDocument();
    // Default status filter is "fail", so the passing check is hidden.
    expect(screen.queryByText("Ensure CloudTrail enabled")).not.toBeInTheDocument();
    expect(screen.getByText(/1 of 2 checks shown/i)).toBeInTheDocument();
  });

  it("copies fix_cli and warns when the check requires human review", async () => {
    apiMock.listCisBenchmarkChecks.mockResolvedValue({
      checks: [
        makeCheck({
          check_id: "1.4",
          title: "Eliminate root access keys",
          fix_cli: "aws iam delete-access-key --user-name root",
          requires_human_review: true,
          remediation: { fix_cli: "aws iam delete-access-key --user-name root", requires_human_review: true },
        }),
      ],
      count: 1,
      source: "scan_jobs",
    });
    render(<CISBenchmarkDetail />);

    await screen.findByText("Eliminate root access keys");
    // Human-review badge is visible on a check that can break production.
    expect(screen.getByTestId("human-review-badge")).toBeInTheDocument();

    const copyButton = screen.getByRole("button", { name: /copy fix command/i });
    fireEvent.click(copyButton);
    await waitFor(() => expect(writeText).toHaveBeenCalledWith("aws iam delete-access-key --user-name root"));
    expect(await screen.findByText(/review carefully before running/i)).toBeInTheDocument();
  });

  it("filters across all fetched checks by guardrail", async () => {
    apiMock.listCisBenchmarkChecks.mockResolvedValue({
      checks: [
        makeCheck({ check_id: "1.4", title: "Root keys", guardrails: ["identity"] }),
        makeCheck({ check_id: "4.1", title: "Logging on", guardrails: ["logging-and-audit"] }),
      ],
      count: 2,
      source: "scan_jobs",
    });
    render(<CISBenchmarkDetail />);

    await screen.findByText("Root keys");
    expect(screen.getByText("Logging on")).toBeInTheDocument();

    // Picking a guardrail narrows to checks carrying it, across every cloud.
    fireEvent.click(screen.getByRole("button", { name: "logging-and-audit" }));
    await waitFor(() => expect(screen.queryByText("Root keys")).not.toBeInTheDocument());
    expect(screen.getByText("Logging on")).toBeInTheDocument();
  });

  it("shows the cloud selector only for clouds present in the data", async () => {
    apiMock.listCisBenchmarkChecks.mockResolvedValue({
      checks: [
        makeCheck({ cloud: "aws", check_id: "1.1", title: "AWS check" }),
        makeCheck({ cloud: "gcp", check_id: "2.1", title: "GCP check" }),
      ],
      count: 2,
      source: "scan_jobs",
    });
    render(<CISBenchmarkDetail />);

    await screen.findByText("AWS check");
    const filters = screen.getByText("Cloud").closest("div") as HTMLElement;
    expect(within(filters).getByRole("button", { name: "AWS" })).toBeInTheDocument();
    expect(within(filters).getByRole("button", { name: "GCP" })).toBeInTheDocument();
    expect(within(filters).queryByRole("button", { name: "Azure" })).not.toBeInTheDocument();
  });
});
