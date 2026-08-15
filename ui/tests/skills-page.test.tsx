import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import type { ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import SkillsPage from "@/app/skills/page";
import type { SkillsScanReport } from "@/lib/api";
import { ApiValidationError } from "@/lib/api-errors";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    getSkillsScan: vi.fn(),
    runSkillsScan: vi.fn(),
  },
}));

vi.mock("next/link", () => ({
  default: ({ href, children }: { href: string; children: ReactNode }) => <a href={href}>{children}</a>,
}));

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return { ...actual, api: apiMock };
});

function report(overrides: Partial<SkillsScanReport> = {}): SkillsScanReport {
  return {
    scan_type: "skills",
    report_type: "skills_scan",
    status: "completed",
    run_id: "run-1",
    created_at: "2026-08-13T00:00:00Z",
    summary: {
      files_scanned: 2,
      bundles: 2,
      packages_found: 0,
      servers_found: 0,
      credential_env_vars: 1,
      findings: 1,
      verified_files: 0,
      suspicious_files: 1,
      malicious_files: 0,
      blocked_files: 0,
      high_risk_files: 0,
      clean_files: 1,
      suspicious_status_files: 1,
      malicious_status_files: 0,
      pending_status_files: 0,
      unavailable_status_files: 0,
    },
    files: [
      {
        path: "skills/risky/SKILL.md",
        status: "suspicious",
        credential_env_vars: ["OPENAI_API_KEY"],
        packages: [],
        servers: [],
        audit: {
          passed: false,
          findings: [
            {
              severity: "high",
              category: "credentials",
              title: "Credential reference",
              detail: "References OPENAI_API_KEY.",
              recommendation: "Use a brokered credential.",
            },
          ],
        },
        trust: {
          verdict: "suspicious",
          content_verdict: "suspicious",
          provenance_verdict: "unverified",
          review_verdict: "review",
          confidence: "medium",
          recommendations: [],
          review_reasons: [],
        },
        provenance: { status: "unsigned", sha256: "abc123", signer: null },
      },
      {
        path: "skills/clean/SKILL.md",
        status: "clean",
        credential_env_vars: [],
        packages: [],
        servers: [],
        audit: { passed: true, findings: [] },
        trust: {
          verdict: "benign",
          content_verdict: "benign",
          provenance_verdict: "verified",
          review_verdict: "clean",
          confidence: "high",
          recommendations: [],
          review_reasons: [],
        },
        provenance: { status: "verified", sha256: "def456", signer: "ci@example.test" },
      },
    ],
    ...overrides,
  };
}

function emptyReport(): SkillsScanReport {
  return {
    scan_type: "skills",
    report_type: "skills_scan",
    status: "no_data",
    run_id: null,
    created_at: null,
    summary: {
      files_scanned: 0,
      bundles: 0,
      packages_found: 0,
      servers_found: 0,
      credential_env_vars: 0,
      findings: 0,
      verified_files: 0,
      suspicious_files: 0,
      malicious_files: 0,
      blocked_files: 0,
      high_risk_files: 0,
      clean_files: 0,
      suspicious_status_files: 0,
      malicious_status_files: 0,
      pending_status_files: 0,
      unavailable_status_files: 0,
    },
    files: [],
  };
}

describe("SkillsPage", () => {
  beforeEach(() => {
    apiMock.getSkillsScan.mockReset();
    apiMock.runSkillsScan.mockReset();
  });

  it("shows a loading state while the latest scan resolves", () => {
    apiMock.getSkillsScan.mockReturnValue(new Promise(() => {}));
    render(<SkillsPage />);
    expect(screen.getByTestId("skills-loading")).toBeInTheDocument();
  });

  it("renders per-file verdict + provenance from the API report", async () => {
    apiMock.getSkillsScan.mockResolvedValue(report());
    render(<SkillsPage />);

    await screen.findByTestId("skills-summary");
    const rows = screen.getAllByTestId("skills-row");
    expect(rows).toHaveLength(2);

    // The suspicious file reads suspicious (never a clean pass) with unsigned provenance.
    const risky = rows[0]!;
    expect(within(risky).getByTestId("skill-status")).toHaveAttribute("data-status", "suspicious");
    expect(within(risky).getByText(/unsigned/i)).toBeInTheDocument();

    // Summary reconciles with the table (one source of truth).
    const summary = screen.getByTestId("skills-summary");
    expect(within(summary).getByText("Files scanned").previousSibling).toHaveTextContent("2");
  });

  it("paginates filtered files instead of rendering the whole result set", async () => {
    const base = report();
    const files = Array.from({ length: 27 }, (_, index) => ({
      ...base.files[0]!,
      path: `skills/team-${index.toString().padStart(2, "0")}/SKILL.md`,
    }));
    apiMock.getSkillsScan.mockResolvedValue(
      report({ files, summary: { ...base.summary, files_scanned: files.length } }),
    );
    render(<SkillsPage />);

    expect(await screen.findAllByTestId("skills-row")).toHaveLength(25);
    expect(screen.getByText(/Page 1 of 2 \(27 files\)/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Next/i }));
    expect(screen.getAllByTestId("skills-row")).toHaveLength(2);
  });

  it("opens a drawer with provenance + findings on row click", async () => {
    apiMock.getSkillsScan.mockResolvedValue(report());
    render(<SkillsPage />);

    const rows = await screen.findAllByTestId("skills-row");
    fireEvent.click(rows[0]!);

    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText("skills/risky/SKILL.md")).toBeInTheDocument();
    expect(within(dialog).getByText("OPENAI_API_KEY")).toBeInTheDocument();
    expect(within(dialog).getByText("Credential reference")).toBeInTheDocument();
    expect(within(dialog).getByText(/abc123/)).toBeInTheDocument();
  });

  it("shows an honest empty state when no scan has been recorded", async () => {
    apiMock.getSkillsScan.mockResolvedValue(emptyReport());
    render(<SkillsPage />);
    expect(await screen.findByTestId("skills-empty")).toBeInTheDocument();
    expect(screen.queryByTestId("skills-summary")).not.toBeInTheDocument();
  });

  it("triggers a scan and renders the returned results", async () => {
    apiMock.getSkillsScan.mockResolvedValue(emptyReport());
    apiMock.runSkillsScan.mockResolvedValue(report());
    render(<SkillsPage />);

    await screen.findByTestId("skills-empty");
    fireEvent.click(screen.getByTestId("skills-scan-button"));

    await waitFor(() => expect(apiMock.runSkillsScan).toHaveBeenCalledTimes(1));
    await screen.findByTestId("skills-summary");
    expect(screen.getAllByTestId("skills-row")).toHaveLength(2);
  });

  it("guides the operator to the CLI when server-side scans are disabled (400)", async () => {
    apiMock.getSkillsScan.mockResolvedValue(emptyReport());
    apiMock.runSkillsScan.mockRejectedValue(
      new ApiValidationError("Invalid scan path", {
        url: "/v1/skills/scan",
        method: "POST",
        status: 400,
        statusText: "Bad Request",
      })
    );
    render(<SkillsPage />);

    await screen.findByTestId("skills-empty");
    fireEvent.click(screen.getByTestId("skills-scan-button"));

    const notice = await screen.findByTestId("skills-scan-disabled");
    expect(notice).toHaveTextContent(/agent-bom skills scan/i);
  });
});
